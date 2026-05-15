package main

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const (
	rtnMagic                byte = 0x52
	rtnVersion              byte = 0x01
	rtnHeaderSize                = 12
	rtnMaxPayload                = 1 << 20
	rtnPingInterval              = 10 * time.Second
	rtnHandshakeTO               = 15 * time.Second
	rtnPriorityQueue             = 4096
	rtnBulkQueue                 = 4096
	rtnFragmentSize              = 32 << 10
	rtnMaxFragmentedPayload      = 8 << 20
	rtnWriteTimeout              = 2 * time.Minute
	rtnControlEnqueueTO          = 5 * time.Second
	rtnBulkEnqueueTO             = 10 * time.Second
)

const (
	rtnKindHello      byte = 0x01
	rtnKindWelcome    byte = 0x02
	rtnKindAuth       byte = 0x03
	rtnKindAuthOK     byte = 0x04
	rtnKindEnvelope   byte = 0x10
	rtnKindClose      byte = 0x11
	rtnKindPing       byte = 0x20
	rtnKindPong       byte = 0x21
	rtnKindLaneAttach byte = 0x30
	rtnKindLaneOK     byte = 0x31
)

const (
	rtnFlagEncrypted byte = 1 << 0
	rtnFlagPriority  byte = 1 << 1
	rtnFlagEnd       byte = 1 << 2
)

type rtnHeader struct {
	Kind   byte
	Flags  byte
	Stream uint32
	Length uint32
}

func rtnEncodeHeader(h rtnHeader) [rtnHeaderSize]byte {
	var b [rtnHeaderSize]byte
	b[0] = rtnMagic
	b[1] = h.Kind
	b[2] = h.Flags
	b[3] = rtnVersion
	binary.BigEndian.PutUint32(b[4:8], h.Stream)
	binary.BigEndian.PutUint32(b[8:12], h.Length)
	return b
}

func rtnDecodeHeader(b []byte) (rtnHeader, error) {
	if len(b) < rtnHeaderSize {
		return rtnHeader{}, errors.New("rtn: short header")
	}
	if b[0] != rtnMagic {
		return rtnHeader{}, fmt.Errorf("rtn: bad magic 0x%02x", b[0])
	}
	return rtnHeader{
		Kind:   b[1],
		Flags:  b[2],
		Stream: binary.BigEndian.Uint32(b[4:8]),
		Length: binary.BigEndian.Uint32(b[8:12]),
	}, nil
}

type rtnCrypter interface {
	Encrypt(plain []byte) ([]byte, error)
	Decrypt(cipher []byte) ([]byte, error)
}

type rtnFrameOut struct {
	header  rtnHeader
	payload []byte
}

type rtnLink struct {
	conn       net.Conn
	writeMu    sync.Mutex
	priorityQ  chan rtnFrameOut
	bulkQ      chan rtnFrameOut
	done       chan struct{}
	closeOnce  sync.Once
	started    uint32
	nextStream uint32
	fragments  map[uint32][]byte
	onWriteErr func(error)
}

func newRtnLink(conn net.Conn) *rtnLink {
	return &rtnLink{
		conn:      conn,
		priorityQ: make(chan rtnFrameOut, rtnPriorityQueue),
		bulkQ:     make(chan rtnFrameOut, rtnBulkQueue),
		done:      make(chan struct{}),
		fragments: make(map[uint32][]byte),
	}
}

func (l *rtnLink) startWriter(onWriteErr func(error)) {
	if !atomic.CompareAndSwapUint32(&l.started, 0, 1) {
		return
	}
	l.onWriteErr = onWriteErr
	go l.writerLoop()
}

func (l *rtnLink) close() error {
	l.closeOnce.Do(func() {
		close(l.done)
		_ = l.conn.Close()
	})
	return nil
}

func (l *rtnLink) writeFrame(h rtnHeader, payload []byte) error {
	h.Length = uint32(len(payload))
	if h.Length > rtnMaxPayload {
		return fmt.Errorf("rtn: payload too large %d", h.Length)
	}
	if atomic.LoadUint32(&l.started) == 0 {
		return l.writeFrameSync(h, payload)
	}
	if l.shouldFragment(h, payload) {
		return l.writeFragmentedFrame(h, payload)
	}
	select {
	case <-l.done:
		return errors.New("rtn: link closed")
	default:
	}
	f := rtnFrameOut{header: h, payload: payload}
	q := l.bulkQ
	if h.Kind != rtnKindEnvelope || h.Flags&rtnFlagPriority != 0 {
		q = l.priorityQ
		timer := time.NewTimer(rtnControlEnqueueTO)
		defer timer.Stop()
		select {
		case q <- f:
			return nil
		case <-l.done:
			return errors.New("rtn: link closed")
		case <-timer.C:
			return errors.New("rtn: priority queue full")
		}
	}
	select {
	case q <- f:
		return nil
	case <-l.done:
		return errors.New("rtn: link closed")
	default:
		return errors.New("rtn: bulk queue full")
	}
}

func (l *rtnLink) shouldFragment(h rtnHeader, payload []byte) bool {
	return h.Kind == rtnKindEnvelope && h.Flags&rtnFlagPriority == 0 && len(payload) > rtnFragmentSize
}

func (l *rtnLink) writeFragmentedFrame(h rtnHeader, payload []byte) error {
	stream := atomic.AddUint32(&l.nextStream, 1)
	if stream == 0 {
		stream = atomic.AddUint32(&l.nextStream, 1)
	}
	for off := 0; off < len(payload); off += rtnFragmentSize {
		end := off + rtnFragmentSize
		if end > len(payload) {
			end = len(payload)
		}
		fh := h
		fh.Stream = stream
		if end == len(payload) {
			fh.Flags |= rtnFlagEnd
		} else {
			fh.Flags &^= rtnFlagEnd
		}
		if err := l.enqueueBulkFrame(rtnFrameOut{header: fh, payload: payload[off:end]}); err != nil {
			l.close()
			return err
		}
	}
	return nil
}

func (l *rtnLink) enqueueBulkFrame(f rtnFrameOut) error {
	timer := time.NewTimer(rtnBulkEnqueueTO)
	defer timer.Stop()
	select {
	case l.bulkQ <- f:
		return nil
	case <-l.done:
		return errors.New("rtn: link closed")
	case <-timer.C:
		return errors.New("rtn: bulk queue full")
	}
}

func (l *rtnLink) assembleEnvelope(h rtnHeader, payload []byte) ([]byte, bool, error) {
	if h.Stream == 0 {
		return payload, true, nil
	}
	buf := l.fragments[h.Stream]
	if len(buf)+len(payload) > rtnMaxFragmentedPayload {
		delete(l.fragments, h.Stream)
		return nil, false, fmt.Errorf("rtn: fragmented payload too large stream=%d", h.Stream)
	}
	buf = append(buf, payload...)
	if h.Flags&rtnFlagEnd == 0 {
		l.fragments[h.Stream] = buf
		return nil, false, nil
	}
	delete(l.fragments, h.Stream)
	return buf, true, nil
}

func (l *rtnLink) writerLoop() {
	for {
		select {
		case f := <-l.priorityQ:
			if err := l.writeFrameSync(f.header, f.payload); err != nil {
				l.failWriter(err)
				return
			}
			continue
		default:
		}
		select {
		case f := <-l.priorityQ:
			if err := l.writeFrameSync(f.header, f.payload); err != nil {
				l.failWriter(err)
				return
			}
		case f := <-l.bulkQ:
			if err := l.writeFrameSync(f.header, f.payload); err != nil {
				l.failWriter(err)
				return
			}
		case <-l.done:
			return
		}
	}
}

func (l *rtnLink) failWriter(err error) {
	l.close()
	if l.onWriteErr != nil {
		l.onWriteErr(err)
	}
}

func (l *rtnLink) writeFrameSync(h rtnHeader, payload []byte) error {
	h.Length = uint32(len(payload))
	if h.Length > rtnMaxPayload {
		return fmt.Errorf("rtn: payload too large %d", h.Length)
	}
	hdr := rtnEncodeHeader(h)
	l.writeMu.Lock()
	defer l.writeMu.Unlock()
	l.conn.SetWriteDeadline(time.Now().Add(rtnWriteTimeout))
	defer l.conn.SetWriteDeadline(time.Time{})
	if _, err := l.conn.Write(hdr[:]); err != nil {
		return err
	}
	if h.Length > 0 {
		if _, err := l.conn.Write(payload); err != nil {
			return err
		}
	}
	return nil
}

func rtnReadFrame(r io.Reader) (rtnHeader, []byte, error) {
	hbuf := make([]byte, rtnHeaderSize)
	if _, err := io.ReadFull(r, hbuf); err != nil {
		return rtnHeader{}, nil, err
	}
	h, err := rtnDecodeHeader(hbuf)
	if err != nil {
		return rtnHeader{}, nil, err
	}
	if h.Length > rtnMaxPayload {
		return rtnHeader{}, nil, fmt.Errorf("rtn: oversized frame %d", h.Length)
	}
	if h.Length == 0 {
		return h, nil, nil
	}
	payload := make([]byte, h.Length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return rtnHeader{}, nil, err
	}
	return h, payload, nil
}

type RtnSession struct {
	primary    *rtnLink
	lanes      []*rtnLink
	lanesMu    sync.RWMutex
	closeOnce  sync.Once
	closed     chan struct{}
	sessionID  []byte
	crypter    rtnCrypter
	peer       string
	onEnvelope func(envelope []byte)
	onClose    func()
	nextLaneIx uint32
}

func (s *RtnSession) SessionID() []byte { return s.sessionID }
func (s *RtnSession) Peer() string      { return s.peer }
func (s *RtnSession) Closed() <-chan struct{} {
	return s.closed
}

func (s *RtnSession) SendPriority(plaintext []byte) error {
	cipher, err := s.crypter.Encrypt(plaintext)
	if err != nil {
		return err
	}
	return s.SendPriorityRaw(cipher)
}

func (s *RtnSession) SendBulk(plaintext []byte) error {
	cipher, err := s.crypter.Encrypt(plaintext)
	if err != nil {
		return err
	}
	return s.SendBulkRaw(cipher)
}

func (s *RtnSession) SendPriorityRaw(cipher []byte) error {
	h := rtnHeader{Kind: rtnKindEnvelope, Flags: rtnFlagEncrypted | rtnFlagPriority}
	return s.primary.writeFrame(h, cipher)
}

func (s *RtnSession) SendBulkRaw(cipher []byte) error {
	return s.sendBulkOnLane(cipher, s.pickLane())
}

func (s *RtnSession) SendBulkStickyRaw(cipher []byte, stickyKey string) error {
	return s.sendBulkOnLane(cipher, s.stickyLane(stickyKey))
}

func (s *RtnSession) sendBulkOnLane(cipher []byte, link *rtnLink) error {
	h := rtnHeader{Kind: rtnKindEnvelope, Flags: rtnFlagEncrypted}
	if err := link.writeFrame(h, cipher); err != nil {
		if link == s.primary {
			s.Close()
		} else {
			s.dropLane(link)
		}
		return err
	}
	return nil
}

func (s *RtnSession) pickLane() *rtnLink {
	s.lanesMu.RLock()
	lanes := append([]*rtnLink(nil), s.lanes...)
	s.lanesMu.RUnlock()
	if len(lanes) == 0 {
		return s.primary
	}
	idx := atomic.AddUint32(&s.nextLaneIx, 1)
	return lanes[int(idx)%len(lanes)]
}

func (s *RtnSession) stickyLane(stickyKey string) *rtnLink {
	s.lanesMu.RLock()
	lanes := append([]*rtnLink(nil), s.lanes...)
	s.lanesMu.RUnlock()
	if len(lanes) == 0 {
		return s.primary
	}
	h := rtnHashKey(stickyKey)
	return lanes[int(h%uint32(len(lanes)))]
}

func rtnHashKey(s string) uint32 {
	h := uint32(2166136261)
	for i := 0; i < len(s); i++ {
		h ^= uint32(s[i])
		h *= 16777619
	}
	return h
}

func (s *RtnSession) attachLane(link *rtnLink) {
	s.lanesMu.Lock()
	s.lanes = append(s.lanes, link)
	s.lanesMu.Unlock()
}

func (s *RtnSession) dropLane(dead *rtnLink) {
	_ = dead.close()
	s.lanesMu.Lock()
	kept := s.lanes[:0]
	for _, l := range s.lanes {
		if l != dead {
			kept = append(kept, l)
		}
	}
	s.lanes = kept
	s.lanesMu.Unlock()
}

func (s *RtnSession) Close() {
	s.closeOnce.Do(func() {
		close(s.closed)
		_ = s.primary.close()
		s.lanesMu.Lock()
		for _, l := range s.lanes {
			_ = l.close()
		}
		s.lanes = nil
		s.lanesMu.Unlock()
		if s.onClose != nil {
			s.onClose()
		}
	})
}

func (s *RtnSession) serveLink(link *rtnLink) {
	for {
		h, payload, err := rtnReadFrame(link.conn)
		if err != nil {
			if link == s.primary {
				s.Close()
			} else {
				s.dropLane(link)
			}
			return
		}
		switch h.Kind {
		case rtnKindPing:
			_ = link.writeFrame(rtnHeader{Kind: rtnKindPong}, nil)
		case rtnKindPong:
		case rtnKindClose:
			if link == s.primary {
				s.Close()
			} else {
				s.dropLane(link)
			}
			return
		case rtnKindEnvelope:
			if h.Flags&rtnFlagEncrypted == 0 {
				continue
			}
			envelope, complete, err := link.assembleEnvelope(h, payload)
			if err != nil {
				if link == s.primary {
					s.Close()
				} else {
					s.dropLane(link)
				}
				return
			}
			if !complete {
				continue
			}
			plain, err := s.crypter.Decrypt(envelope)
			if err != nil {
				continue
			}
			if s.onEnvelope != nil {
				s.onEnvelope(plain)
			}
		}
	}
}

func (s *RtnSession) keepalive() {
	t := time.NewTicker(rtnPingInterval)
	defer t.Stop()
	for {
		select {
		case <-s.closed:
			return
		case <-t.C:
			if err := s.primary.writeFrame(rtnHeader{Kind: rtnKindPing}, nil); err != nil {
				s.Close()
				return
			}
		}
	}
}

type RtnListener struct {
	ln       net.Listener
	crypter  rtnCrypter
	pending  sync.Map
	onAccept func(*RtnSession)
}

func RtnListen(addr string, crypter rtnCrypter, onAccept func(*RtnSession)) (*RtnListener, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	l := &RtnListener{ln: ln, crypter: crypter, onAccept: onAccept}
	go l.acceptLoop()
	return l, nil
}

func (l *RtnListener) Addr() net.Addr { return l.ln.Addr() }
func (l *RtnListener) Close() error   { return l.ln.Close() }

func (l *RtnListener) acceptLoop() {
	for {
		conn, err := l.ln.Accept()
		if err != nil {
			return
		}
		go l.handle(conn)
	}
}

func (l *RtnListener) handle(conn net.Conn) {
	if tc, ok := conn.(*net.TCPConn); ok {
		tc.SetKeepAlive(true)
		tc.SetKeepAlivePeriod(15 * time.Second)
		tc.SetNoDelay(true)
		_ = tc.SetReadBuffer(4 << 20)
		_ = tc.SetWriteBuffer(4 << 20)
	}

	conn.SetReadDeadline(time.Now().Add(rtnHandshakeTO))
	hbuf := make([]byte, rtnHeaderSize)
	if _, err := io.ReadFull(conn, hbuf); err != nil {
		_ = conn.Close()
		return
	}
	h, err := rtnDecodeHeader(hbuf)
	if err != nil || h.Length > rtnMaxPayload {
		_ = conn.Close()
		return
	}
	payload := make([]byte, h.Length)
	if h.Length > 0 {
		if _, err := io.ReadFull(conn, payload); err != nil {
			_ = conn.Close()
			return
		}
	}
	conn.SetReadDeadline(time.Time{})

	if h.Kind == rtnKindLaneAttach {
		l.handleLaneAttach(conn, h, payload)
		return
	}
	if h.Kind != rtnKindHello || h.Flags&rtnFlagEncrypted == 0 {
		_ = conn.Close()
		return
	}
	l.handleHello(conn, payload)
}

func (l *RtnListener) handleHello(conn net.Conn, helloCipher []byte) {
	plainHello, err := l.crypter.Decrypt(helloCipher)
	if err != nil || len(plainHello) < 16 {
		_ = conn.Close()
		return
	}
	clientNonce := plainHello[:16]
	serverNonce, err := rtnRandomBytes(16)
	if err != nil {
		_ = conn.Close()
		return
	}
	sessionID, err := rtnRandomBytes(16)
	if err != nil {
		_ = conn.Close()
		return
	}
	welcome := make([]byte, 0, 48)
	welcome = append(welcome, clientNonce...)
	welcome = append(welcome, serverNonce...)
	welcome = append(welcome, sessionID...)
	welcomeCipher, err := l.crypter.Encrypt(welcome)
	if err != nil {
		_ = conn.Close()
		return
	}
	primary := newRtnLink(conn)
	if err := primary.writeFrame(rtnHeader{Kind: rtnKindWelcome, Flags: rtnFlagEncrypted}, welcomeCipher); err != nil {
		_ = conn.Close()
		return
	}

	conn.SetReadDeadline(time.Now().Add(rtnHandshakeTO))
	authH, authPayload, err := rtnReadFrame(conn)
	conn.SetReadDeadline(time.Time{})
	if err != nil || authH.Kind != rtnKindAuth || authH.Flags&rtnFlagEncrypted == 0 {
		_ = conn.Close()
		return
	}
	plainAuth, err := l.crypter.Decrypt(authPayload)
	if err != nil || !rtnBytesEqual(plainAuth, serverNonce) {
		_ = conn.Close()
		return
	}
	authOKCipher, err := l.crypter.Encrypt(sessionID)
	if err != nil {
		_ = conn.Close()
		return
	}
	if err := primary.writeFrame(rtnHeader{Kind: rtnKindAuthOK, Flags: rtnFlagEncrypted}, authOKCipher); err != nil {
		_ = conn.Close()
		return
	}

	peer, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
	sess := &RtnSession{
		primary:   primary,
		closed:    make(chan struct{}),
		sessionID: sessionID,
		crypter:   l.crypter,
		peer:      peer,
	}
	primary.startWriter(func(error) { sess.Close() })
	l.pending.Store(string(sessionID), sess)
	go func() {
		<-sess.closed
		l.pending.Delete(string(sessionID))
	}()

	if l.onAccept != nil {
		l.onAccept(sess)
	}
	go sess.keepalive()
	sess.serveLink(primary)
}

func (l *RtnListener) handleLaneAttach(conn net.Conn, h rtnHeader, payload []byte) {
	if h.Flags&rtnFlagEncrypted == 0 {
		_ = conn.Close()
		return
	}
	plainSID, err := l.crypter.Decrypt(payload)
	if err != nil {
		_ = conn.Close()
		return
	}
	v, ok := l.pending.Load(string(plainSID))
	if !ok {
		_ = conn.Close()
		return
	}
	sess := v.(*RtnSession)
	link := newRtnLink(conn)
	if err := link.writeFrame(rtnHeader{Kind: rtnKindLaneOK}, nil); err != nil {
		_ = conn.Close()
		return
	}
	link.startWriter(func(error) { sess.dropLane(link) })
	sess.attachLane(link)
	sess.serveLink(link)
}

func rtnBytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func rtnRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return nil, err
	}
	return b, nil
}
