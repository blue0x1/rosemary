package main

import (
	"context"
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

type RtnClient struct {
	primary    *rtnLink
	lanes      []*rtnLink
	lanesMu    sync.RWMutex
	closeOnce  sync.Once
	closed     chan struct{}
	sessionID  []byte
	serverAddr string
	crypter    rtnCrypter
	onEnvelope func([]byte)
	onEnvMu    sync.Mutex
	pending    [][]byte
	laneTarget int
	nextLaneIx uint32
}

func (c *RtnClient) SessionID() []byte       { return c.sessionID }
func (c *RtnClient) Closed() <-chan struct{} { return c.closed }
func (c *RtnClient) SetOnEnvelope(fn func([]byte)) {
	c.onEnvMu.Lock()
	c.onEnvelope = fn
	buf := c.pending
	c.pending = nil
	c.onEnvMu.Unlock()
	for _, b := range buf {
		fn(b)
	}
}

func (c *RtnClient) deliverEnvelope(b []byte) {
	c.onEnvMu.Lock()
	fn := c.onEnvelope
	if fn == nil {
		c.pending = append(c.pending, b)
		c.onEnvMu.Unlock()
		return
	}
	c.onEnvMu.Unlock()
	fn(b)
}
func (c *RtnClient) LaneCount() int {
	c.lanesMu.RLock()
	defer c.lanesMu.RUnlock()
	return len(c.lanes)
}

func (c *RtnClient) SendPriority(plain []byte) error {
	cipher, err := c.crypter.Encrypt(plain)
	if err != nil {
		return err
	}
	return c.SendPriorityRaw(cipher)
}

func (c *RtnClient) SendBulk(plain []byte) error {
	cipher, err := c.crypter.Encrypt(plain)
	if err != nil {
		return err
	}
	return c.SendBulkRaw(cipher)
}

func (c *RtnClient) SendPriorityRaw(cipher []byte) error {
	h := rtnHeader{Kind: rtnKindEnvelope, Flags: rtnFlagEncrypted | rtnFlagPriority}
	return c.primary.writeFrame(h, cipher)
}

func (c *RtnClient) SendBulkRaw(cipher []byte) error {
	c.lanesMu.RLock()
	lanes := append([]*rtnLink(nil), c.lanes...)
	c.lanesMu.RUnlock()
	if len(lanes) == 0 {
		h := rtnHeader{Kind: rtnKindEnvelope, Flags: rtnFlagEncrypted}
		return c.primary.writeFrame(h, cipher)
	}
	idx := atomic.AddUint32(&c.nextLaneIx, 1)
	return c.sendBulkOnLane(cipher, lanes[int(idx)%len(lanes)])
}

func (c *RtnClient) SendBulkStickyRaw(cipher []byte, stickyKey string) error {
	c.lanesMu.RLock()
	lanes := append([]*rtnLink(nil), c.lanes...)
	c.lanesMu.RUnlock()
	if len(lanes) == 0 {
		h := rtnHeader{Kind: rtnKindEnvelope, Flags: rtnFlagEncrypted}
		return c.primary.writeFrame(h, cipher)
	}
	h := rtnHashKey(stickyKey)
	return c.sendBulkOnLane(cipher, lanes[int(h%uint32(len(lanes)))])
}

func (c *RtnClient) sendBulkOnLane(cipher []byte, link *rtnLink) error {
	h := rtnHeader{Kind: rtnKindEnvelope, Flags: rtnFlagEncrypted}
	if err := link.writeFrame(h, cipher); err != nil {
		if link == c.primary {
			c.Close()
		} else {
			c.dropLane(link)
		}
		return err
	}
	return nil
}

func rtnHashKey(s string) uint32 {
	h := uint32(2166136261)
	for i := 0; i < len(s); i++ {
		h ^= uint32(s[i])
		h *= 16777619
	}
	return h
}

func (c *RtnClient) Close() {
	c.closeOnce.Do(func() {
		close(c.closed)
		_ = c.primary.close()
		c.lanesMu.Lock()
		for _, l := range c.lanes {
			_ = l.close()
		}
		c.lanes = nil
		c.lanesMu.Unlock()
	})
}

func (c *RtnClient) dropLane(dead *rtnLink) {
	_ = dead.close()
	c.lanesMu.Lock()
	kept := c.lanes[:0]
	for _, l := range c.lanes {
		if l != dead {
			kept = append(kept, l)
		}
	}
	c.lanes = kept
	c.lanesMu.Unlock()
}

func (c *RtnClient) serveLink(link *rtnLink) {
	for {
		h, payload, err := rtnReadFrame(link.conn)
		if err != nil {
			if link == c.primary {
				c.Close()
			} else {
				c.dropLane(link)
			}
			return
		}
		switch h.Kind {
		case rtnKindPing:
			_ = link.writeFrame(rtnHeader{Kind: rtnKindPong}, nil)
		case rtnKindPong:
		case rtnKindClose:
			if link == c.primary {
				c.Close()
			} else {
				c.dropLane(link)
			}
			return
		case rtnKindEnvelope:
			if h.Flags&rtnFlagEncrypted == 0 {
				continue
			}
			envelope, complete, err := link.assembleEnvelope(h, payload)
			if err != nil {
				if link == c.primary {
					c.Close()
				} else {
					c.dropLane(link)
				}
				return
			}
			if !complete {
				continue
			}
			c.deliverEnvelope(envelope)
		}
	}
}

func (c *RtnClient) keepalive() {
	t := time.NewTicker(rtnPingInterval)
	defer t.Stop()
	for {
		select {
		case <-c.closed:
			return
		case <-t.C:
			if err := c.primary.writeFrame(rtnHeader{Kind: rtnKindPing}, nil); err != nil {
				c.Close()
				return
			}
		}
	}
}

func RtnDial(ctx context.Context, serverAddr string, crypter rtnCrypter, lanes int) (*RtnClient, error) {
	d := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 15 * time.Second}
	tcpConn, err := d.DialContext(ctx, "tcp", serverAddr)
	if err != nil {
		return nil, err
	}
	if tc, ok := tcpConn.(*net.TCPConn); ok {
		tc.SetNoDelay(true)
		_ = tc.SetReadBuffer(4 << 20)
		_ = tc.SetWriteBuffer(4 << 20)
	}
	primary := newRtnLink(tcpConn)

	clientNonce, err := rtnRandomBytes(16)
	if err != nil {
		_ = tcpConn.Close()
		return nil, err
	}
	helloCipher, err := crypter.Encrypt(clientNonce)
	if err != nil {
		_ = tcpConn.Close()
		return nil, err
	}
	if err := primary.writeFrame(rtnHeader{Kind: rtnKindHello, Flags: rtnFlagEncrypted}, helloCipher); err != nil {
		_ = tcpConn.Close()
		return nil, err
	}

	tcpConn.SetReadDeadline(time.Now().Add(rtnHandshakeTO))
	wh, wpayload, err := rtnReadFrame(tcpConn)
	if err != nil {
		_ = tcpConn.Close()
		return nil, fmt.Errorf("welcome read: %w", err)
	}
	if wh.Kind != rtnKindWelcome || wh.Flags&rtnFlagEncrypted == 0 {
		_ = tcpConn.Close()
		return nil, fmt.Errorf("expected welcome, got 0x%02x", wh.Kind)
	}
	welcomePlain, err := crypter.Decrypt(wpayload)
	if err != nil {
		_ = tcpConn.Close()
		return nil, fmt.Errorf("welcome decrypt: %w", err)
	}
	if len(welcomePlain) < 48 || !rtnBytesEqual(welcomePlain[:16], clientNonce) {
		_ = tcpConn.Close()
		return nil, errors.New("welcome nonce mismatch")
	}
	serverNonce := welcomePlain[16:32]
	sessionID := welcomePlain[32:48]

	authCipher, err := crypter.Encrypt(serverNonce)
	if err != nil {
		_ = tcpConn.Close()
		return nil, err
	}
	if err := primary.writeFrame(rtnHeader{Kind: rtnKindAuth, Flags: rtnFlagEncrypted}, authCipher); err != nil {
		_ = tcpConn.Close()
		return nil, err
	}
	okH, okPayload, err := rtnReadFrame(tcpConn)
	tcpConn.SetReadDeadline(time.Time{})
	if err != nil || okH.Kind != rtnKindAuthOK || okH.Flags&rtnFlagEncrypted == 0 {
		_ = tcpConn.Close()
		return nil, fmt.Errorf("auth_ok failed")
	}
	okPlain, err := crypter.Decrypt(okPayload)
	if err != nil || !rtnBytesEqual(okPlain, sessionID) {
		_ = tcpConn.Close()
		return nil, errors.New("auth_ok mismatch")
	}

	c := &RtnClient{
		primary:    primary,
		closed:     make(chan struct{}),
		sessionID:  sessionID,
		serverAddr: serverAddr,
		crypter:    crypter,
		laneTarget: lanes,
	}
	primary.startWriter(func(error) { c.Close() })
	go c.serveLink(primary)
	go c.keepalive()
	if lanes > 0 {
		go c.maintainLanes(ctx)
	}
	return c, nil
}

func (c *RtnClient) maintainLanes(ctx context.Context) {
	backoff := time.Second
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		for c.LaneCount() < c.laneTarget {
			select {
			case <-ctx.Done():
				return
			case <-c.closed:
				return
			default:
			}
			if err := c.openLane(ctx); err != nil {
				select {
				case <-time.After(backoff):
				case <-ctx.Done():
					return
				case <-c.closed:
					return
				}
				if backoff < 30*time.Second {
					backoff *= 2
				}
				continue
			}
			backoff = time.Second
		}
		select {
		case <-ticker.C:
		case <-ctx.Done():
			return
		case <-c.closed:
			return
		}
	}
}

func (c *RtnClient) openLane(ctx context.Context) error {
	d := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 15 * time.Second}
	tcpConn, err := d.DialContext(ctx, "tcp", c.serverAddr)
	if err != nil {
		return err
	}
	if tc, ok := tcpConn.(*net.TCPConn); ok {
		tc.SetNoDelay(true)
		_ = tc.SetReadBuffer(4 << 20)
		_ = tc.SetWriteBuffer(4 << 20)
	}
	link := newRtnLink(tcpConn)
	attachCipher, err := c.crypter.Encrypt(c.sessionID)
	if err != nil {
		_ = tcpConn.Close()
		return err
	}
	if err := link.writeFrame(rtnHeader{Kind: rtnKindLaneAttach, Flags: rtnFlagEncrypted}, attachCipher); err != nil {
		_ = tcpConn.Close()
		return err
	}
	tcpConn.SetReadDeadline(time.Now().Add(rtnHandshakeTO))
	okH, _, err := rtnReadFrame(tcpConn)
	tcpConn.SetReadDeadline(time.Time{})
	if err != nil || okH.Kind != rtnKindLaneOK {
		_ = tcpConn.Close()
		return fmt.Errorf("lane_ok failed")
	}
	link.startWriter(func(error) { c.dropLane(link) })
	c.lanesMu.Lock()
	c.lanes = append(c.lanes, link)
	c.lanesMu.Unlock()
	go c.serveLink(link)
	return nil
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
