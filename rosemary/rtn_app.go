package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"sync"
	"time"

	quic "github.com/quic-go/quic-go"
)

var rtnConnIDNeedle = []byte(`"conn_id":"`)

const (
	quicALPN        = "rosemary-quic/1"
	quicAuthLabel   = "rosemary-quic-auth-v1"
	quicCertLabel   = "rosemary-quic-cert-v1"
	quicMaxEnvelope = 8 << 20
)

func rtnConnIDFromPayload(payload []byte) string {
	i := bytes.Index(payload, rtnConnIDNeedle)
	if i < 0 {
		return ""
	}
	start := i + len(rtnConnIDNeedle)
	end := bytes.IndexByte(payload[start:], '"')
	if end < 0 {
		return ""
	}
	return string(payload[start : start+end])
}

type rtnAppCrypter struct{}

func (rtnAppCrypter) Encrypt(p []byte) ([]byte, error) { return encrypt(p, getEncryptionKey()) }
func (rtnAppCrypter) Decrypt(c []byte) ([]byte, error) { return decrypt(c, getEncryptionKey()) }

type rtnSink struct {
	session   *RtnSession
	qsession  *quicAgentSession
	connID    string
	controlMu sync.Mutex
}

func (s *rtnSink) write(encrypted []byte) error {
	if s.qsession != nil {
		return s.qsession.writeControl(encrypted)
	}
	return s.session.SendPriorityRaw(encrypted)
}

func (s *rtnSink) writeMessage(msg Message, encrypted []byte) error {
	if s.qsession != nil {
		return s.qsession.writeMessage(msg, encrypted)
	}
	bulk := msg.Type == "data" || msg.Type == "udp_data" || msg.Type == "agent_fwd_data"
	if bulk {
		if connID := rtnConnIDFromPayload(msg.Payload); connID != "" {
			return s.session.SendBulkStickyRaw(encrypted, connID)
		}
		return s.session.SendBulkRaw(encrypted)
	}
	return s.session.SendPriorityRaw(encrypted)
}

func (s *rtnSink) close() error {
	if s.qsession != nil {
		return s.qsession.close()
	}
	s.session.Close()
	return nil
}

func startRtnListener(port int) {
	ln, err := quic.ListenAddr(fmt.Sprintf(":%d", port), quicTLSConfig(), quicConfig())
	if err != nil {
		log.Printf("quic listener failed on port %d: %v", port, err)
		return
	}
	log.Printf("Agent QUIC endpoint: :%d/udp", port)
	go func() {
		for {
			conn, err := ln.Accept(context.Background())
			if err != nil {
				return
			}
			go onQuicSessionAccept(conn)
		}
	}()
}

type quicAgentSession struct {
	conn      *quic.Conn
	control   *quic.Stream
	controlMu sync.Mutex
	streams   map[string]*quicDataStream
	streamsMu sync.Mutex
	closeOnce sync.Once
	onClose   func()
}

func onQuicSessionAccept(conn *quic.Conn) {
	st, err := conn.AcceptStream(context.Background())
	if err != nil {
		_ = conn.CloseWithError(1, "no control stream")
		return
	}
	token, err := readQuicFrame(st)
	if err != nil || !hmac.Equal(token, quicAuthToken()) {
		_ = conn.CloseWithError(1, "auth failed")
		return
	}
	peer, _, _ := netSplitHostPort(conn.RemoteAddr().String())
	if !canAcceptAgentConnection(peer) {
		log.Printf("Reject quic agent from %s (rate limit or max agents)", peer)
		_ = conn.CloseWithError(1, "rejected")
		return
	}

	connLock.Lock()
	directConnectedAgentID := fmt.Sprintf("conn-%d", nextAgentID)
	nextAgentID++
	qs := &quicAgentSession{conn: conn, control: st, streams: make(map[string]*quicDataStream)}
	sink := &rtnSink{qsession: qs, connID: directConnectedAgentID}
	rtnSinks[directConnectedAgentID] = sink
	connLock.Unlock()

	deliver := func(plain []byte) {
		var msg Message
		if err := json.Unmarshal(plain, &msg); err != nil {
			return
		}
		actualSourceAgentID := sink.connID
		if msg.OriginalAgentID != "" {
			actualSourceAgentID = msg.OriginalAgentID
		}
		if msg.TargetAgentID != "" && msg.TargetAgentID != "server" && msg.TargetAgentID != actualSourceAgentID {
			relayConnMsg(msg, actualSourceAgentID)
			return
		}
		dispatchConnMsg(msg, actualSourceAgentID, peer, &sink.connID)
	}

	qs.onClose = func() {
		releaseAgentConnection(peer)
		cleanupAgentConn(sink.connID)
	}
	go qs.readStream(st, true, deliver)
	go qs.acceptStreams(deliver)
	go func() {
		<-conn.Context().Done()
		qs.close()
	}()
}

func (s *quicAgentSession) writeControl(payload []byte) error {
	plain, err := decrypt(payload, getEncryptionKey())
	if err != nil {
		return err
	}
	return writeQuicFrame(s.control, &s.controlMu, plain)
}

func (s *quicAgentSession) writeMessage(msg Message, encrypted []byte) error {
	plain, err := decrypt(encrypted, getEncryptionKey())
	if err != nil {
		return err
	}
	bulk := msg.Type == "data" || msg.Type == "udp_data" || msg.Type == "agent_fwd_data"
	if !bulk {
		return writeQuicFrame(s.control, &s.controlMu, plain)
	}
	connID := rtnConnIDFromPayload(msg.Payload)
	if connID == "" {
		return writeQuicFrame(s.control, &s.controlMu, plain)
	}
	ds, err := s.streamForConn(connID)
	if err != nil {
		return err
	}
	return writeQuicFrame(ds.stream, &ds.mu, plain)
}

type quicDataStream struct {
	stream *quic.Stream
	mu     sync.Mutex
}

func (s *quicAgentSession) streamForConn(connID string) (*quicDataStream, error) {
	s.streamsMu.Lock()
	defer s.streamsMu.Unlock()
	if ds, ok := s.streams[connID]; ok {
		return ds, nil
	}
	st, err := s.conn.OpenStreamSync(context.Background())
	if err != nil {
		return nil, err
	}
	ds := &quicDataStream{stream: st}
	s.streams[connID] = ds
	return ds, nil
}

func (s *quicAgentSession) acceptStreams(deliver func([]byte)) {
	for {
		st, err := s.conn.AcceptStream(context.Background())
		if err != nil {
			s.close()
			return
		}
		go s.readStream(st, false, deliver)
	}
}

func (s *quicAgentSession) readStream(st *quic.Stream, closeSession bool, deliver func([]byte)) {
	for {
		payload, err := readQuicFrame(st)
		if err != nil {
			if closeSession && err != io.EOF {
				s.close()
			}
			return
		}
		deliver(payload)
	}
}

func (s *quicAgentSession) close() error {
	s.closeOnce.Do(func() {
		_ = s.conn.CloseWithError(0, "closed")
		if s.onClose != nil {
			s.onClose()
		}
	})
	return nil
}

func writeQuicFrame(st *quic.Stream, mu *sync.Mutex, payload []byte) error {
	if len(payload) > quicMaxEnvelope {
		return fmt.Errorf("quic envelope too large: %d", len(payload))
	}
	if mu != nil {
		mu.Lock()
		defer mu.Unlock()
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(payload)))
	st.SetWriteDeadline(time.Now().Add(30 * time.Second))
	if err := writeAll(st, hdr[:]); err != nil {
		st.SetWriteDeadline(time.Time{})
		return err
	}
	err := writeAll(st, payload)
	st.SetWriteDeadline(time.Time{})
	return err
}

func writeAll(w io.Writer, b []byte) error {
	for len(b) > 0 {
		n, err := w.Write(b)
		if err != nil {
			return err
		}
		if n <= 0 {
			return io.ErrShortWrite
		}
		b = b[n:]
	}
	return nil
}

func quicAuthToken() []byte {
	mac := hmac.New(sha256.New, getEncryptionKey())
	mac.Write([]byte(quicAuthLabel))
	return mac.Sum(nil)
}

func readQuicFrame(r io.Reader) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n == 0 || n > quicMaxEnvelope {
		return nil, fmt.Errorf("invalid quic frame length %d", n)
	}
	payload := make([]byte, n)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, err
	}
	return payload, nil
}

func quicConfig() *quic.Config {
	return &quic.Config{
		HandshakeIdleTimeout:           15 * time.Second,
		MaxIdleTimeout:                 2 * time.Minute,
		KeepAlivePeriod:                10 * time.Second,
		MaxIncomingStreams:             8192,
		InitialStreamReceiveWindow:     1 << 20,
		MaxStreamReceiveWindow:         16 << 20,
		InitialConnectionReceiveWindow: 4 << 20,
		MaxConnectionReceiveWindow:     64 << 20,
		EnableDatagrams:                true,
	}
}

func quicTLSConfig() *tls.Config {
	cert, err := generateQuicCert()
	if err != nil {
		panic(err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{quicALPN},
		MinVersion:   tls.VersionTLS13,
	}
}

func generateQuicCert() (tls.Certificate, error) {
	der, priv, err := quicServerCertMaterial()
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  priv,
	}, nil
}

func quicServerCertMaterial() ([]byte, ed25519.PrivateKey, error) {
	seed := sha256.Sum256(append([]byte(quicCertLabel), getEncryptionKey()...))
	priv := ed25519.NewKeyFromSeed(seed[:])
	serialHash := sha256.Sum256(append([]byte("serial:"), seed[:]...))
	tpl := x509.Certificate{
		SerialNumber: new(big.Int).SetBytes(serialHash[:16]),
		Subject: pkix.Name{
			CommonName: "rosemary-quic",
		},
		NotBefore:             time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2036, 1, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"rosemary-quic"},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tpl, &tpl, priv.Public(), priv)
	if err != nil {
		return nil, nil, err
	}
	return der, priv, nil
}

func netSplitHostPort(addr string) (string, string, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return addr, "", err
	}
	return host, port, nil
}

func onRtnSessionAccept(sess *RtnSession) {
	if !canAcceptAgentConnection(sess.Peer()) {
		log.Printf("Reject rtn agent from %s (rate limit or max agents)", sess.Peer())
		sess.Close()
		return
	}

	connLock.Lock()
	directConnectedAgentID := fmt.Sprintf("conn-%d", nextAgentID)
	nextAgentID++
	sink := &rtnSink{session: sess, connID: directConnectedAgentID}
	rtnSinks[directConnectedAgentID] = sink
	connLock.Unlock()

	sess.onEnvelope = func(plain []byte) {
		var msg Message
		if err := json.Unmarshal(plain, &msg); err != nil {
			return
		}
		actualSourceAgentID := sink.connID
		if msg.OriginalAgentID != "" {
			actualSourceAgentID = msg.OriginalAgentID
		}
		if msg.TargetAgentID != "" && msg.TargetAgentID != "server" && msg.TargetAgentID != actualSourceAgentID {
			relayConnMsg(msg, actualSourceAgentID)
			return
		}
		dispatchConnMsg(msg, actualSourceAgentID, sess.Peer(), &sink.connID)
	}
	sess.onClose = func() {
		releaseAgentConnection(sess.Peer())
		cleanupAgentConn(sink.connID)
	}
}
