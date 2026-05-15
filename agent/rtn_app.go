package main

import (
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"sync"
	"sync/atomic"
	"time"

	quic "github.com/quic-go/quic-go"
)

const (
	quicALPN        = "rosemary-quic/1"
	quicAuthLabel   = "rosemary-quic-auth-v1"
	quicCertLabel   = "rosemary-quic-cert-v1"
	quicMaxEnvelope = 8 << 20
)

type rtnAppCrypter struct{}

func (rtnAppCrypter) Encrypt(p []byte) ([]byte, error) { return encrypt(p, getEncryptionKey()) }
func (rtnAppCrypter) Decrypt(c []byte) ([]byte, error) { return decrypt(c, getEncryptionKey()) }

type agentTransport interface {
	write(encrypted []byte) error
	writeDataForConn(connID string, encrypted []byte) error
	setOnEnvelope(fn func([]byte))
	closed() <-chan struct{}
	Close()
	startUploadLanes(ctx context.Context, agentID string, dispatch func([]byte))
}

type rtnClientAdapter struct {
	conn       *quic.Conn
	control    *quic.Stream
	controlMu  sync.Mutex
	streams    map[string]*quicDataStream
	streamsMu  sync.Mutex
	onEnvelope func([]byte)
	onEnvMu    sync.Mutex
	pending    [][]byte
	closeOnce  sync.Once
	closedCh   chan struct{}
}

func (a *rtnClientAdapter) write(encrypted []byte) error {
	plain, err := decrypt(encrypted, getEncryptionKey())
	if err != nil {
		return err
	}
	return a.writeFrame(a.control, &a.controlMu, plain)
}

func (a *rtnClientAdapter) writeDataForConn(connID string, encrypted []byte) error {
	plain, err := decrypt(encrypted, getEncryptionKey())
	if err != nil {
		return err
	}
	if connID == "" {
		return a.writeFrame(a.control, &a.controlMu, plain)
	}
	ds, err := a.streamForConn(connID)
	if err != nil {
		return err
	}
	return a.writeFrame(ds.stream, &ds.mu, plain)
}

func (a *rtnClientAdapter) setOnEnvelope(fn func([]byte)) {
	a.onEnvMu.Lock()
	a.onEnvelope = fn
	pending := a.pending
	a.pending = nil
	a.onEnvMu.Unlock()
	for _, b := range pending {
		fn(b)
	}
}

func (a *rtnClientAdapter) closed() <-chan struct{} {
	return a.closedCh
}

func (a *rtnClientAdapter) Close() {
	a.closeOnce.Do(func() {
		_ = a.conn.CloseWithError(0, "closed")
		close(a.closedCh)
	})
}

func (a *rtnClientAdapter) startUploadLanes(ctx context.Context, agentID string, dispatch func([]byte)) {
}

func dialRtn(ctx context.Context, serverAddr string) (*rtnClientAdapter, error) {
	configureQuicAgentLogging()
	tlsConf, err := quicClientTLSConfig()
	if err != nil {
		return nil, err
	}
	conn, err := quic.DialAddr(ctx, serverAddr, tlsConf, quicConfig())
	if err != nil {
		return nil, err
	}
	control, err := conn.OpenStreamSync(ctx)
	if err != nil {
		_ = conn.CloseWithError(1, "control stream failed")
		return nil, err
	}
	if err := writeQuicFrameRaw(control, nil, quicAuthToken()); err != nil {
		_ = conn.CloseWithError(1, "auth write failed")
		return nil, err
	}
	a := &rtnClientAdapter{
		conn:     conn,
		control:  control,
		streams:  make(map[string]*quicDataStream),
		closedCh: make(chan struct{}),
	}
	go a.readStream(control, true)
	go a.acceptStreams(ctx)
	go func() {
		<-conn.Context().Done()
		a.Close()
	}()
	return a, nil
}

func configureQuicAgentLogging() {
	if atomic.LoadInt32(&verboseMode) == 0 {
		_ = os.Setenv("QUIC_GO_DISABLE_RECEIVE_BUFFER_WARNING", "true")
	}
}

func quicConfig() *quic.Config {
	return &quic.Config{
		HandshakeIdleTimeout:           15 * time.Second,
		MaxIdleTimeout:                 2 * time.Minute,
		KeepAlivePeriod:                10 * time.Second,
		MaxIncomingStreams:             8192,
		InitialStreamReceiveWindow:     512 << 10,
		MaxStreamReceiveWindow:         2 << 20,
		InitialConnectionReceiveWindow: 1 << 20,
		MaxConnectionReceiveWindow:     4 << 20,
		EnableDatagrams:                true,
	}
}

type quicDataStream struct {
	stream *quic.Stream
	mu     sync.Mutex
}

func (a *rtnClientAdapter) streamForConn(connID string) (*quicDataStream, error) {
	a.streamsMu.Lock()
	defer a.streamsMu.Unlock()
	if ds, ok := a.streams[connID]; ok {
		return ds, nil
	}
	st, err := a.conn.OpenStreamSync(context.Background())
	if err != nil {
		return nil, err
	}
	ds := &quicDataStream{stream: st}
	a.streams[connID] = ds
	go a.readStream(st, false)
	return ds, nil
}

func (a *rtnClientAdapter) writeFrame(st *quic.Stream, mu *sync.Mutex, payload []byte) error {
	return writeQuicFrameRaw(st, mu, payload)
}

func writeQuicFrameRaw(st *quic.Stream, mu *sync.Mutex, payload []byte) error {
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
	if _, err := st.Write(hdr[:]); err != nil {
		st.SetWriteDeadline(time.Time{})
		return err
	}
	_, err := st.Write(payload)
	st.SetWriteDeadline(time.Time{})
	return err
}

func quicAuthToken() []byte {
	mac := hmac.New(sha256.New, getEncryptionKey())
	mac.Write([]byte(quicAuthLabel))
	return mac.Sum(nil)
}

func quicClientTLSConfig() (*tls.Config, error) {
	expectedDER, err := quicServerCertDER()
	if err != nil {
		return nil, err
	}
	expectedPin := sha256.Sum256(expectedDER)
	return &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{quicALPN},
		MinVersion:         tls.VersionTLS13,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return errors.New("quic: missing server certificate")
			}
			gotPin := sha256.Sum256(rawCerts[0])
			if !hmac.Equal(gotPin[:], expectedPin[:]) {
				return errors.New("quic: server certificate pin mismatch")
			}
			return nil
		},
	}, nil
}

func quicServerCertDER() ([]byte, error) {
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
	return x509.CreateCertificate(rand.Reader, &tpl, &tpl, priv.Public(), priv)
}

func (a *rtnClientAdapter) acceptStreams(ctx context.Context) {
	for {
		st, err := a.conn.AcceptStream(ctx)
		if err != nil {
			a.Close()
			return
		}
		go a.readStream(st, false)
	}
}

func (a *rtnClientAdapter) readStream(st *quic.Stream, closeSession bool) {
	for {
		payload, err := readQuicFrame(st)
		if err != nil {
			if closeSession && !errors.Is(err, io.EOF) {
				a.Close()
			}
			return
		}
		encrypted, err := encrypt(payload, getEncryptionKey())
		if err != nil {
			a.Close()
			return
		}
		a.deliver(encrypted)
	}
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

func (a *rtnClientAdapter) deliver(payload []byte) {
	a.onEnvMu.Lock()
	fn := a.onEnvelope
	if fn == nil {
		a.pending = append(a.pending, payload)
		a.onEnvMu.Unlock()
		return
	}
	a.onEnvMu.Unlock()
	fn(payload)
}
