// Package syslogsink is the acceptance gates' syslog receiver (plan M12 §9, gates S1–S3): a TLS listener on the test
// host that reads RFC 5424 messages in octet-counting framing (RFC 6587 section 3.4.1) and records them. Like the
// webhook sink it runs on a port the test chooses and is reached by the stack's api and notifier as acceptance-host
// through the Docker host gateway. It can be stopped and started again on the same port, to make a destination stall
// and recover.
package syslogsink

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// Host is the name under which the development stack reaches the test host (compose.dev.yaml extra_hosts) and the
// name the sink's certificate carries.
const Host = "acceptance-host"

// maxFrame bounds one message so that a broken sender cannot make the sink allocate without limit.
const maxFrame = 1 << 20

// bom is the UTF-8 marker that starts the MSG of every Paddock message (RFC 5424 section 6.4).
const bom = "\xef\xbb\xbf"

// Message is one received syslog message.
type Message struct {
	PRI       int
	Timestamp string
	Hostname  string
	AppName   string
	ProcID    string
	MsgID     string
	// Body is the MSG without the byte order mark.
	Body     []byte
	Received time.Time
}

// Parse decodes the content of one frame: "<PRI>1 TIMESTAMP HOSTNAME APP-NAME PROCID MSGID - MSG".
func Parse(content []byte) (Message, error) {
	s := string(content)
	if !strings.HasPrefix(s, "<") {
		return Message{}, fmt.Errorf("syslogsink: no PRI in %q", abbreviate(s))
	}
	end := strings.IndexByte(s, '>')
	if end < 2 {
		return Message{}, fmt.Errorf("syslogsink: unterminated PRI in %q", abbreviate(s))
	}
	pri, err := strconv.Atoi(s[1:end])
	if err != nil || pri < 0 || pri > 191 {
		return Message{}, fmt.Errorf("syslogsink: PRI %q", s[1:end])
	}
	fields := strings.SplitN(s[end+1:], " ", 8)
	if len(fields) != 8 || fields[0] != "1" || fields[6] != "-" {
		return Message{}, fmt.Errorf("syslogsink: header of %q is not RFC 5424 with nil structured data", abbreviate(s))
	}
	if !validHeaderField(fields[2], 255) || !validHeaderField(fields[3], 48) || !validHeaderField(fields[4], 128) ||
		!validHeaderField(fields[5], 32) {
		return Message{}, fmt.Errorf("syslogsink: HOSTNAME, APP-NAME, PROCID or MSGID of %q outside RFC 5424 section 6", abbreviate(s))
	}
	if !strings.HasPrefix(fields[7], bom) {
		return Message{}, fmt.Errorf("syslogsink: MSG without byte order mark in %q", abbreviate(s))
	}
	return Message{
		PRI: pri, Timestamp: fields[1], Hostname: fields[2], AppName: fields[3], ProcID: fields[4], MsgID: fields[5],
		Body: []byte(strings.TrimPrefix(fields[7], bom)),
	}, nil
}

// validHeaderField reports whether v is 1 to max printable US-ASCII characters (RFC 5424 section 6 PRINTUSASCII, no
// space), which is also what the nil value "-" is.
func validHeaderField(v string, max int) bool {
	if len(v) < 1 || len(v) > max {
		return false
	}
	for i := 0; i < len(v); i++ {
		if v[i] < 33 || v[i] > 126 {
			return false
		}
	}
	return true
}

func abbreviate(s string) string {
	if len(s) > 120 {
		return s[:120] + "…"
	}
	return s
}

// readFrame reads one octet-counted frame: "MSG-LEN SP content".
func readFrame(r *bufio.Reader) ([]byte, error) {
	digits, err := r.ReadString(' ')
	if err != nil {
		return nil, err
	}
	n, err := strconv.Atoi(strings.TrimSuffix(digits, " "))
	if err != nil || n <= 0 || n > maxFrame {
		return nil, fmt.Errorf("syslogsink: octet count %q", digits)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// Sink is a running receiver.
type Sink struct {
	port   int
	cert   tls.Certificate
	caPEM  string
	tlsCfg *tls.Config

	mu       sync.Mutex
	ln       net.Listener
	conns    map[net.Conn]struct{}
	messages []Message
	bad      []error
	refused  []error
	wg       sync.WaitGroup
}

// Start listens on an ephemeral port of every interface of the test host (the stack's containers arrive through the
// Docker bridge gateway, not through loopback) and stops when the test ends.
func Start(t testing.TB) *Sink {
	t.Helper()
	cert, caPEM, err := selfSigned()
	if err != nil {
		t.Fatalf("syslogsink: certificate: %v", err)
	}
	s := &Sink{
		cert: cert, caPEM: caPEM, conns: map[net.Conn]struct{}{},
		tlsCfg: &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12},
	}
	if err := s.listen(0); err != nil {
		t.Fatalf("syslogsink: listen: %v", err)
	}
	t.Cleanup(s.Stop)
	return s
}

func (s *Sink) listen(port int) error {
	ln, err := net.Listen("tcp", ":"+strconv.Itoa(port)) //nolint:gosec // a test receiver on the test host only
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.ln, s.port = ln, ln.Addr().(*net.TCPAddr).Port
	s.mu.Unlock()
	s.wg.Add(1)
	go s.accept(ln)
	return nil
}

func (s *Sink) accept(ln net.Listener) {
	defer s.wg.Done()
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		s.mu.Lock()
		s.conns[c] = struct{}{}
		s.mu.Unlock()
		s.wg.Add(1)
		go s.serve(c)
	}
}

func (s *Sink) serve(c net.Conn) {
	defer s.wg.Done()
	defer func() {
		_ = c.Close()
		s.mu.Lock()
		delete(s.conns, c)
		s.mu.Unlock()
	}()
	conn := tls.Server(c, s.tlsCfg)
	_ = conn.SetDeadline(time.Now().Add(time.Minute))
	// A refused certificate ends in a failed handshake; that is the client's choice, not malformed syslog.
	if err := conn.Handshake(); err != nil {
		s.recordHandshake(err)
		return
	}
	r := bufio.NewReader(conn)
	for {
		frame, err := readFrame(r)
		if err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) && !errors.Is(err, io.ErrUnexpectedEOF) {
				s.record(nil, err)
			}
			return
		}
		m, err := Parse(frame)
		s.record(&m, err)
	}
}

func (s *Sink) recordHandshake(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refused = append(s.refused, err)
}

// Handshakes returns the TLS handshakes that failed so far, for instance because the client does not trust the
// certificate.
func (s *Sink) Handshakes() []error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]error(nil), s.refused...)
}

func (s *Sink) record(m *Message, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err != nil {
		s.bad = append(s.bad, err)
		return
	}
	m.Received = time.Now()
	s.messages = append(s.messages, *m)
}

// Host is the syslog_host and ServerName the syslog_server_name of a destination that targets the sink.
func (s *Sink) Host() string { return Host }

// ServerName is the name the sink's certificate carries.
func (s *Sink) ServerName() string { return Host }

// Port is the port the stack reaches the sink on; it stays the same across Stop and Restart.
func (s *Sink) Port() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.port
}

// CAPEM is the sink's self-signed certificate, the syslog_ca_pem of a destination that trusts it.
func (s *Sink) CAPEM() string { return s.caPEM }

// Stop closes the listener and every open connection; connections to the port are refused until Restart.
func (s *Sink) Stop() {
	s.mu.Lock()
	ln := s.ln
	s.ln = nil
	s.mu.Unlock()
	if ln != nil {
		_ = ln.Close()
	}
	// After the listener is closed no connection is added, so the snapshot is complete.
	s.mu.Lock()
	conns := make([]net.Conn, 0, len(s.conns))
	for c := range s.conns {
		conns = append(conns, c)
	}
	s.mu.Unlock()
	for _, c := range conns {
		_ = c.Close()
	}
	s.wg.Wait()
}

// Restart listens on the port of the first Start again; the received messages are kept.
func (s *Sink) Restart(t testing.TB) {
	t.Helper()
	s.mu.Lock()
	running, port := s.ln != nil, s.port
	s.mu.Unlock()
	if running {
		t.Fatalf("syslogsink: Restart of a running sink")
	}
	var err error
	// The port may linger briefly after the close; a new listener on it is normally immediate.
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(100 * time.Millisecond) {
		if err = s.listen(port); err == nil {
			return
		}
	}
	t.Fatalf("syslogsink: listen again on %d: %v", port, err)
}

// Messages returns a copy of the messages received so far.
func (s *Sink) Messages() []Message {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Message(nil), s.messages...)
}

// Malformed returns the framing and header errors seen so far; a conforming notifier causes none.
func (s *Sink) Malformed() []error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]error(nil), s.bad...)
}

// Wait polls until cond holds for the messages received so far and returns them; it fails the test after timeout.
func (s *Sink) Wait(t testing.TB, timeout time.Duration, what string, cond func([]Message) bool) []Message {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		got := s.Messages()
		if cond(got) {
			return got
		}
		if time.Now().After(deadline) {
			t.Fatalf("syslogsink: %s not received within %s (%d messages)", what, timeout, len(got))
		}
		time.Sleep(250 * time.Millisecond)
	}
}

// selfSigned returns a certificate for Host, valid for a day, and its PEM; it is its own CA, so the PEM is what a
// destination trusts.
func selfSigned() (tls.Certificate, string, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	if err != nil {
		return tls.Certificate{}, "", err
	}
	tpl := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: Host},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true, IsCA: true,
		DNSNames: []string{Host},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key},
		string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), nil
}
