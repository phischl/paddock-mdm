package notifier

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
	"github.com/phischl/paddock-mdm/server/internal/domain/outbound"
)

// syslogPKI is a test CA and a server certificate it issued for syslog.example.test.
type syslogPKI struct {
	caPEM string
	cert  tls.Certificate
}

func newSyslogPKI(t *testing.T) syslogPKI {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "syslog test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "syslog.example.test"},
		DNSNames: []string{"syslog.example.test"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, leaf, caCert, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	return syslogPKI{
		caPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})),
		cert:  tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key},
	}
}

// syslogSink is a local TLS syslog receiver. Each connection's frames (octet-counting) and SNI are recorded. The next
// connection misbehaves when one of these is set: resetAfter > 0 resets it (SO_LINGER 0) after that many frames,
// closeAfter > 0 waits closeDelay after that many frames and closes TLS (close_notify, then an RST as the rest of
// the batch is unread), finAfter > 0 half-closes it (a bare FIN) after that many frames, stops reading and closes it
// finHold later (an RST), stall stops reading after stallAfter frames and holds the connection until the test ends.
// maxVersion caps the TLS version of every connection.
type syslogSink struct {
	t    *testing.T
	ln   net.Listener
	port int
	mu   sync.Mutex
	sni  []string
	// conns holds the frames of every finished connection, nil for a failed handshake; waited counts the ones wait
	// returned.
	conns      [][][]byte
	waited     int
	resetAfter int
	closeAfter int
	closeDelay time.Duration
	finAfter   int
	finHold    time.Duration
	stall      bool
	stallAfter int
	maxVersion uint16
	done       chan struct{}
}

func newSyslogSink(t *testing.T, cert tls.Certificate) *syslogSink {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	return serveSyslogSink(t, cert, ln)
}

func serveSyslogSink(t *testing.T, cert tls.Certificate, ln net.Listener) *syslogSink {
	t.Helper()
	s := &syslogSink{t: t, ln: ln, port: ln.Addr().(*net.TCPAddr).Port, done: make(chan struct{})}
	cfg := &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert},
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			s.mu.Lock()
			s.sni = append(s.sni, hello.ServerName)
			maxVersion := s.maxVersion
			s.mu.Unlock()
			if maxVersion != 0 {
				return &tls.Config{MinVersion: tls.VersionTLS10, MaxVersion: maxVersion,
					Certificates: []tls.Certificate{cert}}, nil
			}
			return nil, nil
		}}
	go func() {
		for {
			raw, err := ln.Accept()
			if err != nil {
				return
			}
			go s.serve(raw, cfg)
		}
	}()
	t.Cleanup(func() {
		close(s.done)
		_ = ln.Close()
	})
	return s
}

func (s *syslogSink) serve(raw net.Conn, cfg *tls.Config) {
	var frames [][]byte
	defer func() {
		s.mu.Lock()
		s.conns = append(s.conns, frames)
		s.mu.Unlock()
	}()
	s.mu.Lock()
	reset, closeAfter, closeDelay, stall, stallAfter := s.resetAfter, s.closeAfter, s.closeDelay, s.stall, s.stallAfter
	finAfter, finHold := s.finAfter, s.finHold
	s.resetAfter, s.closeAfter, s.finAfter, s.stall = 0, 0, 0, false
	s.mu.Unlock()
	conn := tls.Server(raw, cfg)
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if err := conn.Handshake(); err != nil {
		_ = raw.Close()
		return
	}
	r := bufio.NewReader(conn)
	for {
		if stall && len(frames) == stallAfter {
			<-s.done
			_ = raw.Close()
			return
		}
		n, err := r.ReadString(' ')
		if err != nil {
			break
		}
		length, err := strconv.Atoi(n[:len(n)-1])
		if err != nil {
			break
		}
		msg := make([]byte, length)
		if _, err := io.ReadFull(r, msg); err != nil {
			break
		}
		frames = append(frames, msg)
		if reset > 0 && len(frames) == reset {
			_ = raw.(*net.TCPConn).SetLinger(0)
			_ = raw.Close()
			break
		}
		if closeAfter > 0 && len(frames) == closeAfter {
			time.Sleep(closeDelay)
			_ = conn.Close()
			return
		}
		if finAfter > 0 && len(frames) == finAfter {
			_ = raw.(*net.TCPConn).CloseWrite()
			select {
			case <-time.After(finHold):
			case <-s.done:
			}
			_ = raw.Close()
			return
		}
	}
	if reset == 0 {
		_ = conn.Close()
	}
}

// wait waits until n more connections finished and returns the frames of the last of them.
func (s *syslogSink) wait(n int) [][]byte {
	s.t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		s.mu.Lock()
		if len(s.conns) >= s.waited+n {
			s.waited += n
			frames := s.conns[s.waited-1]
			s.mu.Unlock()
			return frames
		}
		s.mu.Unlock()
		if time.Now().After(deadline) {
			s.t.Fatal("the sink saw no connection")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func (s *syslogSink) lastSNI() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.sni) == 0 {
		return ""
	}
	return s.sni[len(s.sni)-1]
}

// dnsResolver resolves from a map; a missing name is a *net.DNSError like the system resolver's.
type dnsResolver map[string][]netip.Addr

func (r dnsResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	if a, ok := r[host]; ok {
		return a, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
}

var loopback = []netip.Addr{netip.MustParseAddr("127.0.0.1")}

func eventsMessage(n int) outbound.Message {
	m := testMessage(uuid.New())
	m.Kind = outbound.KindEvents
	m.ForwardSeq = &outbound.SeqRange{From: 1, To: int64(n)}
	m.Events = make([]outbound.MessageEvent, n)
	for i := range m.Events {
		m.Events[i] = outbound.MessageEvent{ForwardSeq: int64(i + 1), CommitSeq: int64(100 + i), Event: audit.Event{
			EventID: uuid.New(), Code: tamper, Outcome: audit.OutcomeSuccess,
			OccurredAt: time.Date(2026, 11, 4, 8, 0, i, 0, time.UTC),
		}}
	}
	return m
}

// syslogMSG decodes the JSON MSG of a received frame.
func syslogMSG(t *testing.T, frame []byte) map[string]any {
	t.Helper()
	_, msg, ok := bytes.Cut(frame, []byte("\xef\xbb\xbf"))
	if !ok {
		t.Fatalf("no BOM in %q", frame)
	}
	var out map[string]any
	if err := json.Unmarshal(msg, &out); err != nil {
		t.Fatalf("MSG %q: %v", msg, err)
	}
	return out
}

// TestSyslogDelivers: the transport connects to the address its resolver returned (the pinned address; the name
// exists nowhere else), sends syslog_server_name as SNI, trusts the CA bundle, and writes one message per event; a test
// message is one control message; without syslog_server_name the host is the server name.
func TestSyslogDelivers(t *testing.T) {
	pki := newSyslogPKI(t)
	sink := newSyslogSink(t, pki.cert)
	s := NewSyslog(true)
	s.Hostname = "admin.paddock.example.org"
	s.resolver = dnsResolver{"collector.test": loopback, "syslog.example.test": loopback}
	d := Destination{Type: outbound.TypeSyslog, SyslogHost: "collector.test", SyslogPort: sink.port,
		SyslogServerName: "syslog.example.test", SyslogCAPEM: pki.caPEM}

	m := eventsMessage(3)
	if err := s.Deliver(context.Background(), d, m); err != nil {
		t.Fatalf("deliver: %v", err)
	}
	frames := sink.wait(1)
	if len(frames) != 3 {
		t.Fatalf("%d messages, want 3", len(frames))
	}
	for i, f := range frames {
		if !bytes.HasPrefix(f, []byte("<133>1 2026-11-04T08:00:0"+strconv.Itoa(i)+"Z admin.paddock.example.org paddock acme "+string(tamper)+" - ")) {
			t.Errorf("message %d: %q", i, f)
		}
		if msg := syslogMSG(t, f); msg["forward_seq"] != float64(i+1) || msg["delivery_id"] != m.DeliveryID {
			t.Errorf("message %d MSG %v", i, msg)
		}
	}
	if got := sink.lastSNI(); got != "syslog.example.test" {
		t.Errorf("SNI %q, want syslog.example.test", got)
	}

	d.SyslogHost, d.SyslogServerName = "syslog.example.test", ""
	if err := s.Deliver(context.Background(), d, testMessage(uuid.New())); err != nil {
		t.Fatalf("test delivery: %v", err)
	}
	frames = sink.wait(1)
	if len(frames) != 1 || !bytes.Contains(frames[0], []byte(" paddock.test - ")) {
		t.Errorf("test delivery frames %q", frames)
	}
	if got := sink.lastSNI(); got != "syslog.example.test" {
		t.Errorf("SNI %q, want the host", got)
	}
}

// TestSyslogFailures: the error classes of plan M12 decision 18.
func TestSyslogFailures(t *testing.T) {
	pki := newSyslogPKI(t)
	sink := newSyslogSink(t, pki.cert)
	base := Destination{Type: outbound.TypeSyslog, SyslogHost: "syslog.example.test", SyslogPort: sink.port,
		SyslogCAPEM: pki.caPEM}
	resolver := dnsResolver{"syslog.example.test": loopback}
	for name, tc := range map[string]struct {
		allowPrivate bool
		mut          func(*Destination)
		want         string
	}{
		"self-signed without the CA bundle": {true, func(d *Destination) { d.SyslogCAPEM = "" }, "tls"},
		"certificate for another name":      {true, func(d *Destination) { d.SyslogServerName = "other.example.test" }, "tls"},
		"private address without dev flag":  {false, nil, "denied_address"},
		"private literal without dev flag":  {false, func(d *Destination) { d.SyslogHost = "127.0.0.1" }, "denied_address"},
		"unknown name":                      {true, func(d *Destination) { d.SyslogHost = "nowhere.example.test" }, "dns"},
	} {
		s := NewSyslog(tc.allowPrivate)
		s.resolver = resolver
		d := base
		if tc.mut != nil {
			tc.mut(&d)
		}
		if got := ErrorClass(s.Deliver(context.Background(), d, eventsMessage(1))); got != tc.want {
			t.Errorf("%s: class %q, want %q", name, got, tc.want)
		}
	}

	t.Run("server limited to TLS 1.1", func(t *testing.T) {
		sink := newSyslogSink(t, pki.cert)
		sink.mu.Lock()
		sink.maxVersion = tls.VersionTLS11
		sink.mu.Unlock()
		s := NewSyslog(true)
		s.resolver = resolver
		d := base
		d.SyslogPort = sink.port
		if got := ErrorClass(s.Deliver(context.Background(), d, eventsMessage(1))); got != "tls" {
			t.Errorf("class %q, want tls", got)
		}
	})

	t.Run("closed port", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		port := ln.Addr().(*net.TCPAddr).Port
		_ = ln.Close()
		s := NewSyslog(true)
		s.resolver = resolver
		d := base
		d.SyslogPort = port
		if got := ErrorClass(s.Deliver(context.Background(), d, eventsMessage(1))); got != "dial" {
			t.Errorf("class %q, want dial", got)
		}
	})

	t.Run("connection reset mid-batch", func(t *testing.T) {
		// A sink of its own: the handshakes the cases above refused may still finish on the shared one.
		sink := newSyslogSink(t, pki.cert)
		base := base
		base.SyslogPort = sink.port
		sink.mu.Lock()
		sink.resetAfter = 1
		sink.mu.Unlock()
		s := NewSyslog(true)
		s.resolver = resolver
		err := s.Deliver(context.Background(), base, eventsMessage(50))
		if got := ErrorClass(err); got != "io" {
			t.Errorf("class %q (%v), want io", got, err)
		}
		if frames := sink.wait(1); len(frames) != 1 {
			t.Errorf("the sink took %d messages before the reset, want 1", len(frames))
		}
	})
}

// TestSyslogBatchRetried: a syslog delivery that the receiver drops mid-batch fails, and the engine sends the same
// batch again under the same delivery ID and forward sequence numbers; the cursor moves only after that.
func TestSyslogBatchRetried(t *testing.T) {
	pki := newSyslogPKI(t)
	sink := newSyslogSink(t, pki.cert)
	h := newHarness(t)
	s := NewSyslog(true)
	s.resolver = dnsResolver{"syslog.example.test": loopback}
	h.e.transports[outbound.TypeSyslog] = s
	d := h.store.add(h.org, Destination{ID: uuid.Must(uuid.NewV7()), Type: outbound.TypeSyslog, Name: "siem",
		Filter: outbound.FilterSecurity, SyslogHost: "syslog.example.test", SyslogPort: sink.port,
		SyslogCAPEM: pki.caPEM}, State{})
	h.index.append(h.org, tamper, 40)

	sink.mu.Lock()
	sink.resetAfter = 1
	sink.mu.Unlock()
	h.round()
	sink.wait(1)
	st := h.state(d)
	if st.Cursor != 0 || st.Pending == uuid.Nil || st.ConsecutiveFailures != 1 {
		t.Fatalf("state after the dropped batch %+v", st)
	}
	if got := h.store.deliveries[st.Pending].lastError; got != "io" {
		t.Errorf("last_error %q, want io", got)
	}
	pending := st.Pending

	h.now = h.now.Add(5 * time.Second)
	h.round()
	frames := sink.wait(1)
	if len(frames) != 40 {
		t.Fatalf("the retry carried %d messages, want 40", len(frames))
	}
	for i, f := range frames {
		msg := syslogMSG(t, f)
		if msg["forward_seq"] != float64(i+1) || msg["delivery_id"] != pending.String() {
			t.Fatalf("message %d: forward_seq %v delivery %v, want %d %s", i, msg["forward_seq"], msg["delivery_id"],
				i+1, pending)
		}
	}
	if st := h.state(d); st.Cursor != 40 || st.Pending != uuid.Nil || st.ConsecutiveFailures != 0 {
		t.Errorf("state after the retry %+v", st)
	}
}

func TestIOClass(t *testing.T) {
	if got := ioClass(errors.New("connection reset by peer")); got != "io" {
		t.Errorf("reset: %q", got)
	}
	if got := ioClass(context.DeadlineExceeded); got != "timeout" {
		t.Errorf("deadline: %q", got)
	}
}
