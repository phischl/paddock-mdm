package notifier

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"io"
	"math/big"
	"mime/quotedprintable"
	"net"
	"net/mail"
	"net/smtp"
	"net/textproto"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
	"github.com/phischl/paddock-mdm/server/internal/domain/outbound"
)

const testPassword = "s3cret-relay-password"

// testCert is a self-signed certificate for 127.0.0.1 and the pool that trusts it.
func testCert(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "relay"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IsCA: true, BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, pool
}

// fakeRelay is a scripted SMTP server: it records every command line and message and answers as configured.
type fakeRelay struct {
	t        *testing.T
	ln       net.Listener
	cert     tls.Certificate
	implicit bool   // TLS from the first byte
	startTLS bool   // advertise STARTTLS
	auth     string // advertised AUTH mechanisms, "" for none
	authFail bool
	rcptCode int  // answer to RCPT when set
	silent   bool // never greets nor handshakes

	mu       sync.Mutex
	commands []string
	creds    []string // user\x00password as received by any mechanism
	tlsAt    []int    // index into commands at which TLS became active
	messages []string
}

func startRelay(t *testing.T, cert tls.Certificate, configure func(*fakeRelay)) *fakeRelay {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	r := &fakeRelay{t: t, ln: ln, cert: cert}
	if configure != nil {
		configure(r)
	}
	done := make(chan struct{})
	t.Cleanup(func() { _ = ln.Close(); <-done })
	go func() {
		defer close(done)
		var wg sync.WaitGroup
		for {
			conn, err := ln.Accept()
			if err != nil {
				wg.Wait()
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer func() { _ = conn.Close() }()
				r.serve(conn)
			}()
		}
	}()
	return r
}

func (r *fakeRelay) port() int { return r.ln.Addr().(*net.TCPAddr).Port }

func (r *fakeRelay) record(line string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.commands = append(r.commands, line)
}

func (r *fakeRelay) snapshot() (commands, creds, messages []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.commands...), append([]string(nil), r.creds...), append([]string(nil), r.messages...)
}

func (r *fakeRelay) sawCommand(prefix string) bool {
	cmds, _, _ := r.snapshot()
	for _, c := range cmds {
		if strings.HasPrefix(strings.ToUpper(c), prefix) {
			return true
		}
	}
	return false
}

func (r *fakeRelay) serve(conn net.Conn) {
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if r.silent {
		_, _ = io.Copy(io.Discard, conn)
		return
	}
	secure := false
	if r.implicit {
		conn = tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{r.cert}})
		secure = true
	}
	tp := textproto.NewConn(conn)
	reply := func(s string) { _ = tp.PrintfLine("%s", s) }
	reply("220 fake ESMTP")
	for {
		line, err := tp.ReadLine()
		if err != nil {
			return
		}
		r.record(line)
		verb := strings.ToUpper(strings.SplitN(line, " ", 2)[0])
		switch verb {
		case "EHLO", "HELO":
			ext := []string{"fake"}
			if r.startTLS && !secure {
				ext = append(ext, "STARTTLS")
			}
			if r.auth != "" {
				ext = append(ext, "AUTH "+r.auth)
			}
			for i, e := range ext {
				sep := "-"
				if i == len(ext)-1 {
					sep = " "
				}
				reply("250" + sep + e)
			}
		case "STARTTLS":
			reply("220 go ahead")
			tc := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{r.cert}})
			if err := tc.Handshake(); err != nil {
				return
			}
			conn, secure = tc, true
			tp = textproto.NewConn(conn)
			r.mu.Lock()
			r.tlsAt = append(r.tlsAt, len(r.commands))
			r.mu.Unlock()
		case "AUTH":
			r.serveAuth(tp, strings.Fields(line)[1:], reply)
		case "MAIL":
			reply("250 ok")
		case "RCPT":
			if r.rcptCode != 0 {
				reply(strconv.Itoa(r.rcptCode) + " 5.1.1 <someone@example.org> refused")
				continue
			}
			reply("250 ok")
		case "DATA":
			reply("354 go ahead")
			msg, err := tp.ReadDotBytes()
			if err != nil {
				return
			}
			r.mu.Lock()
			r.messages = append(r.messages, string(msg))
			r.mu.Unlock()
			reply("250 queued")
		case "QUIT":
			reply("221 bye")
			return
		default:
			reply("502 unknown")
		}
	}
}

func (r *fakeRelay) serveAuth(tp *textproto.Conn, args []string, reply func(string)) {
	b64 := func(s string) string {
		d, _ := base64.StdEncoding.DecodeString(s)
		return string(d)
	}
	read := func() string {
		l, _ := tp.ReadLine()
		return b64(l)
	}
	var cred string
	switch strings.ToUpper(args[0]) {
	case "PLAIN":
		parts := strings.SplitN(b64(args[1]), "\x00", 3)
		cred = parts[1] + "\x00" + parts[2]
	case "LOGIN":
		reply("334 " + base64.StdEncoding.EncodeToString([]byte("Username:")))
		user := read()
		reply("334 " + base64.StdEncoding.EncodeToString([]byte("Password:")))
		cred = user + "\x00" + read()
	case "CRAM-MD5":
		reply("334 " + base64.StdEncoding.EncodeToString([]byte("<1.2@relay>")))
		cred = read()
	}
	r.mu.Lock()
	r.creds = append(r.creds, cred)
	r.mu.Unlock()
	if r.authFail {
		reply("535 5.7.8 authentication failed")
		return
	}
	reply("235 ok")
}

func relayConfig(r *fakeRelay, pool *x509.CertPool, mode string) EmailConfig {
	return EmailConfig{Host: "127.0.0.1", Port: r.port(), TLS: mode, From: mail.Address{Address: "paddock@example.com"},
		Timeout: 5 * time.Second, RootCAs: pool}
}

func emailDestination() Destination {
	return Destination{ID: uuid.Must(uuid.NewV7()), Type: outbound.TypeEmail, Name: "secops",
		Recipients: []string{"a@example.org", "b@example.org"}, ScopeName: "Acme Corp"}
}

func emailMessage(n int) outbound.Message {
	m := outbound.Message{Schema: outbound.MessageSchema, Kind: outbound.KindEvents, DeliveryID: uuid.NewString(),
		DestinationID: uuid.NewString(), Organization: "acme", SentAt: time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC),
		ForwardSeq: &outbound.SeqRange{From: 7, To: int64(6 + n)}}
	for i := range n {
		code := audit.CodeDeviceTamperSudoersDFile
		if i%2 == 1 {
			code = audit.CodeAdminLogin
		}
		m.Events = append(m.Events, outbound.MessageEvent{ForwardSeq: int64(7 + i), Event: audit.Event{
			EventID: uuid.New(), Code: code, Outcome: audit.OutcomeSuccess,
			OccurredAt: time.Date(2026, 10, 31, 11, 0, i, 0, time.UTC),
			Actor:      audit.Actor{Type: audit.ActorAdmin, Display: "alice"},
			Target:     &audit.Target{Type: "device", ID: "dev-" + strconv.Itoa(i), Display: "host-" + strconv.Itoa(i)},
			Params:     map[string]any{"file": "evil-" + strconv.Itoa(i)},
		}})
	}
	return m
}

func deliveryClass(t *testing.T, err error) string {
	t.Helper()
	if err == nil {
		return ""
	}
	var d *DeliveryError
	if !errors.As(err, &d) {
		t.Fatalf("error %v is not a *DeliveryError", err)
	}
	for _, secret := range []string{testPassword, "a@example.org", "b@example.org", "someone@example.org"} {
		if strings.Contains(err.Error(), secret) {
			t.Fatalf("error %q carries %q", err, secret)
		}
	}
	return d.Class
}

// TestEmailStartTLS: the default mode upgrades with STARTTLS before anything else is said, authenticates over TLS,
// and sends one message to every recipient.
func TestEmailStartTLS(t *testing.T) {
	cert, pool := testCert(t)
	r := startRelay(t, cert, func(r *fakeRelay) { r.startTLS, r.auth = true, "PLAIN LOGIN" })
	cfg := relayConfig(r, pool, SMTPStartTLS)
	cfg.Username, cfg.Password = "relay-user", testPassword
	if err := NewEmail(cfg).Deliver(context.Background(), emailDestination(), emailMessage(2)); err != nil {
		t.Fatalf("deliver: %v", err)
	}
	cmds, creds, msgs := r.snapshot()
	if len(r.tlsAt) != 1 || len(msgs) != 1 || len(creds) != 1 || creds[0] != "relay-user\x00"+testPassword {
		t.Fatalf("commands %q, creds %d, messages %d", cmds, len(creds), len(msgs))
	}
	for i, c := range cmds {
		if (strings.HasPrefix(c, "AUTH") || strings.HasPrefix(c, "MAIL")) && i < r.tlsAt[0] {
			t.Fatalf("%q before STARTTLS: %q", c, cmds)
		}
	}
	var rcpts []string
	for _, c := range cmds {
		if strings.HasPrefix(c, "RCPT") {
			rcpts = append(rcpts, c)
		}
	}
	if len(rcpts) != 2 || !strings.Contains(rcpts[0], "a@example.org") || !strings.Contains(rcpts[1], "b@example.org") {
		t.Fatalf("recipients %q", rcpts)
	}
}

// TestEmailTLSRequired: without TLS the transport never authenticates and never sends in starttls mode.
func TestEmailTLSRequired(t *testing.T) {
	cert, pool := testCert(t)

	t.Run("starttls refuses a relay without STARTTLS", func(t *testing.T) {
		r := startRelay(t, cert, func(r *fakeRelay) { r.auth = "PLAIN LOGIN CRAM-MD5" })
		cfg := relayConfig(r, pool, SMTPStartTLS)
		cfg.Username, cfg.Password = "relay-user", testPassword
		err := NewEmail(cfg).Deliver(context.Background(), emailDestination(), emailMessage(1))
		if c := deliveryClass(t, err); c != "smtp_tls" {
			t.Fatalf("class %q, want smtp_tls", c)
		}
		if r.sawCommand("AUTH") || r.sawCommand("MAIL") {
			t.Fatal("the relay received AUTH or MAIL without TLS")
		}
	})

	t.Run("plaintext AUTH is refused in mode none", func(t *testing.T) {
		for _, mech := range []string{"PLAIN", "LOGIN", "CRAM-MD5"} {
			r := startRelay(t, cert, func(r *fakeRelay) { r.auth = mech })
			cfg := relayConfig(r, pool, SMTPNone)
			cfg.Username, cfg.Password = "relay-user", testPassword
			err := NewEmail(cfg).Deliver(context.Background(), emailDestination(), emailMessage(1))
			if c := deliveryClass(t, err); c != "smtp_tls" {
				t.Fatalf("%s: class %q, want smtp_tls", mech, c)
			}
			if _, creds, _ := r.snapshot(); r.sawCommand("AUTH") || len(creds) != 0 {
				t.Fatalf("%s: credentials sent without TLS", mech)
			}
		}
	})

	t.Run("LOGIN refuses a connection without TLS", func(t *testing.T) {
		a := &loginAuth{username: "u", password: testPassword, host: "relay"}
		if _, _, err := a.Start(&smtp.ServerInfo{Name: "relay", TLS: false, Auth: []string{"LOGIN"}}); err == nil {
			t.Fatal("LOGIN started without TLS")
		}
		if _, _, err := a.Start(&smtp.ServerInfo{Name: "other", TLS: true, Auth: []string{"LOGIN"}}); err == nil {
			t.Fatal("LOGIN started for another host")
		}
	})

	t.Run("none delivers without TLS and without credentials", func(t *testing.T) {
		r := startRelay(t, cert, nil)
		if err := NewEmail(relayConfig(r, pool, SMTPNone)).Deliver(context.Background(), emailDestination(), emailMessage(1)); err != nil {
			t.Fatalf("deliver: %v", err)
		}
		if _, _, msgs := r.snapshot(); len(msgs) != 1 || r.sawCommand("AUTH") {
			t.Fatalf("%d messages", len(msgs))
		}
	})

	t.Run("an untrusted certificate is refused", func(t *testing.T) {
		r := startRelay(t, cert, func(r *fakeRelay) { r.startTLS = true })
		err := NewEmail(relayConfig(r, x509.NewCertPool(), SMTPStartTLS)).Deliver(context.Background(), emailDestination(), emailMessage(1))
		if c := deliveryClass(t, err); c != "smtp_tls" {
			t.Fatalf("class %q, want smtp_tls", c)
		}
		if r.sawCommand("MAIL") {
			t.Fatal("sent after a failed verification")
		}
		ri := startRelay(t, cert, func(r *fakeRelay) { r.implicit = true })
		err = NewEmail(relayConfig(ri, x509.NewCertPool(), SMTPImplicit)).Deliver(context.Background(), emailDestination(), emailMessage(1))
		if c := deliveryClass(t, err); c != "smtp_tls" {
			t.Fatalf("implicit: class %q, want smtp_tls", c)
		}
	})
}

// TestEmailImplicit: implicit TLS speaks TLS from the first byte; a plain relay on that port is a TLS failure.
func TestEmailImplicit(t *testing.T) {
	cert, pool := testCert(t)
	r := startRelay(t, cert, func(r *fakeRelay) { r.implicit, r.auth = true, "PLAIN" })
	cfg := relayConfig(r, pool, SMTPImplicit)
	cfg.Username, cfg.Password = "relay-user", testPassword
	if err := NewEmail(cfg).Deliver(context.Background(), emailDestination(), emailMessage(1)); err != nil {
		t.Fatalf("deliver: %v", err)
	}
	if _, creds, msgs := r.snapshot(); len(msgs) != 1 || len(creds) != 1 || r.sawCommand("STARTTLS") {
		t.Fatalf("%d messages, %d logins", len(msgs), len(creds))
	}
	plain := startRelay(t, cert, nil)
	err := NewEmail(relayConfig(plain, pool, SMTPImplicit)).Deliver(context.Background(), emailDestination(), emailMessage(1))
	if c := deliveryClass(t, err); c != "smtp_tls" {
		t.Fatalf("plain relay: class %q, want smtp_tls", c)
	}
}

// TestEmailMechanisms: LOGIN when the relay offers LOGIN but not PLAIN (Microsoft 365), CRAM-MD5 as the last
// fallback, PLAIN first.
func TestEmailMechanisms(t *testing.T) {
	cert, pool := testCert(t)
	for _, tc := range []struct{ advertised, want string }{
		{"LOGIN", "relay-user\x00" + testPassword},
		{"LOGIN PLAIN", "relay-user\x00" + testPassword},
		{"CRAM-MD5", ""},
	} {
		r := startRelay(t, cert, func(r *fakeRelay) { r.startTLS, r.auth = true, tc.advertised })
		cfg := relayConfig(r, pool, SMTPStartTLS)
		cfg.Username, cfg.Password = "relay-user", testPassword
		if err := NewEmail(cfg).Deliver(context.Background(), emailDestination(), emailMessage(1)); err != nil {
			t.Fatalf("%s: %v", tc.advertised, err)
		}
		cmds, creds, _ := r.snapshot()
		var auth string
		for _, c := range cmds {
			if strings.HasPrefix(c, "AUTH ") {
				auth = strings.Fields(c)[1]
			}
		}
		wantMech := strings.Fields(tc.advertised)[0]
		if tc.advertised == "LOGIN PLAIN" {
			wantMech = "PLAIN"
		}
		if auth != wantMech || len(creds) != 1 {
			t.Fatalf("%s: mechanism %q, want %q", tc.advertised, auth, wantMech)
		}
		if tc.want != "" && creds[0] != tc.want {
			t.Fatalf("%s: credentials %q", tc.advertised, creds[0])
		}
		if tc.advertised == "CRAM-MD5" && !strings.HasPrefix(creds[0], "relay-user ") {
			t.Fatalf("CRAM-MD5 answer %q", creds[0])
		}
	}
}

// TestEmailFailureClasses: auth failure, a refused recipient, timeouts and a refused connection have their classes,
// and no class or error text carries an address or the password.
func TestEmailFailureClasses(t *testing.T) {
	cert, pool := testCert(t)

	r := startRelay(t, cert, func(r *fakeRelay) { r.startTLS, r.auth, r.authFail = true, "PLAIN", true })
	cfg := relayConfig(r, pool, SMTPStartTLS)
	cfg.Username, cfg.Password = "relay-user", testPassword
	if c := deliveryClass(t, NewEmail(cfg).Deliver(context.Background(), emailDestination(), emailMessage(1))); c != "smtp_auth" {
		t.Errorf("auth failure: class %q", c)
	}

	r = startRelay(t, cert, func(r *fakeRelay) { r.startTLS, r.rcptCode = true, 550 })
	if c := deliveryClass(t, NewEmail(relayConfig(r, pool, SMTPStartTLS)).Deliver(context.Background(), emailDestination(), emailMessage(1))); c != "smtp_550" {
		t.Errorf("refused recipient: class %q", c)
	}
	if r.sawCommand("DATA") {
		t.Error("DATA after a refused recipient")
	}

	r = startRelay(t, cert, func(r *fakeRelay) { r.startTLS, r.rcptCode = true, 451 })
	if c := deliveryClass(t, NewEmail(relayConfig(r, pool, SMTPStartTLS)).Deliver(context.Background(), emailDestination(), emailMessage(1))); c != "smtp_451" {
		t.Errorf("deferred recipient: class %q", c)
	}

	for _, mode := range []string{SMTPStartTLS, SMTPImplicit} {
		r = startRelay(t, cert, func(r *fakeRelay) { r.silent = true })
		cfg = relayConfig(r, pool, mode)
		cfg.Timeout = 300 * time.Millisecond
		start := time.Now()
		if c := deliveryClass(t, NewEmail(cfg).Deliver(context.Background(), emailDestination(), emailMessage(1))); c != "smtp_timeout" {
			t.Errorf("%s: silent relay: class %q", mode, c)
		}
		if time.Since(start) > 3*time.Second {
			t.Errorf("%s: the timeout took %s", mode, time.Since(start))
		}
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	cfg = EmailConfig{Host: "127.0.0.1", Port: port, TLS: SMTPStartTLS, From: mail.Address{Address: "p@example.com"},
		Timeout: time.Second, RootCAs: pool}
	if c := deliveryClass(t, NewEmail(cfg).Deliver(context.Background(), emailDestination(), emailMessage(1))); c != "smtp_dial" {
		t.Errorf("refused connection: class %q", c)
	}
}

// decoded splits a rendered message into its headers and the decoded body.
func decoded(t *testing.T, raw []byte) (mail.Header, string) {
	t.Helper()
	msg, err := mail.ReadMessage(strings.NewReader(string(raw)))
	if err != nil {
		t.Fatalf("message: %v", err)
	}
	body, err := io.ReadAll(quotedprintable.NewReader(msg.Body))
	if err != nil {
		t.Fatalf("body: %v", err)
	}
	return msg.Header, strings.ReplaceAll(string(body), "\r\n", "\n")
}

// TestEmailRendering: plan M9 decision 28. Headers, at most 50 events in detail with a code summary of the rest,
// parameters only with include_params, pseudonymized actors as they come from the engine.
func TestEmailRendering(t *testing.T) {
	from := mail.Address{Name: "Paddock", Address: "paddock@example.com"}
	d := emailDestination()
	m := emailMessage(60)
	h, body := decoded(t, renderEmail(from, d, m))
	for name, want := range map[string]string{
		"Auto-Submitted": "auto-generated", "X-Paddock-Forward-Seq": "7-66", "X-Paddock-Delivery": m.DeliveryID,
		"X-Paddock-Destination": m.DestinationID, "Subject": "[Paddock] Acme Corp: 60 security events",
		"To": "<a@example.org>, <b@example.org>", "From": `"Paddock" <paddock@example.com>`,
		"Message-Id": "<" + m.DeliveryID + "@example.com>", "Content-Type": "text/plain; charset=utf-8",
	} {
		if got := h.Get(name); got != want {
			t.Errorf("%s: %q, want %q", name, got, want)
		}
	}
	if date, err := h.Date(); err != nil || !date.Equal(m.SentAt) {
		t.Errorf("Date %q: %v", h.Get("Date"), err)
	}
	if n := strings.Count(body, "  actor: "); n != MaxDetailedEvents {
		t.Errorf("%d detailed blocks, want 50", n)
	}
	if !strings.Contains(body, "host-49\n") || strings.Contains(body, "host-50\n") {
		t.Error("the detailed blocks are not the first 50 events")
	}
	for _, want := range []string{
		"  admin.login: 5\n", "  device.tamper_sudoers_d_file: 5\n", "and 10 more events; see the portal.",
		"2026-10-31T11:00:00Z  device.tamper_sudoers_d_file  success\n  device: host-0\n  actor: alice\n",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("body lacks %q:\n%s", want, body)
		}
	}
	if strings.Contains(body, "params:") || strings.Contains(body, "evil-") {
		t.Error("parameters shown without include_params")
	}

	t.Run("include_params and links", func(t *testing.T) {
		d := emailDestination()
		d.IncludeParams = true
		m := emailMessage(1)
		m.Events[0].Links = &outbound.Links{Device: "https://admin.example/devices/dev-0"}
		_, body := decoded(t, renderEmail(from, d, m))
		if !strings.Contains(body, "  params:\n    file: evil-0\n") || !strings.Contains(body, "  link: https://admin.example/devices/dev-0\n") ||
			strings.Contains(body, "more events") {
			t.Errorf("body:\n%s", body)
		}
	})

	t.Run("pseudonymized actor", func(t *testing.T) {
		m := emailMessage(1)
		m.Events[0].Event = outbound.Pseudonymize([]byte("0123456789abcdef0123456789abcdef"), m.Events[0].Event)
		_, body := decoded(t, renderEmail(from, d, m))
		if !regexp.MustCompile(`(?m)^  actor: u_[0-9a-f]{24}$`).MatchString(body) || strings.Contains(body, "alice") {
			t.Errorf("body:\n%s", body)
		}
	})

	t.Run("no value adds a header or a line", func(t *testing.T) {
		d := emailDestination()
		d.ScopeName = "Evil\r\nBcc: x@example.net"
		m := emailMessage(1)
		m.Events[0].Event.Actor.Display = "mallory\r\n.\r\nMAIL FROM:<x@example.net>"
		h, body := decoded(t, renderEmail(from, d, m))
		if h.Get("Bcc") != "" || strings.Contains(body, "\n.\n") || !strings.Contains(body, "actor: mallory  .  MAIL") {
			t.Errorf("headers %v body:\n%s", h, body)
		}
	})

	t.Run("test message", func(t *testing.T) {
		m := outbound.Message{Kind: outbound.KindTest, DeliveryID: uuid.NewString(), DestinationID: d.ID.String(),
			SentAt: time.Now(), Events: []outbound.MessageEvent{}}
		h, body := decoded(t, renderEmail(from, d, m))
		if h.Get("Subject") != "[Paddock] Acme Corp: test notification" || h.Get("X-Paddock-Forward-Seq") != "" ||
			!strings.Contains(body, "Paddock test notification") {
			t.Errorf("test message %v:\n%s", h, body)
		}
	})
}

// TestEmailMessageOnTheWire: the relay receives the rendered message intact (dot-stuffing, line endings).
func TestEmailMessageOnTheWire(t *testing.T) {
	cert, pool := testCert(t)
	r := startRelay(t, cert, func(r *fakeRelay) { r.startTLS = true })
	m := emailMessage(3)
	if err := NewEmail(relayConfig(r, pool, SMTPStartTLS)).Deliver(context.Background(), emailDestination(), m); err != nil {
		t.Fatal(err)
	}
	_, _, msgs := r.snapshot()
	if len(msgs) != 1 {
		t.Fatalf("%d messages", len(msgs))
	}
	h, body := decoded(t, []byte(msgs[0]))
	if h.Get("X-Paddock-Forward-Seq") != "7-9" || strings.Count(body, "  actor: ") != 3 {
		t.Fatalf("received %v:\n%s", h, body)
	}
}
