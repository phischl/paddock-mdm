package sink

import (
	"fmt"
	"net"
	"net/textproto"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// DefaultSMTPPort is where the development stack's notifier delivers e-mail (compose.dev.yaml PADDOCK_SMTP_PORT);
// PADDOCK_ACCEPTANCE_SMTP_PORT moves both, for a second stack on the same host.
const DefaultSMTPPort = 2525

// SMTPPort is the port the development stack's notifier sends to.
func SMTPPort() int {
	if p, err := strconv.Atoi(os.Getenv("PADDOCK_ACCEPTANCE_SMTP_PORT")); err == nil && p > 0 {
		return p
	}
	return DefaultSMTPPort
}

// Mail is one received message.
type Mail struct {
	From     string
	To       []string
	Data     []byte
	Received time.Time
}

// SMTPSink is a minimal RFC 5321 receiver without TLS and without authentication (plan M9 gate N6): it accepts every
// message and records it. The stack's notifier may send without TLS only in development (PADDOCK_SMTP_TLS=none).
type SMTPSink struct {
	ln net.Listener
	wg sync.WaitGroup

	mu     sync.Mutex
	mails  []Mail
	open   map[net.Conn]struct{}
	closed bool
}

// ListenSMTP starts a receiver on addr.
func ListenSMTP(addr string) (*SMTPSink, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("smtp sink: listen %s: %w", addr, err)
	}
	s := &SMTPSink{ln: ln, open: map[net.Conn]struct{}{}}
	s.wg.Add(1)
	go s.accept()
	return s, nil
}

// StartSMTP listens on SMTPPort of every interface of the test host (the stack's containers arrive through the
// Docker bridge gateway) and stops when the test ends.
func StartSMTP(t testing.TB) *SMTPSink {
	t.Helper()
	s, err := ListenSMTP(":" + strconv.Itoa(SMTPPort()))
	if err != nil {
		t.Fatalf("%v (is another acceptance run using the port?)", err)
	}
	t.Cleanup(s.Close)
	return s
}

// Addr is the address the receiver listens on.
func (s *SMTPSink) Addr() net.Addr { return s.ln.Addr() }

// Close stops the receiver and drops the connections in progress.
func (s *SMTPSink) Close() {
	_ = s.ln.Close()
	s.mu.Lock()
	s.closed = true
	for c := range s.open {
		_ = c.Close()
	}
	s.mu.Unlock()
	s.wg.Wait()
}

func (s *SMTPSink) accept() {
	defer s.wg.Done()
	var conns sync.WaitGroup
	defer conns.Wait()
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			_ = conn.Close()
			return
		}
		s.open[conn] = struct{}{}
		s.mu.Unlock()
		conns.Add(1)
		go func() {
			defer conns.Done()
			defer func() {
				s.mu.Lock()
				delete(s.open, conn)
				s.mu.Unlock()
				_ = conn.Close()
			}()
			_ = conn.SetDeadline(time.Now().Add(time.Minute))
			s.serve(textproto.NewConn(conn))
		}()
	}
}

// serve speaks the server side of one session: EHLO/HELO, MAIL, RCPT, DATA, RSET, NOOP, QUIT.
func (s *SMTPSink) serve(c *textproto.Conn) {
	reply := func(line string) error { return c.PrintfLine("%s", line) }
	if reply("220 paddock acceptance sink ESMTP") != nil {
		return
	}
	var cur Mail
	for {
		line, err := c.ReadLine()
		if err != nil {
			return
		}
		verb, arg, _ := strings.Cut(line, " ")
		switch strings.ToUpper(verb) {
		case "EHLO":
			err = reply("250-sink")
			if err == nil {
				err = reply("250 8BITMIME")
			}
		case "HELO":
			err = reply("250 sink")
		case "MAIL":
			cur = Mail{From: path(arg)}
			err = reply("250 2.1.0 ok")
		case "RCPT":
			cur.To = append(cur.To, path(arg))
			err = reply("250 2.1.5 ok")
		case "DATA":
			if len(cur.To) == 0 {
				err = reply("503 5.5.1 no recipients")
				break
			}
			if err = reply("354 end with <CRLF>.<CRLF>"); err != nil {
				return
			}
			var data []byte
			if data, err = c.ReadDotBytes(); err != nil {
				return
			}
			cur.Data, cur.Received = data, time.Now()
			s.mu.Lock()
			s.mails = append(s.mails, cur)
			s.mu.Unlock()
			cur = Mail{}
			err = reply("250 2.0.0 queued")
		case "RSET":
			cur = Mail{}
			err = reply("250 2.0.0 ok")
		case "NOOP":
			err = reply("250 2.0.0 ok")
		case "QUIT":
			_ = reply("221 2.0.0 bye")
			return
		default:
			err = reply("502 5.5.2 not implemented")
		}
		if err != nil {
			return
		}
	}
}

// path extracts the address of "FROM:<a@b> SIZE=1" or "TO:<a@b>".
func path(arg string) string {
	_, v, _ := strings.Cut(arg, ":")
	v, _, _ = strings.Cut(strings.TrimSpace(v), " ")
	return strings.Trim(v, "<>")
}

// Mails returns a copy of the messages received so far.
func (s *SMTPSink) Mails() []Mail {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Mail(nil), s.mails...)
}

// WaitMail polls until cond holds for the messages received so far and returns them; it fails the test after timeout.
func (s *SMTPSink) WaitMail(t testing.TB, timeout time.Duration, what string, cond func([]Mail) bool) []Mail {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		got := s.Mails()
		if cond(got) {
			return got
		}
		if time.Now().After(deadline) {
			t.Fatalf("smtp sink: %s not received within %s (%d messages)", what, timeout, len(got))
		}
		time.Sleep(250 * time.Millisecond)
	}
}
