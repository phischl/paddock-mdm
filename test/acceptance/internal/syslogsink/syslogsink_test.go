package syslogsink

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"strings"
	"testing"
	"time"
)

func frame(content string) string { return fmt.Sprintf("%d %s", len(content), content) }

func dial(t *testing.T, s *Sink) (*tls.Conn, error) {
	t.Helper()
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(s.CAPEM())) {
		t.Fatal("the CA PEM holds no certificate")
	}
	return tls.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", s.Port()), &tls.Config{RootCAs: pool, ServerName: s.ServerName(), MinVersion: tls.VersionTLS12})
}

func TestParse(t *testing.T) {
	m, err := Parse([]byte("<132>1 2026-11-06T10:00:00Z host paddock acme device.tamper_sudoers_d_file - \xef\xbb\xbf{\"a\":1}"))
	if err != nil {
		t.Fatal(err)
	}
	if m.PRI != 132 || m.Hostname != "host" || m.AppName != "paddock" || m.ProcID != "acme" ||
		m.MsgID != "device.tamper_sudoers_d_file" || string(m.Body) != `{"a":1}` {
		t.Fatalf("parsed %+v", m)
	}
	for name, in := range map[string]string{
		"no PRI":         "1 x",
		"no BOM":         "<132>1 t h paddock p m - {}",
		"structured":     "<132>1 t h paddock p m [x] \xef\xbb\xbf{}",
		"PRI too large":  "<999>1 t h paddock p m - \xef\xbb\xbf{}",
		"short header":   "<132>1 t h",
		"unterminated":   "<132",
		"another format": "<132>2 t h paddock p m - \xef\xbb\xbf{}",
		"MSGID too long": "<132>1 t h paddock p " + strings.Repeat("m", 33) + " - \xef\xbb\xbf{}",
		"APP too long":   "<132>1 t h " + strings.Repeat("a", 49) + " p m - \xef\xbb\xbf{}",
	} {
		if _, err := Parse([]byte(in)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestSinkReceivesFramesAndSurvivesRestart(t *testing.T) {
	s := Start(t)
	msg := func(id string) string {
		return "<133>1 2026-11-06T10:00:00Z h paddock o " + id + " - \xef\xbb\xbf{\"id\":\"" + id + "\"}"
	}
	c, err := dial(t, s)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write([]byte(frame(msg("a")) + frame(msg("b")))); err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	got := s.Wait(t, 5*time.Second, "two messages", func(m []Message) bool { return len(m) == 2 })
	if got[0].MsgID != "a" || got[1].MsgID != "b" || !strings.Contains(string(got[1].Body), `"b"`) || len(s.Malformed()) != 0 {
		t.Fatalf("messages %+v malformed %v", got, s.Malformed())
	}

	port := s.Port()
	s.Stop()
	if c, err := dial(t, s); err == nil {
		_ = c.Close()
		t.Fatal("a stopped sink accepted a connection")
	}
	s.Restart(t)
	if s.Port() != port {
		t.Fatalf("port %d after the restart, want %d", s.Port(), port)
	}
	c, err = dial(t, s)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write([]byte(frame(msg("c")))); err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	s.Wait(t, 5*time.Second, "the message after the restart", func(m []Message) bool { return len(m) == 3 })
}

func TestSinkRecordsMalformedFraming(t *testing.T) {
	s := Start(t)
	c, err := dial(t, s)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write([]byte("not-a-number rest")); err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	for deadline := time.Now().Add(5 * time.Second); len(s.Malformed()) == 0; time.Sleep(50 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("malformed framing not recorded")
		}
	}
}
