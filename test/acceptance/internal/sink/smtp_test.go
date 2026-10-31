package sink

import (
	"net/smtp"
	"strings"
	"testing"
)

// TestSMTPSink: a standard-library client delivers one message to two recipients through the sink in plain text.
func TestSMTPSink(t *testing.T) {
	s, err := ListenSMTP("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	msg := "Subject: hi\r\n\r\n.leading dot\r\nbody\r\n"
	if err := smtp.SendMail(s.Addr().String(), nil, "p@example.com", []string{"a@example.org", "b@example.org"}, []byte(msg)); err != nil {
		t.Fatal(err)
	}
	got := s.Mails()
	if len(got) != 1 || got[0].From != "p@example.com" || len(got[0].To) != 2 || got[0].To[1] != "b@example.org" ||
		!strings.Contains(string(got[0].Data), "\n.leading dot\n") {
		t.Fatalf("received %+v", got)
	}
}
