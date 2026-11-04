package notifier

import (
	"context"
	"net"
	"syscall"
	"testing"
	"time"
)

// newSmallWindowSink is a syslog sink whose connections have a minimal receive buffer, so a receiver that stops
// reading leaves most of a batch unacknowledged in the client's send queue instead of in its own kernel buffer.
func newSmallWindowSink(t *testing.T, pki syslogPKI) *syslogSink {
	t.Helper()
	lc := net.ListenConfig{Control: func(_, _ string, c syscall.RawConn) error {
		var serr error
		if err := c.Control(func(fd uintptr) {
			serr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF, 1)
		}); err != nil {
			return err
		}
		return serr
	}}
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	return serveSyslogSink(t, pki.cert, ln)
}

func ackTestSyslog(pki syslogPKI, port int) (*Syslog, Destination) {
	s := NewSyslog(true)
	s.resolver = dnsResolver{"syslog.example.test": loopback}
	s.closeWait = 100 * time.Millisecond
	return s, Destination{SyslogHost: "syslog.example.test", SyslogPort: port, SyslogCAPEM: pki.caPEM}
}

// TestSyslogBareFINMidBatch: a receiver that half-closes after the first message (a bare FIN, which crypto/tls reads
// as EOF) and stops reading fails the delivery, because the rest of the batch is never acknowledged; without the
// acknowledgement check the FIN alone would pass for a delivery long before the receiver resets the connection.
func TestSyslogBareFINMidBatch(t *testing.T) {
	pki := newSyslogPKI(t)
	sink := newSmallWindowSink(t, pki)
	sink.mu.Lock()
	sink.finAfter, sink.finHold = 1, 300*time.Millisecond
	sink.mu.Unlock()
	s, d := ackTestSyslog(pki, sink.port)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if got := ErrorClass(s.Deliver(ctx, d, eventsMessage(20))); got != "io" {
		t.Errorf("class %q, want io", got)
	}
	if frames := sink.wait(1); len(frames) != 1 {
		t.Errorf("the sink took %d messages, want 1", len(frames))
	}
}

// TestSyslogCloseNotifyMidBatch: a receiver whose kernel acknowledged the whole batch (it fits the receive window, so
// the acknowledgement check passes) but which read only the first message and then closed TLS (close_notify, followed
// by an RST for the unread rest) fails the delivery.
func TestSyslogCloseNotifyMidBatch(t *testing.T) {
	pki := newSyslogPKI(t)
	sink := newSyslogSink(t, pki.cert)
	sink.mu.Lock()
	sink.closeAfter, sink.closeDelay = 1, 50*time.Millisecond
	sink.mu.Unlock()
	s, d := ackTestSyslog(pki, sink.port)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if got := ErrorClass(s.Deliver(ctx, d, eventsMessage(20))); got != "io" {
		t.Errorf("class %q, want io", got)
	}
	if frames := sink.wait(1); len(frames) != 1 {
		t.Errorf("the sink took %d messages, want 1", len(frames))
	}
}

// TestSyslogStalledReceiver: a receiver that stops acknowledging after the first message while the batch still fits
// the client's send buffer (every Write succeeds, the close wait stays quiet) fails with timeout at the deadline.
func TestSyslogStalledReceiver(t *testing.T) {
	pki := newSyslogPKI(t)
	sink := newSmallWindowSink(t, pki)
	sink.mu.Lock()
	sink.stall, sink.stallAfter = true, 1
	sink.mu.Unlock()
	s, d := ackTestSyslog(pki, sink.port)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if got := ErrorClass(s.Deliver(ctx, d, eventsMessage(20))); got != "timeout" {
		t.Errorf("class %q, want timeout", got)
	}
}

// TestSyslogReceiverNeverReads: a receiver that never reads blocks the writes of a large batch until the deadline.
func TestSyslogReceiverNeverReads(t *testing.T) {
	pki := newSyslogPKI(t)
	sink := newSmallWindowSink(t, pki)
	sink.mu.Lock()
	sink.stall = true
	sink.mu.Unlock()
	s, d := ackTestSyslog(pki, sink.port)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if got := ErrorClass(s.Deliver(ctx, d, eventsMessage(5000))); got != "timeout" {
		t.Errorf("class %q, want timeout", got)
	}
}
