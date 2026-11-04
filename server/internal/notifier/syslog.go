package notifier

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"os"
	"strconv"
	"time"

	"github.com/phischl/paddock-mdm/server/internal/domain/outbound"
)

// syslogCloseWait bounds the wait for the receiver's answer to the client's close: an RST from a receiver that
// dropped the connection mid-batch arrives within a round trip, and a receiver that keeps the connection open must
// not hold every delivery for the full 30 s.
const syslogCloseWait = 5 * time.Second

// Syslog delivers RFC 5424 messages over TLS (RFC 5425) with octet-counting framing (plan M12 decision 18, ADR 0031
// amendment 2026-11-04 items 1 and 2): one connection per delivery to the address the outbound policy checked, TLS 1.2
// or newer, the server certificate verified against the destination's CA bundle or the system roots.
type Syslog struct {
	allowPrivate bool
	// Hostname is the HOSTNAME of every message: the portal host of PADDOCK_PUBLIC_ADMIN_URL.
	Hostname string
	// resolver resolves the receiver's name; nil uses net.DefaultResolver (tests pin it).
	resolver outbound.Resolver
	// closeWait replaces syslogCloseWait when set (tests shorten it).
	closeWait time.Duration
}

// NewSyslog creates the syslog transport; allowPrivate is the development-only PADDOCK_OUTBOUND_DEV_ALLOW_PRIVATE.
func NewSyslog(allowPrivate bool) *Syslog {
	return &Syslog{allowPrivate: allowPrivate}
}

// Deliver writes m to the destination's receiver: one message per event for kind events, one control message
// otherwise. Every message must be written, the receiver must acknowledge every byte at TCP level and must not reset
// the connection; anything less fails the whole delivery, which the engine retries under the same forward sequence
// numbers (at-least-once). The error is a *DeliveryError of class dns, dial, tls, timeout, denied_address or io.
func (s *Syslog) Deliver(ctx context.Context, d Destination, m outbound.Message) error {
	frames := s.frames(m)
	ctx, cancel := context.WithTimeout(ctx, outbound.TotalTimeout)
	defer cancel()
	conn, err := s.dial(ctx, d)
	if err != nil {
		var derr *DeliveryError
		if errors.As(err, &derr) {
			return derr
		}
		return &DeliveryError{Class: transportClass(err)}
	}
	defer func() { _ = conn.Close() }()
	deadline, _ := ctx.Deadline()
	if err := conn.SetDeadline(deadline); err != nil {
		return &DeliveryError{Class: "io"}
	}
	for _, f := range frames {
		if _, err := conn.Write(f); err != nil {
			return &DeliveryError{Class: ioClass(err)}
		}
	}
	return s.finish(ctx, conn, deadline)
}

func (s *Syslog) frames(m outbound.Message) [][]byte {
	if m.Kind != outbound.KindEvents {
		return [][]byte{outbound.FormatSyslogControl(m, s.Hostname)}
	}
	out := make([][]byte, len(m.Events))
	for i, ev := range m.Events {
		out[i] = outbound.FormatSyslog(m, ev, s.Hostname)
	}
	return out
}

// dial connects to the checked address of the destination's host and completes the TLS handshake within the connect
// timeout. The server name is syslog_server_name or the host; with a CA bundle only that bundle is trusted.
func (s *Syslog) dial(ctx context.Context, d Destination) (*tls.Conn, error) {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: d.SyslogHost, Renegotiation: tls.RenegotiateNever}
	if d.SyslogServerName != "" {
		cfg.ServerName = d.SyslogServerName
	}
	if d.SyslogCAPEM != "" {
		certs, err := outbound.ParseCAPEM(d.SyslogCAPEM)
		if err != nil {
			return nil, &DeliveryError{Class: "tls"}
		}
		pool := x509.NewCertPool()
		for _, c := range certs {
			pool.AddCert(c)
		}
		cfg.RootCAs = pool
	}
	port := d.SyslogPort
	if port == 0 {
		port = outbound.DefaultSyslogPort
	}
	connectCtx, cancel := context.WithTimeout(ctx, outbound.ConnectTimeout)
	defer cancel()
	policy := outbound.Policy{AllowPrivate: s.allowPrivate, Resolver: s.resolver}
	raw, err := policy.DialContext(connectCtx, "tcp", net.JoinHostPort(d.SyslogHost, strconv.Itoa(port)))
	if err != nil {
		return nil, err
	}
	conn := tls.Client(raw, cfg)
	if err := conn.HandshakeContext(connectCtx); err != nil {
		_ = raw.Close()
		// A received alert (for example protocol_version from a TLS 1.1 server) is a *net.OpError that
		// transportClass would report as dial; the connection already stands, so anything but a timeout is tls.
		if class := transportClass(err); class == "timeout" {
			return nil, &DeliveryError{Class: class}
		}
		return nil, &DeliveryError{Class: "tls"}
	}
	return conn, nil
}

// finish sends the TLS close, waits until the receiver acknowledged every sent byte at TCP level and then waits for
// it to close in turn: EOF or a quiet receiver until the wait ends is success, a reset or another error means the
// receiver did not take every message.
func (s *Syslog) finish(ctx context.Context, conn *tls.Conn, deadline time.Time) error {
	if err := conn.CloseWrite(); err != nil {
		return &DeliveryError{Class: ioClass(err)}
	}
	// A completed Write only fills the local send buffer: a receiver that closed cleanly (crypto/tls reports a bare
	// FIN as EOF) or a path that went silent after the handshake would otherwise pass for a delivery (PDK-751 review).
	if err := awaitAcked(ctx, conn.NetConn()); err != nil {
		return err
	}
	closeWait := syslogCloseWait
	if s.closeWait > 0 {
		closeWait = s.closeWait
	}
	wait := time.Now().Add(closeWait)
	if wait.After(deadline) {
		wait = deadline
	}
	if err := conn.SetReadDeadline(wait); err != nil {
		return &DeliveryError{Class: "io"}
	}
	_, err := io.Copy(io.Discard, conn)
	if err == nil {
		// A receiver that closes with part of the batch still unread in its socket sends close_notify followed by an
		// RST instead of a FIN (Linux tcp_close); only reading on until the FIN tells it from a receiver that read
		// everything (PDK-751 review 2).
		_, err = io.Copy(io.Discard, conn.NetConn())
	}
	switch {
	case err == nil, errors.Is(err, os.ErrDeadlineExceeded) && wait.Before(deadline):
		return nil
	default:
		return &DeliveryError{Class: ioClass(err)}
	}
}

// ackPollInterval is how often awaitAcked looks at the send queue; loopback and LAN receivers acknowledge well within
// it, so a delivery costs at most one interval more than the round trip.
const ackPollInterval = 10 * time.Millisecond

// awaitAcked polls the sent but unacknowledged bytes of raw until they reach 0 (nil), the socket reports an error such
// as a reset (io) or ctx ends (timeout).
func awaitAcked(ctx context.Context, raw net.Conn) error {
	t := time.NewTicker(ackPollInterval)
	defer t.Stop()
	for {
		n, err := unackedBytes(raw)
		if err != nil {
			return &DeliveryError{Class: "io"}
		}
		if n == 0 {
			return nil
		}
		select {
		case <-ctx.Done():
			return &DeliveryError{Class: "timeout"}
		case <-t.C:
		}
	}
}

// ioClass is the class of an error after the handshake: timeout or io.
func ioClass(err error) string {
	var netErr net.Error
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) ||
		(errors.As(err, &netErr) && netErr.Timeout()) {
		return "timeout"
	}
	return "io"
}
