package notifier

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"mime/quotedprintable"
	"net"
	"net/mail"
	"net/smtp"
	"net/textproto"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
	"github.com/phischl/paddock-mdm/server/internal/domain/outbound"
)

// TLS modes of PADDOCK_SMTP_TLS (plan M9 decision 27).
const (
	SMTPStartTLS = "starttls"
	SMTPImplicit = "implicit"
	SMTPNone     = "none"
)

// MaxDetailedEvents is how many events of a batch an e-mail shows in detail; the rest is summarized per code (plan
// M9 decision 28).
const MaxDetailedEvents = 50

// EmailConfig is the operator's SMTP relay (plan M9 decision 27).
type EmailConfig struct {
	Host string
	Port int
	// TLS is SMTPStartTLS, SMTPImplicit or SMTPNone; the configuration admits SMTPNone only in development.
	TLS      string
	Username string
	Password string
	From     mail.Address
	Timeout  time.Duration
	// RootCAs verifies the relay's certificate; nil means the system roots.
	RootCAs *x509.CertPool
}

// Email sends one plain-text message per delivery through the operator's relay with the standard library only
// (ADR 0031, plan M9 decisions 27–29). TLS is mandatory outside development, the certificate is always verified,
// and credentials are only ever sent over TLS.
type Email struct {
	cfg EmailConfig
}

// NewEmail creates the e-mail transport.
func NewEmail(cfg EmailConfig) *Email { return &Email{cfg: cfg} }

// Deliver sends m to every recipient of d in one message; any refused recipient fails the delivery. The error is a
// *DeliveryError whose class (smtp_dial, smtp_tls, smtp_auth, smtp_timeout, smtp_<code>) is all it carries: never an
// address, a server answer or a credential.
func (e *Email) Deliver(ctx context.Context, d Destination, m outbound.Message) error {
	if len(d.Recipients) == 0 {
		return fmt.Errorf("email: destination %s has no recipients", d.ID)
	}
	body := renderEmail(e.cfg.From, d, m)
	ctx, cancel := context.WithTimeout(ctx, e.cfg.Timeout)
	defer cancel()
	c, err := e.dial(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()
	if err := e.secure(ctx, c); err != nil {
		return err
	}
	if err := e.authenticate(ctx, c); err != nil {
		return err
	}
	if err := c.Mail(e.cfg.From.Address); err != nil {
		return classify(ctx, err, "")
	}
	for _, r := range d.Recipients {
		if err := c.Rcpt(r); err != nil {
			return classify(ctx, err, "")
		}
	}
	w, err := c.Data()
	if err != nil {
		return classify(ctx, err, "")
	}
	if _, err := w.Write(body); err != nil {
		return classify(ctx, err, "")
	}
	if err := w.Close(); err != nil {
		return classify(ctx, err, "")
	}
	// The relay accepted the message with the answer to the final dot; a failing QUIT does not undo that.
	_ = c.Quit()
	return nil
}

func (e *Email) tlsConfig() *tls.Config {
	return &tls.Config{ServerName: e.cfg.Host, MinVersion: tls.VersionTLS12, RootCAs: e.cfg.RootCAs}
}

// dial connects and reads the greeting. The relay is the operator's own configuration, not an organization's input,
// so the outbound address policy of the webhooks does not apply.
func (e *Email) dial(ctx context.Context) (*smtp.Client, error) {
	addr := net.JoinHostPort(e.cfg.Host, strconv.Itoa(e.cfg.Port))
	nd := &net.Dialer{}
	var conn net.Conn
	var err error
	if e.cfg.TLS == SMTPImplicit {
		conn, err = (&tls.Dialer{NetDialer: nd, Config: e.tlsConfig()}).DialContext(ctx, "tcp", addr)
	} else {
		conn, err = nd.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		switch transportClass(err) {
		case "tls":
			return nil, &DeliveryError{Class: "smtp_tls"}
		case "timeout":
			return nil, &DeliveryError{Class: "smtp_timeout"}
		default:
			return nil, &DeliveryError{Class: "smtp_dial"}
		}
	}
	// net/smtp takes no context: the deadline bounds every read and write, and cancellation closes the connection.
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	c, err := smtp.NewClient(conn, e.cfg.Host)
	if err != nil {
		stop()
		_ = conn.Close()
		return nil, classify(ctx, err, "")
	}
	if err := c.Hello("localhost"); err != nil {
		stop()
		_ = c.Close()
		return nil, classify(ctx, err, "")
	}
	return c, nil
}

// secure upgrades the connection with STARTTLS; a relay that does not offer it is refused, never used in plain text.
func (e *Email) secure(ctx context.Context, c *smtp.Client) error {
	if e.cfg.TLS != SMTPStartTLS {
		return nil
	}
	if ok, _ := c.Extension("STARTTLS"); !ok {
		return &DeliveryError{Class: "smtp_tls"}
	}
	if err := c.StartTLS(e.tlsConfig()); err != nil {
		return classify(ctx, err, "smtp_tls")
	}
	return nil
}

// authenticate logs in when a username is configured: PLAIN, else LOGIN, else CRAM-MD5 as the relay advertises them.
// Credentials never travel over a connection without TLS, whatever the mechanism.
func (e *Email) authenticate(ctx context.Context, c *smtp.Client) error {
	if e.cfg.Username == "" {
		return nil
	}
	if _, ok := c.TLSConnectionState(); !ok {
		return &DeliveryError{Class: "smtp_tls"}
	}
	ok, advertised := c.Extension("AUTH")
	if !ok {
		return &DeliveryError{Class: "smtp_auth"}
	}
	mechs := strings.Fields(strings.ToUpper(advertised))
	var a smtp.Auth
	switch {
	case slices.Contains(mechs, "PLAIN"):
		a = smtp.PlainAuth("", e.cfg.Username, e.cfg.Password, e.cfg.Host)
	case slices.Contains(mechs, "LOGIN"):
		a = &loginAuth{username: e.cfg.Username, password: e.cfg.Password, host: e.cfg.Host}
	case slices.Contains(mechs, "CRAM-MD5"):
		a = smtp.CRAMMD5Auth(e.cfg.Username, e.cfg.Password)
	default:
		return &DeliveryError{Class: "smtp_auth"}
	}
	if err := c.Auth(a); err != nil {
		return classify(ctx, err, "smtp_auth")
	}
	return nil
}

// classify maps an SMTP error to its class: a timeout is smtp_timeout, otherwise phase when set, else the relay's
// 4xx/5xx reply code, else smtp_dial (the connection broke).
func classify(ctx context.Context, err error, phase string) *DeliveryError {
	var netErr net.Error
	if ctx.Err() != nil || errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &netErr) && netErr.Timeout()) {
		return &DeliveryError{Class: "smtp_timeout"}
	}
	if phase != "" {
		return &DeliveryError{Class: phase}
	}
	var tp *textproto.Error
	if errors.As(err, &tp) && tp.Code >= 400 && tp.Code < 600 {
		return &DeliveryError{Class: "smtp_" + strconv.Itoa(tp.Code)}
	}
	return &DeliveryError{Class: "smtp_dial"}
}

// loginAuth is the LOGIN mechanism, which net/smtp lacks and relays such as Microsoft 365 require (plan M9
// amendment B6.1). Like smtp.PlainAuth it refuses a connection without TLS.
type loginAuth struct {
	username, password, host string
	step                     int
}

func (a *loginAuth) Start(server *smtp.ServerInfo) (string, []byte, error) {
	if !server.TLS {
		return "", nil, errors.New("smtp: LOGIN refused over a connection without TLS")
	}
	if server.Name != a.host {
		return "", nil, errors.New("smtp: wrong host name")
	}
	a.step = 0
	return "LOGIN", nil, nil
}

// Next answers the two challenges in order; relays word them differently ("Username:", "User Name"), so the
// position decides, not the text.
func (a *loginAuth) Next(_ []byte, more bool) ([]byte, error) {
	if !more {
		return nil, nil
	}
	a.step++
	switch a.step {
	case 1:
		return []byte(a.username), nil
	case 2:
		return []byte(a.password), nil
	default:
		return nil, errors.New("smtp: unexpected LOGIN challenge")
	}
}

// renderEmail builds the plain-text message of plan M9 decision 28: headers, at most MaxDetailedEvents events in
// detail and a per-code summary of the rest. Organization-controlled text is folded onto one line and the body is
// quoted-printable, so no value can start a header or end the message.
func renderEmail(from mail.Address, d Destination, m outbound.Message) []byte {
	scope := d.ScopeName
	if scope == "" {
		scope = m.Organization
	}
	var subject string
	switch m.Kind {
	case outbound.KindEvents:
		noun := "security events"
		if len(m.Events) == 1 {
			noun = "security event"
		}
		subject = fmt.Sprintf("[Paddock] %s: %d %s", oneLine(scope), len(m.Events), noun)
	case outbound.KindTest:
		subject = fmt.Sprintf("[Paddock] %s: test notification", oneLine(scope))
	default:
		subject = fmt.Sprintf("[Paddock] %s: %s", oneLine(scope), m.Kind)
	}
	to := make([]string, len(d.Recipients))
	for i, r := range d.Recipients {
		to[i] = (&mail.Address{Address: r}).String()
	}
	domain := from.Address[strings.LastIndex(from.Address, "@")+1:]
	var b bytes.Buffer
	header := func(name, value string) { b.WriteString(name + ": " + value + "\r\n") }
	header("From", from.String())
	header("To", strings.Join(to, ", "))
	header("Subject", mime.QEncoding.Encode("utf-8", subject))
	header("Date", m.SentAt.Format(time.RFC1123Z))
	header("Message-ID", "<"+m.DeliveryID+"@"+domain+">")
	header("MIME-Version", "1.0")
	header("Content-Type", "text/plain; charset=utf-8")
	header("Content-Transfer-Encoding", "quoted-printable")
	header("Auto-Submitted", "auto-generated")
	header("X-Paddock-Delivery", m.DeliveryID)
	header("X-Paddock-Destination", m.DestinationID)
	if m.Kind == outbound.KindEvents && m.ForwardSeq != nil {
		header("X-Paddock-Forward-Seq", fmt.Sprintf("%d-%d", m.ForwardSeq.From, m.ForwardSeq.To))
	}
	b.WriteString("\r\n")
	qp := quotedprintable.NewWriter(&b)
	_, _ = qp.Write([]byte(emailBody(d, m, scope)))
	_ = qp.Close()
	return b.Bytes()
}

func emailBody(d Destination, m outbound.Message, scope string) string {
	var b strings.Builder
	line := func(format string, args ...any) { fmt.Fprintf(&b, format+"\n", args...) }
	switch m.Kind {
	case outbound.KindEvents:
		line("Paddock recorded %d security event(s) for %s.", len(m.Events), oneLine(scope))
	case outbound.KindTest:
		line("Paddock test notification for %s.", oneLine(scope))
		line("This destination is configured correctly.")
	default:
		line("Paddock %s for %s.", m.Kind, oneLine(scope))
	}
	line("")
	for i, me := range m.Events {
		if i == MaxDetailedEvents {
			break
		}
		ev := me.Event
		line("%s  %s  %s", ev.OccurredAt.UTC().Format(time.RFC3339), ev.Code, ev.Outcome)
		if ev.Target != nil {
			label := "target"
			if ev.Target.Type == "device" {
				label = "device"
			}
			line("  %s: %s", label, oneLine(display(ev.Target.Display, ev.Target.Type+" "+ev.Target.ID)))
		}
		line("  actor: %s", oneLine(display(ev.Actor.Display, ev.Actor.Type)))
		if me.Links != nil && me.Links.Device != "" {
			line("  link: %s", me.Links.Device)
		}
		if d.IncludeParams && len(ev.Params) > 0 {
			line("  params:")
			keys := make([]string, 0, len(ev.Params))
			for k := range ev.Params {
				keys = append(keys, k)
			}
			slices.Sort(keys)
			for _, k := range keys {
				line("    %s: %s", oneLine(k), oneLine(paramValue(ev.Params[k])))
			}
		}
		line("")
	}
	if rest := m.Events[min(len(m.Events), MaxDetailedEvents):]; len(rest) > 0 {
		counts := map[audit.Code]int{}
		for _, me := range rest {
			counts[me.Event.Code]++
		}
		codes := make([]audit.Code, 0, len(counts))
		for c := range counts {
			codes = append(codes, c)
		}
		slices.Sort(codes)
		line("Not shown in detail:")
		for _, c := range codes {
			line("  %s: %d", c, counts[c])
		}
		line("and %d more events; see the portal.", len(rest))
		line("")
	}
	line("-- ")
	line("Sent by Paddock to the notification destination %s.", oneLine(d.Name))
	return b.String()
}

func display(value, fallback string) string {
	if value != "" {
		return value
	}
	return strings.TrimSpace(fallback)
}

func paramValue(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	j, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprint(v)
	}
	return string(j)
}

// oneLine replaces control characters, so a value never adds lines to the message.
func oneLine(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
}
