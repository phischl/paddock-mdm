package notifier

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/phischl/paddock-mdm/server/internal/domain/outbound"
)

// maxResponseDrain is how much of a webhook's answer is read (and discarded) so the connection can be reused.
const maxResponseDrain = 4 << 10

// Webhook posts the signed envelope of plan M9 §6.4 through the outbound policy's client: addresses checked at dial
// time, no proxy, redirects refused, 30 s per call (plan M9 decision 24).
type Webhook struct {
	client       *http.Client
	allowPrivate bool
	userAgent    string
	now          func() time.Time
}

// NewWebhook creates the webhook transport; allowPrivate is the development-only PADDOCK_OUTBOUND_DEV_ALLOW_PRIVATE.
func NewWebhook(allowPrivate bool, version string) *Webhook {
	return &Webhook{
		client: outbound.Policy{AllowPrivate: allowPrivate}.Client(), allowPrivate: allowPrivate,
		userAgent: "paddock-notifier/" + version, now: time.Now,
	}
}

// Deliver posts m; a 2xx answer is success, everything else a *DeliveryError with its class. The error never
// carries the URL, which may hold a credential.
func (w *Webhook) Deliver(ctx context.Context, d Destination, m outbound.Message) error {
	body, err := json.Marshal(m)
	if err != nil {
		return fmt.Errorf("webhook: encode message: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.URL, bytes.NewReader(body))
	if err != nil {
		return &DeliveryError{Class: "dial"}
	}
	// The api accepts only https outside development; a stored plain-http URL is never called in production.
	if req.URL.Scheme != "https" && !w.allowPrivate {
		return &DeliveryError{Class: "denied_address"}
	}
	ts := w.now().Unix()
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", w.userAgent)
	req.Header.Set(outbound.HeaderTimestamp, strconv.FormatInt(ts, 10))
	req.Header.Set(outbound.HeaderSignature, outbound.Signature(d.Secret, ts, body))
	req.Header.Set(outbound.HeaderDelivery, m.DeliveryID)
	req.Header.Set(outbound.HeaderDestination, m.DestinationID)
	resp, err := w.client.Do(req)
	if err != nil {
		return &DeliveryError{Class: transportClass(err)}
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponseDrain))
	_ = resp.Body.Close()
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return nil
	case resp.StatusCode >= 300 && resp.StatusCode < 400:
		return &DeliveryError{Class: "redirect"}
	default:
		return &DeliveryError{Class: "http_" + strconv.Itoa(resp.StatusCode)}
	}
}

// transportClass maps an error of the HTTP client to its class.
func transportClass(err error) string {
	var dnsErr *net.DNSError
	var certErr *tls.CertificateVerificationError
	var unknownAuthority x509.UnknownAuthorityError
	var hostnameErr x509.HostnameError
	var invalidCert x509.CertificateInvalidError
	var recordErr tls.RecordHeaderError
	var alertErr tls.AlertError
	var netErr net.Error
	switch {
	case errors.Is(err, outbound.ErrRedirect):
		return "redirect"
	case errors.Is(err, outbound.ErrDeniedAddress):
		return "denied_address"
	case errors.As(err, &dnsErr):
		return "dns"
	case errors.As(err, &certErr), errors.As(err, &unknownAuthority), errors.As(err, &hostnameErr),
		errors.As(err, &invalidCert), errors.As(err, &recordErr), errors.As(err, &alertErr):
		return "tls"
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &netErr) && netErr.Timeout():
		return "timeout"
	default:
		return "dial"
	}
}
