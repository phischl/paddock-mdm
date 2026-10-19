package admin

import (
	"context"
	"io"
	"net/http"
	"time"

	"golang.org/x/oauth2"
)

// tokenAttempts bounds the token requests of one code exchange; tokenBackoff is the wait before the first repeat,
// doubled before each further one (0.25 + 0.5 + 1 s at most).
const (
	tokenAttempts = 4
	tokenBackoff  = 250 * time.Millisecond
)

// exchangeContext returns ctx with the HTTP client oauth2 uses for the token request of a code exchange: it repeats a
// request the identity provider answered with 503 Service Unavailable. Authentik's front server answers 503
// "authentik starting" without passing the request on while its backend is not ready, so the single-use code is still
// unused; any other answer is final, because the code may have been redeemed.
func exchangeContext(ctx context.Context) context.Context {
	return context.WithValue(ctx, oauth2.HTTPClient, &http.Client{
		Transport: retryUnavailable{base: http.DefaultTransport, attempts: tokenAttempts, backoff: tokenBackoff},
	})
}

// retryUnavailable repeats a request answered with 503 up to attempts times in all.
type retryUnavailable struct {
	base     http.RoundTripper
	attempts int
	backoff  time.Duration
}

// RoundTrip implements http.RoundTripper.
func (t retryUnavailable) RoundTrip(req *http.Request) (*http.Response, error) {
	backoff := t.backoff
	for attempt := 1; ; attempt++ {
		resp, err := t.base.RoundTrip(req)
		if err != nil || resp.StatusCode != http.StatusServiceUnavailable || attempt >= t.attempts ||
			(req.Body != nil && req.GetBody == nil) {
			return resp, err
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
		_ = resp.Body.Close()
		select {
		case <-req.Context().Done():
			return nil, req.Context().Err()
		case <-time.After(backoff):
		}
		backoff *= 2
		next := req.Clone(req.Context())
		if req.GetBody != nil {
			if next.Body, err = req.GetBody(); err != nil {
				return nil, err
			}
		}
		req = next
	}
}
