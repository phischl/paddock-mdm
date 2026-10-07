// Package fleet is the Fleet REST adapter (free edition, version pinned in Compose; ADR 0009, plan M5a): Fleet's
// settings of Paddock's data minimization, the hosts with their software, vulnerabilities and policy results, and
// Paddock's policies. Fleet's numeric host IDs leave the package only as opaque external IDs.
package fleet

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// Client talks to Fleet's API with the token of the API-only user paddock.
type Client struct {
	base      string
	token     string
	publicURL string
	http      *http.Client
	retries   int
	backoff   time.Duration
}

// New creates a client for Fleet's internal baseURL (e.g. http://fleet:8080); publicURL is the device-facing URL
// (https://fleet.<domain>), Fleet's server URL. Requests time out after 30 s; 5xx and network errors are retried 3
// times with exponential back-off, 4xx never.
func New(baseURL, token, publicURL string) *Client {
	return &Client{
		base: strings.TrimRight(baseURL, "/"), token: token, publicURL: strings.TrimRight(publicURL, "/"),
		http:    &http.Client{Timeout: 30 * time.Second},
		retries: 3, backoff: 500 * time.Millisecond,
	}
}

// WithBackoff changes the initial retry back-off (tests).
func (c *Client) WithBackoff(d time.Duration) *Client { c.backoff = d; return c }

// errStatus is a non-2xx answer.
type errStatus struct {
	code int
	body string
}

func (e *errStatus) Error() string { return fmt.Sprintf("fleet: HTTP %d: %s", e.code, e.body) }

func (c *Client) do(ctx context.Context, method, path string, in, out any) error {
	var payload []byte
	if in != nil {
		var err error
		if payload, err = json.Marshal(in); err != nil {
			return err
		}
	}
	backoff := c.backoff
	var lastErr error
	for attempt := 0; attempt <= c.retries; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(backoff):
			}
			backoff *= 2
		}
		retry, err := c.once(ctx, method, path, payload, out)
		if err == nil {
			return nil
		}
		lastErr = err
		if !retry {
			return err
		}
		slog.WarnContext(ctx, "fleet request failed; retrying", "method", method, "path", path, "attempt", attempt+1, "error", err)
	}
	return lastErr
}

func (c *Client) once(ctx context.Context, method, path string, payload []byte, out any) (retry bool, err error) {
	var body io.Reader
	if payload != nil {
		body = bytes.NewReader(payload)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, body)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/json")
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return ctx.Err() == nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return true, err
	}
	if resp.StatusCode >= 500 {
		return true, &errStatus{resp.StatusCode, truncate(data)}
	}
	if resp.StatusCode >= 300 {
		return false, &errStatus{resp.StatusCode, truncate(data)}
	}
	if out == nil {
		return false, nil
	}
	return false, json.Unmarshal(data, out)
}

func truncate(b []byte) string {
	if len(b) > 300 {
		b = b[:300]
	}
	return string(b)
}
