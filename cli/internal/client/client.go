// Package client is paddockctl's HTTP client of the Paddock admin API: API token authentication, the CSRF header of
// mutating requests and RFC 9457 problem details (plan M6c decision 25).
package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"
)

// Timeout bounds every request.
const Timeout = 60 * time.Second

// maxResponse bounds a response body (an exported configuration is at most a few MiB).
const maxResponse = 32 << 20

// Client calls the admin API with an API token.
type Client struct {
	base, secret, userAgent string
	http                    *http.Client
}

// New creates a client for the admin API at base. caFile, when set, is a PEM bundle appended to the system roots.
func New(base, secret, caFile, version string) (*Client, error) {
	roots, err := x509.SystemCertPool()
	if err != nil {
		roots = x509.NewCertPool()
	}
	if caFile != "" {
		pem, err := os.ReadFile(caFile) //nolint:gosec // the operator's own CA bundle
		if err != nil {
			return nil, fmt.Errorf("CA file: %w", err)
		}
		if !roots.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("CA file %s contains no PEM certificate", caFile)
		}
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
	return &Client{base: base, secret: secret, userAgent: "paddockctl/" + version,
		http: &http.Client{Timeout: Timeout, Transport: transport}}, nil
}

// Problem is an RFC 9457 problem answered by the admin API.
type Problem struct {
	Status    int    `json:"status"`
	Code      string `json:"code"`
	Detail    string `json:"detail"`
	RequestID string `json:"-"`
}

func (p *Problem) Error() string {
	msg := p.Code
	if msg == "" {
		msg = http.StatusText(p.Status)
	}
	if p.Detail != "" {
		msg += ": " + p.Detail
	}
	if p.RequestID != "" {
		msg += " (request " + p.RequestID + ")"
	}
	return msg
}

// Do sends one request; body is encoded as JSON unless it is []byte. A 2xx answer is decoded into out (unless nil);
// any other answer is returned as *Problem.
func (c *Client) Do(ctx context.Context, method, path string, query url.Values, body, out any) error {
	var rd io.Reader
	switch b := body.(type) {
	case nil:
	case []byte:
		rd = bytes.NewReader(b)
	default:
		raw, err := json.Marshal(b)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(raw)
	}
	u := c.base + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.secret)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.userAgent)
	if rd != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if method != http.MethodGet && method != http.MethodHead {
		req.Header.Set("X-Paddock-CSRF", "1")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse))
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		p := &Problem{Status: resp.StatusCode}
		_ = json.Unmarshal(raw, p)
		p.RequestID = resp.Header.Get("X-Request-Id")
		return p
	}
	switch o := out.(type) {
	case nil:
		return nil
	case *[]byte:
		*o = raw
		return nil
	default:
		return json.Unmarshal(raw, out)
	}
}
