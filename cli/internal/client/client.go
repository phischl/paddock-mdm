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

// Request is one call of Send. Bearer, when set, replaces the client's API token for this call; Header adds
// headers; Limit bounds the response body (0 = the client's default bound).
type Request struct {
	Method, Path string
	Query        url.Values
	Body         any
	Bearer       string
	Header       http.Header
	Limit        int64
}

// Response is the raw answer of Send. TooLarge is set when the body exceeded the limit; Body then holds the first
// Limit bytes.
type Response struct {
	Status   int
	Header   http.Header
	Body     []byte
	TooLarge bool
}

// Problem decodes a non-2xx answer as an RFC 9457 problem; nil for a 2xx answer.
func (r *Response) Problem() *Problem {
	if r.Status >= 200 && r.Status <= 299 {
		return nil
	}
	p := &Problem{Status: r.Status}
	_ = json.Unmarshal(r.Body, p)
	p.RequestID = r.Header.Get("X-Request-Id")
	return p
}

// Base returns the admin API base URL.
func (c *Client) Base() string { return c.base }

// HTTPClient returns the client's HTTP client (with the configured CA roots), for calls outside the admin API such
// as the identity provider's token endpoint.
func (c *Client) HTTPClient() *http.Client { return c.http }

// Send sends one request and returns the raw answer; only transport errors are errors.
func (c *Client) Send(ctx context.Context, r Request) (*Response, error) {
	var rd io.Reader
	switch b := r.Body.(type) {
	case nil:
	case []byte:
		rd = bytes.NewReader(b)
	default:
		raw, err := json.Marshal(b)
		if err != nil {
			return nil, err
		}
		rd = bytes.NewReader(raw)
	}
	u := c.base + r.Path
	if len(r.Query) > 0 {
		u += "?" + r.Query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, r.Method, u, rd)
	if err != nil {
		return nil, err
	}
	for k, v := range r.Header {
		req.Header[k] = v
	}
	bearer := c.secret
	if r.Bearer != "" {
		bearer = r.Bearer
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.userAgent)
	if rd != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		req.Header.Set("X-Paddock-CSRF", "1")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	limit := r.Limit
	if limit <= 0 {
		limit = maxResponse
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	out := &Response{Status: resp.StatusCode, Header: resp.Header, Body: raw}
	if int64(len(raw)) > limit {
		out.Body, out.TooLarge = raw[:limit], true
	}
	return out, nil
}

// Do sends one request; body is encoded as JSON unless it is []byte. A 2xx answer is decoded into out (unless nil);
// any other answer is returned as *Problem.
func (c *Client) Do(ctx context.Context, method, path string, query url.Values, body, out any) error {
	resp, err := c.Send(ctx, Request{Method: method, Path: path, Query: query, Body: body})
	if err != nil {
		return err
	}
	if p := resp.Problem(); p != nil {
		return p
	}
	switch o := out.(type) {
	case nil:
		return nil
	case *[]byte:
		*o = resp.Body
		return nil
	default:
		return json.Unmarshal(resp.Body, out)
	}
}
