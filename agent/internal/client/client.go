// Package client is the agent's side of the device API (api/openapi/device.yaml): every request is signed with the
// device key (pkg/protocol), errors are decoded from RFC 9457 problem details.
package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/phischl/paddock-mdm/agent/internal/identity"
	"github.com/phischl/paddock-mdm/pkg/escrow"
	"github.com/phischl/paddock-mdm/pkg/protocol"
)

// Timeouts of device API requests and downloads.
const (
	requestTimeout  = 30 * time.Second
	downloadTimeout = 10 * time.Minute
	maxResponse     = 1 << 20
)

// APIError is a non-2xx answer of the device API.
type APIError struct {
	Status     int
	Problem    protocol.Problem
	RetryAfter time.Duration
}

func (e *APIError) Error() string {
	if e.Problem.Code != "" {
		return fmt.Sprintf("device API: HTTP %d %s: %s", e.Status, e.Problem.Code, e.Problem.Detail)
	}
	return fmt.Sprintf("device API: HTTP %d", e.Status)
}

// Code returns the problem code of err, or "" if err is not an *APIError.
func Code(err error) string {
	var e *APIError
	if errors.As(err, &e) {
		return e.Problem.Code
	}
	return ""
}

// Client signs and sends device API requests.
type Client struct {
	base string
	http *http.Client
	key  identity.Key
	now  func() time.Time
}

// New creates a client for serverURL. proxy is optional.
func New(serverURL, proxy string, key identity.Key) (*Client, error) {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.Proxy = nil // only the proxy from agent.yml; the supervisor's environment is not configuration
	if proxy != "" {
		u, err := url.Parse(proxy)
		if err != nil {
			return nil, fmt.Errorf("proxy: %w", err)
		}
		tr.Proxy = http.ProxyURL(u)
	}
	return &Client{base: strings.TrimRight(serverURL, "/"), http: &http.Client{Transport: tr}, key: key, now: time.Now}, nil
}

// NewWithHTTP creates a client with a given HTTP client and clock (tests).
func NewWithHTTP(serverURL string, hc *http.Client, key identity.Key, now func() time.Time) *Client {
	return &Client{base: strings.TrimRight(serverURL, "/"), http: hc, key: key, now: now}
}

// do signs and sends a request and decodes a 2xx JSON answer into out (if not nil).
func (c *Client) do(ctx context.Context, method, path, device string, seq int64, in, out any) error {
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	var body []byte
	if in != nil {
		var err error
		if body, err = json.Marshal(in); err != nil {
			return err
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	if err := protocol.Sign(req, body, c.key.Private, device, c.key.KeyID, seq, c.now()); err != nil {
		return err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = res.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(res.Body, maxResponse))
	if err != nil {
		return err
	}
	if res.StatusCode < 200 || res.StatusCode > 299 {
		e := &APIError{Status: res.StatusCode}
		_ = json.Unmarshal(data, &e.Problem)
		if s, err := strconv.Atoi(res.Header.Get("Retry-After")); err == nil && s > 0 {
			e.RetryAfter = time.Duration(s) * time.Second
		}
		return e
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("device API %s %s: decode response: %w", method, path, err)
	}
	return nil
}

// Enroll sends the enrollment request and returns the enrollment ID.
func (c *Client) Enroll(ctx context.Context, req protocol.EnrollRequest) (string, error) {
	var out protocol.EnrollAccepted
	if err := c.do(ctx, http.MethodPost, "/v1/enroll", protocol.EnrollDevice, 0, req, &out); err != nil {
		return "", err
	}
	return out.EnrollmentID, nil
}

// EnrollStatus polls the status of an enrollment.
func (c *Client) EnrollStatus(ctx context.Context, enrollmentID string) (protocol.EnrollStatus, error) {
	var out protocol.EnrollStatus
	err := c.do(ctx, http.MethodGet, "/v1/enroll/"+url.PathEscape(enrollmentID), protocol.EnrollDevice, 0, nil, &out)
	return out, err
}

// Checkin sends a check-in with the last received sequence number.
func (c *Client) Checkin(ctx context.Context, deviceID string, seq int64, req protocol.CheckinRequest) (protocol.CheckinResponse, error) {
	var out protocol.CheckinResponse
	err := c.do(ctx, http.MethodPost, "/v1/checkin", deviceID, seq, req, &out)
	return out, err
}

// Events posts a batch of events; nil means 202.
func (c *Client) Events(ctx context.Context, deviceID string, seq int64, events []protocol.Event) error {
	return c.do(ctx, http.MethodPost, "/v1/events", deviceID, seq, protocol.EventsRequest{Events: events}, nil)
}

// CommandResult posts the result of a command; nil means 202.
func (c *Client) CommandResult(ctx context.Context, deviceID string, seq int64, commandID string, res protocol.CommandResult) error {
	return c.do(ctx, http.MethodPost, "/v1/commands/"+url.PathEscape(commandID)+"/result", deviceID, seq, res, nil)
}

// EscrowUpload uploads an escrowed secret; nil means 202.
func (c *Client) EscrowUpload(ctx context.Context, deviceID string, seq int64, req escrow.Request) error {
	return c.do(ctx, http.MethodPost, "/v1/escrow", deviceID, seq, req, nil)
}

// EscrowStatus returns the storage status of an escrow upload (pending, stored or failed).
func (c *Client) EscrowStatus(ctx context.Context, deviceID string, seq int64, escrowID string) (string, error) {
	var out escrow.Status
	err := c.do(ctx, http.MethodGet, "/v1/escrow/"+url.PathEscape(escrowID), deviceID, seq, nil, &out)
	return out.Status, err
}

// Reachable reports whether the server answers HTTPS at all (any HTTP status counts).
func (c *Client) Reachable(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+"/", nil)
	if err != nil {
		return err
	}
	res, err := c.http.Do(req)
	if err != nil {
		return err
	}
	return res.Body.Close()
}

// ErrTooLarge means a download exceeded its size limit.
var ErrTooLarge = errors.New("download exceeds the expected size")

// Download fetches a presigned URL (no request signature) with at most limit bytes.
func (c *Client) Download(ctx context.Context, rawURL string, limit int64) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, downloadTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	res, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download: HTTP %d", res.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(res.Body, limit+1))
	if err != nil {
		return nil, fmt.Errorf("download: %w", err)
	}
	if int64(len(data)) > limit {
		return nil, ErrTooLarge
	}
	return data, nil
}
