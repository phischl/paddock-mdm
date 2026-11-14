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
	"mime"
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
	var body []byte
	if in != nil {
		var err error
		if body, err = json.Marshal(in); err != nil {
			return err
		}
	}
	data, err := c.send(ctx, method, path, device, seq, body, in != nil)
	if err != nil || out == nil {
		return err
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("device API %s %s: decode response: %w", method, path, err)
	}
	return nil
}

// send signs and sends a request and returns the body of a 2xx answer (at most maxResponse bytes).
func (c *Client) send(ctx context.Context, method, path, device string, seq int64, body []byte, isJSON bool) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	if err := protocol.Sign(req, body, c.key.Private, device, c.key.KeyID, seq, c.now()); err != nil {
		return nil, err
	}
	if isJSON {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = res.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(res.Body, maxResponse))
	if err != nil {
		return nil, err
	}
	if res.StatusCode < 200 || res.StatusCode > 299 {
		return nil, apiError(res, data)
	}
	return data, nil
}

// apiError is the *APIError of a non-2xx answer with body data.
func apiError(res *http.Response, data []byte) *APIError {
	e := &APIError{Status: res.StatusCode}
	_ = json.Unmarshal(data, &e.Problem)
	if s, err := strconv.Atoi(res.Header.Get("Retry-After")); err == nil && s > 0 {
		e.RetryAfter = time.Duration(s) * time.Second
	}
	return e
}

// MaxIconBytes bounds a catalog icon (the server's software.MaxIconBytes).
const MaxIconBytes = 64 << 10

// ErrInvalidIcon is a catalog icon download that is not 200 image/png of at most MaxIconBytes.
var ErrInvalidIcon = errors.New("catalog icon: not a PNG of at most 64 KiB")

var pngMagic = []byte("\x89PNG\r\n\x1a\n")

// CatalogIcon fetches the PNG icon of a catalog entry for the self-service app (plan M13b decision 16). The device API
// answers the signed GET with a redirect to the icon in the bundles bucket (architect decision A10-14); the client
// follows it with a plain GET, so the signed headers never reach the object store, and returns the icon only if the
// answer is 200 image/png of at most MaxIconBytes with the PNG signature. An entry without an icon is an *APIError
// with status 404; any other failure is an error, and the caller shows the category glyph.
func (c *Client) CatalogIcon(ctx context.Context, deviceID string, seq int64, entryID string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+"/v1/catalog/"+url.PathEscape(entryID)+"/icon", nil)
	if err != nil {
		return nil, err
	}
	if err := protocol.Sign(req, nil, c.key.Private, deviceID, c.key.KeyID, seq, c.now()); err != nil {
		return nil, err
	}
	noFollow := *c.http
	noFollow.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	res, err := noFollow.Do(req)
	if err != nil {
		return nil, err
	}
	data, err := io.ReadAll(io.LimitReader(res.Body, maxResponse))
	_ = res.Body.Close()
	if err != nil {
		return nil, err
	}
	switch res.StatusCode {
	case http.StatusFound, http.StatusSeeOther, http.StatusTemporaryRedirect:
	default:
		if res.StatusCode < 200 || res.StatusCode > 299 {
			return nil, apiError(res, data)
		}
		return nil, fmt.Errorf("catalog icon: HTTP %d instead of a redirect", res.StatusCode)
	}
	loc, err := res.Location()
	if err != nil {
		return nil, fmt.Errorf("catalog icon: %w", err)
	}
	get, err := http.NewRequestWithContext(ctx, http.MethodGet, loc.String(), nil)
	if err != nil {
		return nil, err
	}
	icon, err := c.http.Do(get)
	if err != nil {
		return nil, err
	}
	defer func() { _ = icon.Body.Close() }()
	if icon.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("catalog icon: object store HTTP %d", icon.StatusCode)
	}
	if mt, _, err := mime.ParseMediaType(icon.Header.Get("Content-Type")); err != nil || mt != "image/png" {
		return nil, ErrInvalidIcon
	}
	data, err = io.ReadAll(io.LimitReader(icon.Body, MaxIconBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > MaxIconBytes || !bytes.HasPrefix(data, pngMagic) {
		return nil, ErrInvalidIcon
	}
	return data, nil
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
func (c *Client) EscrowUpload(ctx context.Context, deviceID string, seq int64, req escrow.Request) (escrow.Accepted, error) {
	var out escrow.Accepted
	err := c.do(ctx, http.MethodPost, "/v1/escrow", deviceID, seq, req, &out)
	return out, err
}

// Upload PUTs body to a presigned URL (an escrowed LUKS header, plan M4b decision 10).
func (c *Client) Upload(ctx context.Context, rawURL string, body []byte) error {
	ctx, cancel := context.WithTimeout(ctx, downloadTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, rawURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	res, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("upload: HTTP %d", res.StatusCode)
	}
	return nil
}

// Diagnostics announces the sealed diagnostics bundle of a collect_status command and returns the presigned PUT of its
// object (POST /v1/diagnostics, ADR 0048 decision 3).
func (c *Client) Diagnostics(ctx context.Context, deviceID string, seq int64, req protocol.DiagnosticsRequest) (protocol.DiagnosticsResponse, error) {
	var out protocol.DiagnosticsResponse
	err := c.do(ctx, http.MethodPost, "/v1/diagnostics", deviceID, seq, req, &out)
	return out, err
}

// maxHealthz bounds the body of GET /healthz kept for the diagnostics bundle.
const maxHealthz = 4 << 10

// Healthz returns the status line and the body (at most 4 KiB) of GET <server_url>/healthz; any HTTP status is an
// answer, only a failed request is an error.
func (c *Client) Healthz(ctx context.Context) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+"/healthz", nil)
	if err != nil {
		return nil, err
	}
	res, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = res.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(res.Body, maxHealthz))
	if err != nil {
		return nil, err
	}
	return append([]byte(res.Status+"\n"), body...), nil
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
