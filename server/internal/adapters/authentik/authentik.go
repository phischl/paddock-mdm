// Package authentik is the Authentik REST adapter (/api/v3). It only creates and looks up groups in M0.
package authentik

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/paddock-mdm/paddock/server/internal/domain/organization"
	"github.com/paddock-mdm/paddock/server/internal/ports"
	"github.com/paddock-mdm/paddock/server/internal/problem"
)

// Client talks to Authentik with the paddock-service API token.
type Client struct {
	base    string
	token   string
	http    *http.Client
	retries int
	backoff time.Duration
}

var _ ports.IdentityProvider = (*Client)(nil)

// New creates a client for baseURL (e.g. https://auth.example.org). Requests time out after 10 s; 5xx and
// network errors are retried 3 times with exponential back-off, 4xx never.
func New(baseURL, token string) *Client {
	return &Client{
		base: strings.TrimRight(baseURL, "/"), token: token,
		http:    &http.Client{Timeout: 10 * time.Second},
		retries: 3, backoff: 500 * time.Millisecond,
	}
}

// WithHTTPClient replaces the HTTP client (tests).
func (c *Client) WithHTTPClient(h *http.Client) *Client { c.http = h; return c }

// WithBackoff changes the initial retry back-off (tests).
func (c *Client) WithBackoff(d time.Duration) *Client { c.backoff = d; return c }

// errStatus is a non-2xx answer.
type errStatus struct {
	code int
	body string
}

func (e *errStatus) Error() string { return fmt.Sprintf("authentik: HTTP %d: %s", e.code, e.body) }

type group struct {
	PK      string   `json:"pk"`
	Name    string   `json:"name"`
	Parents []string `json:"parents"`
}

// EnsureOrganization creates paddock:<slug> and its :admins, :operators and :auditors children if missing.
func (c *Client) EnsureOrganization(ctx context.Context, slug string) (ports.OrgIdentityRefs, error) {
	root, admins, operators, auditors := organization.AuthentikGroups(slug)
	rootPK, err := c.ensureGroup(ctx, root, "")
	if err != nil {
		return ports.OrgIdentityRefs{}, err
	}
	refs := ports.OrgIdentityRefs{RootGroupPK: rootPK}
	for _, g := range []struct {
		name string
		pk   *string
	}{{admins, &refs.AdminsGroupPK}, {operators, &refs.OperatorsGroupPK}, {auditors, &refs.AuditorsGroupPK}} {
		pk, err := c.ensureGroup(ctx, g.name, rootPK)
		if err != nil {
			return ports.OrgIdentityRefs{}, err
		}
		*g.pk = pk
	}
	return refs, nil
}

func (c *Client) ensureGroup(ctx context.Context, name, parent string) (string, error) {
	pk, err := c.findGroup(ctx, name)
	if err != nil || pk != "" {
		return pk, err
	}
	body := map[string]any{"name": name}
	if parent != "" {
		body["parents"] = []string{parent}
	}
	var created group
	if err := c.do(ctx, http.MethodPost, "/api/v3/core/groups/", body, &created); err != nil {
		var st *errStatus
		// A concurrent request may have created it meanwhile (name is unique): look it up again.
		if errors.As(err, &st) && st.code == http.StatusBadRequest {
			if pk, ferr := c.findGroup(ctx, name); ferr == nil && pk != "" {
				return pk, nil
			}
		}
		return "", upstream(err)
	}
	slog.InfoContext(ctx, "authentik group created", "group", name, "pk", created.PK)
	return created.PK, nil
}

func (c *Client) findGroup(ctx context.Context, name string) (string, error) {
	var page struct {
		Results []group `json:"results"`
	}
	q := url.Values{"name": {name}, "include_users": {"false"}}
	if err := c.do(ctx, http.MethodGet, "/api/v3/core/groups/?"+q.Encode(), nil, &page); err != nil {
		return "", upstream(err)
	}
	for _, g := range page.Results {
		if g.Name == name {
			return g.PK, nil
		}
	}
	return "", nil
}

// do sends one request with retries on network errors and 5xx.
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
		slog.WarnContext(ctx, "authentik request failed; retrying", "method", method, "path", path, "attempt", attempt+1, "error", err)
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
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
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

func upstream(err error) error {
	if errors.Is(err, context.Canceled) {
		return err
	}
	return fmt.Errorf("%w: %v", problem.UpstreamUnavailable, err)
}
