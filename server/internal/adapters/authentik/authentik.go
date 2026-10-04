// Package authentik is the Authentik REST adapter (/api/v3): organization groups, the per-organization device login
// provider (plan M3a decision 5), users, lock and user groups. Every object is found by name and created or corrected
// if needed, so all operations are idempotent.
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
	"strconv"
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

var (
	_ ports.IdentityProvider = (*Client)(nil)
	_ ports.UserDirectory    = (*Client)(nil)
	_ ports.GroupDirectory   = (*Client)(nil)
)

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

// EnsureOrganization creates paddock.<slug> with its .admins, .operators, .auditors and .locked children and the
// device login application if missing, and corrects the device login objects (architecture §9.2).
func (c *Client) EnsureOrganization(ctx context.Context, slug string) (ports.OrgIdentityRefs, error) {
	rootPK, err := c.ensureGroup(ctx, organization.RootGroup(slug), "")
	if err != nil {
		return ports.OrgIdentityRefs{}, err
	}
	refs := ports.OrgIdentityRefs{RootGroupPK: rootPK}
	for _, g := range []struct {
		name string
		pk   *string
	}{
		{organization.RoleGroup(slug, organization.GroupAdmins), &refs.AdminsGroupPK},
		{organization.RoleGroup(slug, organization.GroupOperators), &refs.OperatorsGroupPK},
		{organization.RoleGroup(slug, organization.GroupAuditors), &refs.AuditorsGroupPK},
		{organization.LockedGroup(slug), &refs.LockedGroupPK},
	} {
		pk, err := c.ensureGroup(ctx, g.name, rootPK)
		if err != nil {
			return ports.OrgIdentityRefs{}, err
		}
		*g.pk = pk
	}
	if err := c.ensureDeviceLogin(ctx, slug); err != nil {
		return ports.OrgIdentityRefs{}, err
	}
	return refs, nil
}

// EnsureGroup creates name as child of the organization's root group if missing.
func (c *Client) EnsureGroup(ctx context.Context, slug, name string) (string, error) {
	rootPK, err := c.ensureGroup(ctx, organization.RootGroup(slug), "")
	if err != nil {
		return "", err
	}
	return c.ensureGroup(ctx, name, rootPK)
}

// FindGroup returns the pk of the group name, or "".
func (c *Client) FindGroup(ctx context.Context, name string) (string, error) {
	return c.findGroup(ctx, name)
}

// DeleteGroup deletes a group; a missing group is not an error.
func (c *Client) DeleteGroup(ctx context.Context, pk string) error {
	return c.deleteIgnoringMissing(ctx, "/api/v3/core/groups/"+url.PathEscape(pk)+"/")
}

// AddMember adds a user to a group (idempotent in Authentik).
func (c *Client) AddMember(ctx context.Context, groupPK, userPK string) error {
	return c.membership(ctx, "add_user", groupPK, userPK)
}

// RemoveMember removes a user from a group (idempotent in Authentik).
func (c *Client) RemoveMember(ctx context.Context, groupPK, userPK string) error {
	return c.membership(ctx, "remove_user", groupPK, userPK)
}

func (c *Client) membership(ctx context.Context, action, groupPK, userPK string) error {
	pk, err := strconv.Atoi(userPK)
	if err != nil {
		return fmt.Errorf("authentik: user pk %q: %w", userPK, err)
	}
	if err := c.do(ctx, http.MethodPost, "/api/v3/core/groups/"+url.PathEscape(groupPK)+"/"+action+"/", map[string]int{"pk": pk}, nil); err != nil {
		return upstream(err)
	}
	return nil
}

// GroupMembers returns the pks of the direct members of a group.
func (c *Client) GroupMembers(ctx context.Context, groupPK string) ([]string, error) {
	q := url.Values{"groups_by_pk": {groupPK}, "include_groups": {"false"}}
	var pks []string
	err := pages(ctx, c, "/api/v3/core/users/", q, func(u user) { pks = append(pks, strconv.Itoa(u.PK)) })
	return pks, err
}

// UpstreamGroups lists the groups outside Paddock's namespace that have at least one direct member of
// paddock.<slug> (plan M3b decision 1): an organization never sees groups that only other organizations' users are in.
func (c *Client) UpstreamGroups(ctx context.Context, slug string) ([]ports.IdentityGroup, error) {
	q := url.Values{"groups_by_name": {organization.RootGroup(slug)}, "include_groups": {"true"}}
	seen := map[string]bool{}
	var out []ports.IdentityGroup
	err := pages(ctx, c, "/api/v3/core/users/", q, func(u user) {
		for _, g := range u.GroupsObj {
			if !organization.IsPaddockGroup(g.Name) && !seen[g.PK] {
				seen[g.PK] = true
				out = append(out, ports.IdentityGroup{PK: g.PK, Name: g.Name})
			}
		}
	})
	return out, err
}

// pageSize is the page size of list requests; maxPages bounds a listing (100 000 objects).
const (
	pageSize = 500
	maxPages = 200
)

// pages calls fn for every result of a paginated list endpoint.
func pages[T any](ctx context.Context, c *Client, path string, q url.Values, fn func(T)) error {
	q.Set("page_size", strconv.Itoa(pageSize))
	for page := 1; page <= maxPages; page++ {
		q.Set("page", strconv.Itoa(page))
		var res struct {
			Pagination struct {
				Next int `json:"next"`
			} `json:"pagination"`
			Results []T `json:"results"`
		}
		if err := c.do(ctx, http.MethodGet, path+"?"+q.Encode(), nil, &res); err != nil {
			return upstream(err)
		}
		for _, r := range res.Results {
			fn(r)
		}
		if res.Pagination.Next == 0 {
			return nil
		}
	}
	return fmt.Errorf("authentik: %s has more than %d pages", path, maxPages)
}

// deleteIgnoringMissing deletes an object; 404 counts as deleted.
func (c *Client) deleteIgnoringMissing(ctx context.Context, path string) error {
	err := c.do(ctx, http.MethodDelete, path, nil, nil)
	var st *errStatus
	if errors.As(err, &st) && st.code == http.StatusNotFound {
		return nil
	}
	if err != nil {
		return upstream(err)
	}
	return nil
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
