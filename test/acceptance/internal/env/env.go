// Package env gives the acceptance gates and the dev seeder access to the running development stack: logged-in
// portal clients, the admin API and the Authentik admin API (bootstrap token).
package env

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"

	"github.com/paddock-mdm/paddock/test/acceptance/internal/authflow"
	"github.com/paddock-mdm/paddock/test/acceptance/internal/stack"
)

// Dev users of authentik/dev/paddock-dev.yaml and their password files in .secrets/.
const (
	PlatformAdmin = "platform-admin@paddock.test"
	Alice         = "alice@acme.test"
	Bob           = "bob@acme.test"
	Carol         = "carol@globex.test"
)

var passwordFiles = map[string]string{
	PlatformAdmin: "dev_platform_admin_password",
	Alice:         "dev_alice_password",
	Bob:           "dev_bob_password",
	Carol:         "dev_carol_password",
}

// NewHTTPClient returns a client that trusts the stack's Caddy CA.
func NewHTTPClient() (*http.Client, error) {
	dir, err := stack.SecretsDir()
	if err != nil {
		return nil, err
	}
	return authflow.NewClient(filepath.Join(dir, "caddy-root.crt"))
}

// Password returns the password of a dev user.
func Password(user string) (string, error) {
	f, ok := passwordFiles[user]
	if !ok {
		return "", fmt.Errorf("env: unknown dev user %s", user)
	}
	return stack.Secret(f)
}

// Login signs in a dev user (or any user with the given password) and returns a portal session.
func Login(ctx context.Context, user, password string) (*Portal, error) {
	if password == "" {
		var err error
		if password, err = Password(user); err != nil {
			return nil, err
		}
	}
	client, err := NewHTTPClient()
	if err != nil {
		return nil, err
	}
	res, err := authflow.Login(ctx, client, stack.AdminURL(), user, password)
	if err != nil {
		if res != nil {
			return &Portal{Client: res.Client, Final: res.Final}, err
		}
		return nil, err
	}
	return &Portal{Client: res.Client, Final: res.Final}, nil
}

// Portal is a signed-in portal session.
type Portal struct {
	Client *http.Client
	Final  string
}

// Response is an API answer.
type Response struct {
	Status    int
	Header    http.Header
	Body      []byte
	RequestID string
}

// JSON decodes the body.
func (r Response) JSON(v any) error { return json.Unmarshal(r.Body, v) }

// ProblemCode returns the problem code of an error body.
func (r Response) ProblemCode() string {
	var p struct {
		Code string `json:"code"`
	}
	_ = json.Unmarshal(r.Body, &p)
	return p.Code
}

// Do calls the admin API. Mutating requests carry X-Paddock-CSRF: 1 unless noCSRF is set.
func (p *Portal) Do(ctx context.Context, method, path string, body any) (Response, error) {
	return Call(ctx, p.Client, method, stack.AdminURL()+path, body, method != http.MethodGet)
}

// Call sends one request.
func Call(ctx context.Context, client *http.Client, method, u string, body any, csrf bool) (Response, error) {
	var rd io.Reader
	switch b := body.(type) {
	case nil:
	case []byte:
		rd = bytes.NewReader(b)
	default:
		data, err := json.Marshal(b)
		if err != nil {
			return Response{}, err
		}
		rd = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rd)
	if err != nil {
		return Response{}, err
	}
	if rd != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if csrf {
		req.Header.Set("X-Paddock-CSRF", "1")
	}
	resp, err := client.Do(req)
	if err != nil {
		return Response{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return Response{}, err
	}
	return Response{Status: resp.StatusCode, Header: resp.Header, Body: data, RequestID: resp.Header.Get("X-Request-Id")}, nil
}

// Authentik is the Authentik admin API with the bootstrap token.
type Authentik struct {
	client *http.Client
	base   string
	token  string
}

// NewAuthentik creates the admin client.
func NewAuthentik() (*Authentik, error) {
	client, err := NewHTTPClient()
	if err != nil {
		return nil, err
	}
	token, err := stack.Secret("authentik_bootstrap_token")
	if err != nil {
		return nil, err
	}
	return &Authentik{client: client, base: stack.AuthURL() + "/api/v3", token: token}, nil
}

func (a *Authentik) do(ctx context.Context, method, path string, body, out any) error {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, a.base+path, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+a.token)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := a.client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return fmt.Errorf("authentik %s %s: HTTP %d: %s", method, path, resp.StatusCode, data)
	}
	if out != nil && len(data) > 0 {
		return json.Unmarshal(data, out)
	}
	return nil
}

// UserPK returns the numeric pk of a user (0 if missing).
func (a *Authentik) UserPK(ctx context.Context, username string) (int, error) {
	var page struct {
		Results []struct {
			PK       int    `json:"pk"`
			Username string `json:"username"`
		} `json:"results"`
	}
	if err := a.do(ctx, http.MethodGet, "/core/users/?"+url.Values{"username": {username}}.Encode(), nil, &page); err != nil {
		return 0, err
	}
	for _, u := range page.Results {
		if u.Username == username {
			return u.PK, nil
		}
	}
	return 0, nil
}

// GroupPK returns the pk of a group ("" if missing).
func (a *Authentik) GroupPK(ctx context.Context, name string) (string, error) {
	var page struct {
		Results []struct {
			PK   string `json:"pk"`
			Name string `json:"name"`
		} `json:"results"`
	}
	q := url.Values{"name": {name}, "include_users": {"false"}}
	if err := a.do(ctx, http.MethodGet, "/core/groups/?"+q.Encode(), nil, &page); err != nil {
		return "", err
	}
	for _, g := range page.Results {
		if g.Name == name {
			return g.PK, nil
		}
	}
	return "", nil
}

// EnsureGroup creates a group if missing (tests that need groups Paddock does not create).
func (a *Authentik) EnsureGroup(ctx context.Context, name string) (string, error) {
	pk, err := a.GroupPK(ctx, name)
	if err != nil || pk != "" {
		return pk, err
	}
	var g struct {
		PK string `json:"pk"`
	}
	err = a.do(ctx, http.MethodPost, "/core/groups/", map[string]any{"name": name}, &g)
	return g.PK, err
}

// AddToGroup adds a user to a group (idempotent).
func (a *Authentik) AddToGroup(ctx context.Context, username, group string) error {
	user, err := a.UserPK(ctx, username)
	if err != nil {
		return err
	}
	if user == 0 {
		return fmt.Errorf("authentik user %s not found", username)
	}
	g, err := a.GroupPK(ctx, group)
	if err != nil {
		return err
	}
	if g == "" {
		return fmt.Errorf("authentik group %s not found", group)
	}
	return a.do(ctx, http.MethodPost, "/core/groups/"+g+"/add_user/", map[string]any{"pk": user}, nil)
}

// CreateUser creates an internal user with a password and returns its pk.
func (a *Authentik) CreateUser(ctx context.Context, username, password string, groups ...string) (int, error) {
	var u struct {
		PK int `json:"pk"`
	}
	if err := a.do(ctx, http.MethodPost, "/core/users/", map[string]any{
		"username": username, "name": username, "email": username, "is_active": true, "type": "internal",
	}, &u); err != nil {
		return 0, err
	}
	if err := a.do(ctx, http.MethodPost, fmt.Sprintf("/core/users/%d/set_password/", u.PK), map[string]any{"password": password}, nil); err != nil {
		return u.PK, err
	}
	for _, g := range groups {
		if err := a.AddToGroup(ctx, username, g); err != nil {
			return u.PK, err
		}
	}
	return u.PK, nil
}

// DeleteUser deletes a user.
func (a *Authentik) DeleteUser(ctx context.Context, pk int) error {
	return a.do(ctx, http.MethodDelete, fmt.Sprintf("/core/users/%d/", pk), nil, nil)
}

// IsNotFound reports whether err is an Authentik 404.
func IsNotFound(err error) bool { return err != nil && strings.Contains(err.Error(), "HTTP 404") }
