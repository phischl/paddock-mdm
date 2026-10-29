package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/oauth2"

	"github.com/phischl/paddock-mdm/cli/internal/client"
)

// ErrLoginRequired means the session cannot be renewed: the administrator has to run paddockctl mcp login again.
var ErrLoginRequired = errors.New("login required: run paddockctl mcp login")

// ErrLoginTimedOut is returned by Login when the device code expired before the administrator approved it.
var ErrLoginTimedOut = errors.New("login timed out")

// loginConfig is GET /api/auth/mcp/config.
type loginConfig struct {
	Issuer                      string   `json:"issuer"`
	ClientID                    string   `json:"client_id"`
	Scopes                      []string `json:"scopes"`
	DeviceAuthorizationEndpoint string   `json:"device_authorization_endpoint"`
	TokenEndpoint               string   `json:"token_endpoint"`
	RevocationEndpoint          string   `json:"revocation_endpoint"`
}

func (l loginConfig) oauth() *oauth2.Config {
	return &oauth2.Config{ClientID: l.ClientID, Scopes: l.Scopes, Endpoint: oauth2.Endpoint{
		DeviceAuthURL: l.DeviceAuthorizationEndpoint, TokenURL: l.TokenEndpoint, AuthStyle: oauth2.AuthStyleInParams}}
}

func fetchConfig(ctx context.Context, c *client.Client) (loginConfig, error) {
	var cfg loginConfig
	if err := c.Do(ctx, http.MethodGet, "/api/auth/mcp/config", nil, nil, &cfg); err != nil {
		return loginConfig{}, fmt.Errorf("MCP login configuration: %w", err)
	}
	if cfg.ClientID == "" || cfg.TokenEndpoint == "" || cfg.DeviceAuthorizationEndpoint == "" {
		return loginConfig{}, errors.New("MCP login configuration: incomplete answer")
	}
	return cfg, nil
}

// LoginOptions are the choices of paddockctl mcp login.
type LoginOptions struct {
	// Role is RoleOrganization or RolePlatform (--platform).
	Role string
	// Browser opens the verification URL; nil prints it only (--no-browser, no display).
	Browser func(url string) error
	// Out receives the instructions for the administrator (stderr).
	Out io.Writer
	// Client is the X-Paddock-MCP-Client value of the session call, paddockctl/<version>.
	Client string
}

// Login signs the administrator in with the device authorization grant of the provider paddock-mcp (plan M14 §3.5
// item 25) and opens the MCP session at the api. It returns the session to save.
func Login(ctx context.Context, c *client.Client, o LoginOptions) (SessionFile, error) {
	cfg, err := fetchConfig(ctx, c)
	if err != nil {
		return SessionFile{}, err
	}
	oc := cfg.oauth()
	octx := context.WithValue(ctx, oauth2.HTTPClient, c.HTTPClient())
	da, err := oc.DeviceAuth(octx)
	if err != nil {
		return SessionFile{}, fmt.Errorf("device authorization: %w", tokenError(err))
	}
	verify := da.VerificationURIComplete
	if verify == "" {
		verify = da.VerificationURI
	}
	_, _ = fmt.Fprintf(o.Out, "Open %s and confirm the code %s\n", verify, da.UserCode)
	if o.Browser != nil {
		if err := o.Browser(verify); err != nil {
			_, _ = fmt.Fprintf(o.Out, "could not open a browser: %v\n", err)
		}
	}
	tok, err := oc.DeviceAccessToken(octx, da)
	var re *oauth2.RetrieveError
	switch {
	case err == nil:
	case errors.Is(err, context.DeadlineExceeded) && ctx.Err() == nil,
		errors.As(err, &re) && re.ErrorCode == "expired_token":
		return SessionFile{}, ErrLoginTimedOut
	case errors.As(err, &re) && re.ErrorCode == "access_denied":
		return SessionFile{}, errors.New("login denied in the browser")
	default:
		return SessionFile{}, fmt.Errorf("device login: %w", tokenError(err))
	}
	s := SessionFile{APIURL: c.Base(), Issuer: cfg.Issuer, ClientID: cfg.ClientID, Role: o.Role}
	if err := openSession(ctx, c, &s, tok, o.Client); err != nil {
		var p *client.Problem
		if errors.As(err, &p) && p.Status == http.StatusForbidden {
			return SessionFile{}, fmt.Errorf("sign-in refused: %s", firstNonEmpty(p.Detail, p.Code))
		}
		return SessionFile{}, err
	}
	return s, nil
}

// openSession presents a token pair to POST /api/auth/mcp/session and, on success, stores it in s.
func openSession(ctx context.Context, c *client.Client, s *SessionFile, tok *oauth2.Token, mcpClient string) error {
	idToken, _ := tok.Extra("id_token").(string)
	if idToken == "" || tok.AccessToken == "" || tok.RefreshToken == "" {
		return errors.New("the identity provider answered without an ID, access or refresh token")
	}
	role := s.Role
	if role == "" {
		role = RoleOrganization
	}
	body := map[string]string{"id_token": idToken, "access_token": tok.AccessToken, "role": role}
	resp, err := c.Send(ctx, client.Request{Method: http.MethodPost, Path: "/api/auth/mcp/session", Body: body,
		Header: http.Header{"X-Paddock-Mcp-Client": {mcpClient}}})
	if err != nil {
		return fmt.Errorf("MCP session: %w", err)
	}
	if p := resp.Problem(); p != nil {
		return p
	}
	s.Role, s.AccessToken, s.RefreshToken, s.ExpiresAt = role, tok.AccessToken, tok.RefreshToken, tok.Expiry.UTC()
	return nil
}

// Refresh renews the session: the refresh token buys a new token pair at Authentik, which is presented to
// POST /api/auth/mcp/session again with the session's role. The returned session must be saved even with an error:
// it carries a rotated refresh token, and a failed session call leaves it without a usable access token, so the
// next call refreshes again. Errors wrapping ErrLoginRequired cannot be healed by retrying.
func Refresh(ctx context.Context, c *client.Client, s SessionFile, mcpClient string) (SessionFile, error) {
	cfg, err := fetchConfig(ctx, c)
	if err != nil {
		return s, err
	}
	if cfg.Issuer != s.Issuer || cfg.ClientID != s.ClientID {
		return s, fmt.Errorf("the identity provider changed: %w", ErrLoginRequired)
	}
	octx := context.WithValue(ctx, oauth2.HTTPClient, c.HTTPClient())
	tok, err := cfg.oauth().TokenSource(octx, &oauth2.Token{RefreshToken: s.RefreshToken, Expiry: time.Unix(1, 0)}).Token()
	var re *oauth2.RetrieveError
	switch {
	case errors.As(err, &re) && refused(re):
		return s, fmt.Errorf("refresh refused (%s): %w", re.ErrorCode, ErrLoginRequired)
	case err != nil:
		return s, fmt.Errorf("refresh: %w", tokenError(err))
	}
	next := s
	next.RefreshToken, next.AccessToken, next.ExpiresAt = tok.RefreshToken, "", time.Time{}
	if err := openSession(ctx, c, &next, tok, mcpClient); err != nil {
		var p *client.Problem
		// A 503 after the api consumed the single-use marker is healed by the next refresh (PDK-436); 4xx answers
		// mean the binding or the account is gone.
		if errors.As(err, &p) && p.Status >= 400 && p.Status < 500 {
			return next, fmt.Errorf("session renewal refused (%s): %w", p.Code, ErrLoginRequired)
		}
		return next, err
	}
	return next, nil
}

// refused reports an OAuth refusal of the refresh token (RFC 6749 §5.2), as opposed to an outage of the identity
// provider or a proxy (5xx, 429), which the next renewal heals.
func refused(re *oauth2.RetrieveError) bool {
	if re.ErrorCode == "invalid_grant" || re.ErrorCode == "invalid_client" {
		return true
	}
	return re.Response != nil && (re.Response.StatusCode == http.StatusBadRequest || re.Response.StatusCode == http.StatusUnauthorized)
}

// Logout ends the session at the api and revokes the refresh token at Authentik (RFC 7009). Both are best effort:
// failures are reported on out, the caller removes the session file regardless.
func Logout(ctx context.Context, c *client.Client, s SessionFile, out io.Writer) {
	resp, err := c.Send(ctx, client.Request{Method: http.MethodPost, Path: "/api/auth/mcp/logout", Bearer: s.AccessToken})
	switch {
	case err != nil:
		_, _ = fmt.Fprintf(out, "warning: the api did not end the session: %v\n", transportError(err))
	case resp.Status == http.StatusUnauthorized:
		_, _ = fmt.Fprintln(out, "warning: the api did not end the session because its access token had expired; "+
			"its renewals end with the refresh token revoked below")
	case resp.Problem() != nil:
		_, _ = fmt.Fprintf(out, "warning: the api did not end the session: %v\n", resp.Problem())
	}
	if err := revoke(ctx, c, s); err != nil {
		_, _ = fmt.Fprintf(out, "warning: the refresh token was not revoked: %v\n", err)
	}
}

func revoke(ctx context.Context, c *client.Client, s SessionFile) error {
	cfg, err := fetchConfig(ctx, c)
	if err != nil {
		return transportError(err)
	}
	if cfg.RevocationEndpoint == "" {
		return errors.New("no revocation endpoint")
	}
	form := url.Values{"token": {s.RefreshToken}, "token_type_hint": {"refresh_token"}, "client_id": {cfg.ClientID}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.RevocationEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.HTTPClient().Do(req)
	if err != nil {
		return transportError(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("revocation endpoint answered %d", resp.StatusCode)
	}
	return nil
}

// Me is the part of GET /api/v1/me the sign-in summary shows.
type Me struct {
	Username     string `json:"username"`
	DisplayName  string `json:"display_name"`
	Role         string `json:"role"`
	Organization *struct {
		Slug string `json:"slug"`
	} `json:"organization"`
}

// Summary is "Signed in as <display> (<role>, <organization or platform>)" for the session's access token.
func Summary(ctx context.Context, c *client.Client, s SessionFile) (string, error) {
	resp, err := c.Send(ctx, client.Request{Method: http.MethodGet, Path: "/api/v1/me", Bearer: s.AccessToken})
	if err != nil {
		return "", transportError(err)
	}
	if p := resp.Problem(); p != nil {
		return "", p
	}
	var me Me
	if err := json.Unmarshal(resp.Body, &me); err != nil {
		return "", err
	}
	scope := "platform"
	if me.Organization != nil {
		scope = me.Organization.Slug
	}
	return fmt.Sprintf("Signed in as %s (%s, %s)", firstNonEmpty(me.DisplayName, me.Username), me.Role, scope), nil
}

// tokenError keeps the OAuth error code and drops the response body the oauth2 package quotes.
func tokenError(err error) error {
	var re *oauth2.RetrieveError
	if errors.As(err, &re) {
		code := re.ErrorCode
		if code == "" && re.Response != nil {
			code = http.StatusText(re.Response.StatusCode)
		}
		return fmt.Errorf("identity provider: %s", code)
	}
	return transportError(err)
}

// transportError drops the URL of a *url.Error: a query can carry tool arguments, which never reach a log.
func transportError(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return ue.Err
	}
	return err
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
