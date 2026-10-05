// Package authflow signs in to the Paddock portal headlessly: it drives the Authentik flow executor API
// (/api/v3/flows/executor/<flow>/) stage by stage with a cookie jar and follows the redirects to
// /api/auth/callback. The returned client holds the paddock_session cookie.
package authflow

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strings"
	"time"
)

// ErrDenied means Paddock rejected the login (redirect to /login-denied).
var ErrDenied = errors.New("authflow: login denied")

// Result is a finished login.
type Result struct {
	Client *http.Client // carries the session cookie; does not follow redirects
	// Final is the last URL Paddock redirected to (e.g. "/" or "/login-denied?reason=not_authorized").
	Final string
	// CallbackRequestID is the X-Request-Id of /api/auth/callback (the correlation ID of the admin.login event).
	CallbackRequestID string
}

// NewClient returns an HTTP client that trusts the Caddy root certificate (caRoot, PEM file), resolves every
// *.localhost name to 127.0.0.1 and never follows redirects.
func NewClient(caRoot string) (*http.Client, error) {
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if caRoot != "" {
		pem, err := os.ReadFile(caRoot) //nolint:gosec // test helper
		if err != nil {
			return nil, err
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("authflow: no certificate in %s", caRoot)
		}
	}
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err == nil && (host == "localhost" || strings.HasSuffix(host, ".localhost")) {
				addr = net.JoinHostPort("127.0.0.1", port)
			}
			return dialer.DialContext(ctx, network, addr)
		},
	}
	jar, _ := cookiejar.New(nil)
	return &http.Client{
		Transport: transport, Jar: jar, Timeout: 30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}, nil
}

// Login signs in username/password at adminURL ("https://admin.paddock.localhost:8443"). On a Paddock denial it
// returns the result together with ErrDenied.
func Login(ctx context.Context, client *http.Client, adminURL, username, password string) (*Result, error) {
	return follow(ctx, client, adminURL, strings.TrimRight(adminURL, "/")+"/api/auth/login?return_to=%2F", username, password, nil, false)
}

// StepUp runs a step-up authentication (plan M4a decision 6) for the session in client: /api/auth/stepup, the flow
// paddock-stepup with password and a TOTP code of totp, and the callback. Final is the portal URL the step-up
// returned to (with stepup=failed when Paddock refused it). The flow identifies the session's user from the login
// hint; dropHint removes it from the authorization request, as a user editing the URL could, so that username may
// be another user.
func StepUp(ctx context.Context, client *http.Client, adminURL, returnTo, username, password string, totp *TOTP, dropHint bool) (*Result, error) {
	start := strings.TrimRight(adminURL, "/") + "/api/auth/stepup?" + url.Values{"return_to": {returnTo}}.Encode()
	return follow(ctx, client, adminURL, start, username, password, totp, dropHint)
}

// follow follows the redirects from next through Authentik flows (run with the executor API) back into the portal.
func follow(ctx context.Context, client *http.Client, adminURL, next, username, password string, totp *TOTP, dropHint bool) (*Result, error) {
	admin, err := url.Parse(adminURL)
	if err != nil {
		return nil, err
	}
	callbackID := ""
	for hop := 0; hop < 30; hop++ {
		u, err := url.Parse(next)
		if err != nil {
			return nil, err
		}
		if q := u.Query(); dropHint && q.Has("login_hint") {
			q.Del("login_hint")
			u.RawQuery = q.Encode()
			next = u.String()
		}
		// Paddock redirected back into the portal: the login is finished.
		if u.Host == admin.Host && !strings.HasPrefix(u.Path, "/api/") {
			res := &Result{Client: client, Final: u.RequestURI(), CallbackRequestID: callbackID}
			if strings.HasPrefix(u.Path, "/login-denied") {
				return res, fmt.Errorf("%w: %s", ErrDenied, u.RawQuery)
			}
			return res, nil
		}
		// An Authentik flow page: run it through the executor API instead of the browser UI.
		if slug, ok := strings.CutPrefix(u.Path, "/if/flow/"); ok {
			slug = strings.TrimSuffix(slug, "/")
			next, err = runFlow(ctx, client, u, slug, username, password, totp)
			if err != nil {
				return nil, err
			}
			continue
		}
		resp, err := get(ctx, client, next)
		if err != nil {
			return nil, err
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
		_ = resp.Body.Close()
		if u.Host == admin.Host && (u.Path == "/api/auth/callback" || u.Path == "/api/auth/stepup/callback") {
			callbackID = resp.Header.Get("X-Request-Id")
		}
		if resp.StatusCode < 300 || resp.StatusCode >= 400 {
			return nil, fmt.Errorf("authflow: GET %s: HTTP %d: %s", next, resp.StatusCode, truncate(body))
		}
		loc, err := resp.Location()
		if err != nil {
			return nil, err
		}
		next = loc.String()
	}
	return nil, errors.New("authflow: too many redirects")
}

// WaitReady polls the Authentik flow executor of flow at authURL ("https://auth.paddock.localhost:8443") until
// it answers with the identification stage, every interval until timeout. A healthy Authentik container is not
// enough: the worker applies the blueprints that create the flow only after start-up. It only waits for
// readiness; it never submits credentials.
func WaitReady(ctx context.Context, client *http.Client, authURL, flow string, timeout, interval time.Duration) error {
	exec, err := url.Parse(strings.TrimRight(authURL, "/") + "/api/v3/flows/executor/" + flow + "/")
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	for {
		ch, err := executor(ctx, client, http.MethodGet, exec, nil)
		if err == nil && ch.Component == "ak-stage-identification" {
			return nil
		}
		if err == nil {
			err = fmt.Errorf("first stage is %q", ch.Component)
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("authflow: flow %s not ready after %s: %w", flow, timeout, err)
		case <-time.After(interval):
		}
	}
}

type challenge struct {
	Component string `json:"component"`
	To        string `json:"to"`
	Type      string `json:"type"`
	Error     string `json:"error_message"`
	Token     string `json:"token"`
	Raw       json.RawMessage
}

// runFlow executes one Authentik flow and returns the URL it redirects to. An MFA stage is answered with a code of
// totp (nil: MFA is not supported).
func runFlow(ctx context.Context, client *http.Client, page *url.URL, slug, username, password string, totp *TOTP) (string, error) {
	exec := &url.URL{Scheme: page.Scheme, Host: page.Host, Path: "/api/v3/flows/executor/" + slug + "/",
		RawQuery: url.Values{"query": {page.RawQuery}}.Encode()}
	ch, err := executor(ctx, client, http.MethodGet, exec, nil)
	if err != nil {
		return "", err
	}
	for step := 0; step < 10; step++ {
		var answer map[string]any
		switch ch.Component {
		case "xak-flow-redirect":
			to, err := page.Parse(ch.To)
			if err != nil {
				return "", err
			}
			return to.String(), nil
		case "ak-stage-identification":
			answer = map[string]any{"component": ch.Component, "uid_field": username}
		case "ak-stage-password":
			answer = map[string]any{"component": ch.Component, "password": password}
		case "ak-stage-consent":
			answer = map[string]any{"component": ch.Component, "token": ch.Token}
		case "ak-stage-authenticator-validate":
			if totp == nil {
				return "", fmt.Errorf("authflow: flow %s asks for MFA", slug)
			}
			if answer, err = validateAnswer(ch.Raw, totp); err != nil {
				return "", err
			}
			answer["component"] = ch.Component
		case "ak-stage-access-denied":
			return "", fmt.Errorf("authflow: Authentik denied access in flow %s: %s", slug, ch.Error)
		default:
			return "", fmt.Errorf("authflow: unsupported stage %q in flow %s: %s", ch.Component, slug, truncate(ch.Raw))
		}
		if ch, err = executor(ctx, client, http.MethodPost, exec, answer); err != nil {
			return "", err
		}
	}
	return "", fmt.Errorf("authflow: flow %s did not finish", slug)
}

func executor(ctx context.Context, client *http.Client, method string, u *url.URL, body any) (challenge, error) {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return challenge{}, err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), rd)
	if err != nil {
		return challenge{}, err
	}
	req.Header.Set("Accept", "application/json")
	// Django's CSRF check on requests of an authenticated session wants a same-origin Referer, as a browser sends it.
	req.Header.Set("Referer", u.Scheme+"://"+u.Host+"/")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for _, c := range client.Jar.Cookies(u) {
		if c.Name == "authentik_csrf" {
			req.Header.Set("X-authentik-CSRF", c.Value)
		}
	}
	resp, err := client.Do(req)
	if err != nil {
		return challenge{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	// The executor answers a POST with a redirect to the GET of the same flow.
	if resp.StatusCode == http.StatusFound {
		loc, err := resp.Location()
		if err != nil {
			return challenge{}, err
		}
		return executor(ctx, client, http.MethodGet, loc, nil)
	}
	if resp.StatusCode != http.StatusOK {
		return challenge{}, fmt.Errorf("authflow: %s %s: HTTP %d: %s", method, u.Path, resp.StatusCode, truncate(data))
	}
	var ch challenge
	if err := json.Unmarshal(data, &ch); err != nil {
		return challenge{}, fmt.Errorf("authflow: %s: %w", truncate(data), err)
	}
	ch.Raw = data
	return ch, nil
}

func get(ctx context.Context, client *http.Client, u string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	return client.Do(req)
}

func truncate(b []byte) string {
	if len(b) > 500 {
		return string(b[:500]) + "…"
	}
	return string(b)
}
