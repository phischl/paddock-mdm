package admin

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/platform/httpx"
	"github.com/phischl/paddock-mdm/server/internal/problem"
)

// OIDCConfig configures the portal's OIDC client (Authentik application paddock-portal).
type OIDCConfig struct {
	Issuer       string
	ClientID     string
	ClientSecret string
	PublicURL    string // https://admin.<domain>[:port]
	// RedirectPath is the path of the redirect URI below PublicURL; default /api/auth/callback.
	RedirectPath string
}

// OIDC holds the discovered provider. Discovery is retried in the background until Authentik answers.
type OIDC struct {
	cfg OIDCConfig

	mu         sync.RWMutex
	oauth      *oauth2.Config
	verifier   *oidc.IDTokenVerifier
	endSession string
}

// NewOIDC creates the client; call Discover to connect.
func NewOIDC(cfg OIDCConfig) *OIDC { return &OIDC{cfg: cfg} }

// Ready reports whether discovery succeeded.
func (o *OIDC) Ready() bool {
	o.mu.RLock()
	defer o.mu.RUnlock()
	return o.oauth != nil
}

// Discover retries provider discovery every 5 s until it succeeds or ctx ends.
func (o *OIDC) Discover(ctx context.Context) {
	for {
		err := o.discoverOnce(ctx)
		if err == nil {
			slog.InfoContext(ctx, "oidc provider discovered", "issuer", o.cfg.Issuer)
			return
		}
		slog.WarnContext(ctx, "oidc discovery failed; retrying", "issuer", o.cfg.Issuer, "error", err)
		select {
		case <-ctx.Done():
			return
		case <-time.After(5 * time.Second):
		}
	}
}

func (o *OIDC) discoverOnce(ctx context.Context) error {
	provider, err := oidc.NewProvider(ctx, o.cfg.Issuer)
	if err != nil {
		return err
	}
	var claims struct {
		EndSession string `json:"end_session_endpoint"`
	}
	if err := provider.Claims(&claims); err != nil {
		return err
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	o.oauth = &oauth2.Config{
		ClientID: o.cfg.ClientID, ClientSecret: o.cfg.ClientSecret, Endpoint: provider.Endpoint(),
		RedirectURL: o.cfg.PublicURL + o.redirectPath(),
		Scopes:      []string{oidc.ScopeOpenID, "profile", "email", "groups"},
	}
	o.verifier = provider.Verifier(&oidc.Config{ClientID: o.cfg.ClientID})
	o.endSession = claims.EndSession
	return nil
}

func (o *OIDC) redirectPath() string {
	if o.cfg.RedirectPath == "" {
		return "/api/auth/callback"
	}
	return o.cfg.RedirectPath
}

func (o *OIDC) snapshot() (*oauth2.Config, *oidc.IDTokenVerifier, string) {
	o.mu.RLock()
	defer o.mu.RUnlock()
	return o.oauth, o.verifier, o.endSession
}

// loginState is the payload of the paddock_login cookie.
type loginState struct {
	State    string `json:"state"`
	Verifier string `json:"verifier"`
	Nonce    string `json:"nonce"`
	ReturnTo string `json:"return_to"`
	Exp      int64  `json:"exp"`
}

// bff implements /api/auth/*.
type bff struct {
	oidc     *OIDC
	stepUp   *OIDC // provider paddock-portal-stepup (plan M4a decision 6)
	keys     *Keyring
	accounts *app.Accounts
	now      func() time.Time
	// maxAuthAge is the oldest login a step-up callback accepts.
	maxAuthAge time.Duration
	// tokens keeps the raw step-up ID token for tokenTTL, the step-up window.
	tokens   StepUpTokenStore
	tokenTTL time.Duration
}

func randomToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// login starts the authorization code flow with PKCE (S256), state and nonce.
func (b *bff) login(w http.ResponseWriter, r *http.Request) {
	returnTo := r.URL.Query().Get("return_to")
	if returnTo == "" {
		returnTo = "/"
	}
	if !ValidReturnTo(returnTo) {
		httpx.WriteProblem(w, r, problem.InvalidRequest.WithDetail("return_to must be a relative path"))
		return
	}
	oauth, _, _ := b.oidc.snapshot()
	if oauth == nil {
		httpx.WriteProblem(w, r, problem.UpstreamUnavailable.WithDetail("identity provider not reachable"))
		return
	}
	st := loginState{
		State: randomToken(), Verifier: oauth2.GenerateVerifier(), Nonce: randomToken(), ReturnTo: returnTo,
		Exp: b.now().Add(LoginLifetime).Unix(),
	}
	value, err := b.keys.Seal(LoginCookie, st)
	if err != nil {
		httpx.WriteProblem(w, r, err)
		return
	}
	http.SetCookie(w, loginCookie(value, int(LoginLifetime.Seconds())))
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, oauth.AuthCodeURL(st.State, oidc.Nonce(st.Nonce), oauth2.S256ChallengeOption(st.Verifier)), http.StatusFound)
}

func denied(w http.ResponseWriter, r *http.Request, reason string) {
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, "/login-denied?reason="+url.QueryEscape(reason), http.StatusFound)
}

type idClaims struct {
	Subject           string   `json:"sub"`
	PreferredUsername string   `json:"preferred_username"`
	Name              string   `json:"name"`
	Email             string   `json:"email"`
	Groups            []string `json:"groups"`
}

// errLoginFailed is the audit error code of logins that fail after the state check (code exchange, ID token).
var errLoginFailed = &problem.Error{Code: app.ReasonLoginFailed, Status: http.StatusBadGateway}

// callback completes the login: state check, code exchange with PKCE, ID token verification (issuer, audience,
// nonce, expiry), role resolution from the groups claim, admin.login audit event and session cookie.
func (b *bff) callback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	http.SetCookie(w, loginCookie("", -1))
	var st loginState
	c, err := r.Cookie(LoginCookie)
	if err == nil {
		err = b.keys.Open(LoginCookie, c.Value, &st)
	}
	q := r.URL.Query()
	switch {
	case err != nil || st.State == "" || b.now().Unix() > st.Exp:
		slog.WarnContext(ctx, "login callback without valid login cookie")
		denied(w, r, app.ReasonLoginFailed)
		return
	case q.Get("state") != st.State:
		slog.WarnContext(ctx, "login callback with mismatching state")
		denied(w, r, app.ReasonLoginFailed)
		return
	case q.Get("error") != "" || q.Get("code") == "":
		slog.InfoContext(ctx, "login aborted at the identity provider", "error", q.Get("error"))
		denied(w, r, app.ReasonLoginFailed)
		return
	}
	oauth, verifier, _ := b.oidc.snapshot()
	if oauth == nil {
		denied(w, r, app.ReasonLoginFailed)
		return
	}
	ip := httpx.ClientIP(r)
	token, err := oauth.Exchange(ctx, q.Get("code"), oauth2.VerifierOption(st.Verifier))
	if err != nil {
		slog.WarnContext(ctx, "code exchange failed", "error", err)
		b.accounts.RecordLoginFailure(ctx, ip, app.ReasonLoginFailed, errLoginFailed)
		denied(w, r, app.ReasonLoginFailed)
		return
	}
	raw, _ := token.Extra("id_token").(string)
	idt, err := verifier.Verify(ctx, raw)
	if err == nil && idt.Nonce != st.Nonce {
		err = errors.New("nonce mismatch")
	}
	var claims idClaims
	if err == nil {
		err = idt.Claims(&claims)
	}
	if err != nil || claims.Subject == "" {
		slog.WarnContext(ctx, "ID token rejected", "error", err)
		b.accounts.RecordLoginFailure(ctx, ip, app.ReasonLoginFailed, errLoginFailed)
		denied(w, r, app.ReasonLoginFailed)
		return
	}
	username := claims.PreferredUsername
	if username == "" {
		username = claims.Email
	}
	res := ResolveRole(claims.Groups)
	result, err := b.accounts.Login(ctx,
		app.LoginIdentity{Subject: claims.Subject, Username: username, Name: claims.Name, IP: ip},
		app.LoginRole{Platform: res.Platform, Slug: res.Slug, Role: res.Role, Denied: res.Denied, Slugs: res.Slugs})
	if errors.Is(err, problem.Forbidden) {
		denied(w, r, app.ReasonNotAuthorized)
		return
	}
	if err != nil {
		slog.ErrorContext(ctx, "login failed", "error", err)
		denied(w, r, app.ReasonLoginFailed)
		return
	}
	value, err := b.keys.Seal(SessionCookie, NewSession(result.Principal, result.Locale, b.now()))
	if err != nil {
		slog.ErrorContext(ctx, "session cookie", "error", err)
		denied(w, r, app.ReasonLoginFailed)
		return
	}
	http.SetCookie(w, sessionCookie(value, int(SessionAbsolute.Seconds())))
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, st.ReturnTo, http.StatusFound)
}

// logout clears the session and returns the Authentik end-session URL.
func (b *bff) logout(publicURL string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, sessionCookie("", -1))
		_, _, endSession := b.oidc.snapshot()
		target := publicURL + "/"
		if endSession != "" {
			target = endSession + "?" + url.Values{"post_logout_redirect_uri": {publicURL + "/"}}.Encode()
		}
		writeJSON(w, http.StatusOK, map[string]string{"end_session_url": target})
	}
}
