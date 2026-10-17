package admin

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/google/uuid"
	"golang.org/x/oauth2"

	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/domain/organization"
	"github.com/phischl/paddock-mdm/server/internal/platform/httpx"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/problem"
	"github.com/phischl/paddock-mdm/server/internal/sessions"
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

// discardTimeout bounds the deletion of the session record of a failed login.
const discardTimeout = 5 * time.Second

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
	sessions SessionStore
	roles    StepUpAccounts
	// loginMFAOptional accepts a portal ID token without "mfa" in amr (development only, PADDOCK_LOGIN_MFA_OPTIONAL).
	loginMFAOptional bool
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
	// prompt=login: an existing Authentik session must never satisfy the portal sign-in; the provider's own flow with
	// its second factor runs every time (plan M8x decision 1).
	http.Redirect(w, r, oauth.AuthCodeURL(st.State, oidc.Nonce(st.Nonce), oauth2.S256ChallengeOption(st.Verifier),
		oauth2.SetAuthURLParam("prompt", "login")), http.StatusFound)
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
	AMR               []string `json:"amr"`
}

// hasMFA reports whether the authentication methods name a second factor.
func (c idClaims) hasMFA() bool {
	return slices.Contains(c.AMR, "mfa")
}

// errLoginFailed is the audit error code of logins that fail after the state check (code exchange, ID token).
var errLoginFailed = &problem.Error{Code: app.ReasonLoginFailed, Status: http.StatusBadGateway}

// errMFARequired is the audit error code of a login whose ID token carried no second factor. It also wraps
// problem.Forbidden, so that the runner records the refusal as denied rather than failed.
var errMFARequired = fmt.Errorf("%w (%w)", &problem.Error{Code: app.ReasonMFARequired, Status: http.StatusForbidden},
	problem.Forbidden)

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
		b.accounts.RecordLoginFailure(ctx, ip, "", app.ReasonLoginFailed, errLoginFailed)
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
		b.accounts.RecordLoginFailure(ctx, ip, "", app.ReasonLoginFailed, errLoginFailed)
		denied(w, r, app.ReasonLoginFailed)
		return
	}
	username := claims.PreferredUsername
	if username == "" {
		username = claims.Email
	}
	if !b.loginMFAOptional && !claims.hasMFA() {
		slog.WarnContext(ctx, "ID token without a second factor refused")
		b.accounts.RecordLoginFailure(ctx, ip, username, app.ReasonMFARequired, errMFARequired)
		denied(w, r, app.ReasonMFARequired)
		return
	}
	res := organization.ResolveRole(claims.Groups)
	now := b.now()
	sid := sessions.NewID()
	var opened uuid.UUID // the account whose session record exists, once it does
	openSession := func(ctx context.Context, p principal.Principal) error {
		if _, err := b.sessions.Create(ctx, sid, sessions.Record{AccountID: p.ID, Kind: string(p.Kind), Role: string(p.Role),
			Org: p.OrganizationID, CreatedAt: now.Unix()}, SessionAbsolute); err != nil {
			return err
		}
		opened = p.ID
		return nil
	}
	// A record whose cookie never reaches the browser is removed, so that no revocation counts or records it later.
	discard := func() {
		if opened == uuid.Nil {
			return
		}
		// The request may be ending (a client that gave up); the cleanup does not depend on it.
		dctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), discardTimeout)
		defer cancel()
		if err := b.sessions.Delete(dctx, sid, opened); err != nil {
			slog.WarnContext(ctx, "session record of a failed login not deleted", "error", err)
		}
	}
	result, err := b.accounts.Login(ctx,
		app.LoginIdentity{Subject: claims.Subject, Username: username, Name: claims.Name, IP: ip, OpenSession: openSession},
		app.LoginRole{Platform: res.Platform, Slug: res.Slug, Role: res.Role, Denied: res.Denied, Slugs: res.Slugs})
	if errors.Is(err, problem.Forbidden) {
		discard()
		denied(w, r, app.ReasonNotAuthorized)
		return
	}
	if err != nil {
		discard()
		slog.ErrorContext(ctx, "login failed", "error", err)
		denied(w, r, app.ReasonLoginFailed)
		return
	}
	p := result.Principal
	value, err := b.keys.Seal(SessionCookie, NewSession(p, sid, result.Locale, now))
	if err != nil {
		discard()
		slog.ErrorContext(ctx, "session cookie", "error", err)
		denied(w, r, app.ReasonLoginFailed)
		return
	}
	http.SetCookie(w, sessionCookie(value, int(SessionAbsolute.Seconds())))
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, st.ReturnTo, http.StatusFound)
}

// logout ends the session on the server, clears the cookie and returns the Authentik end-session URL. It reads the
// cookie itself, so it also signs the browser out while the session store is unreachable; the record then expires on
// its own (plan M8s decision 15).
func (b *bff) logout(publicURL string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var sess Session
		if c, err := r.Cookie(SessionCookie); err == nil && b.keys.Open(SessionCookie, c.Value, &sess) == nil && sess.SID != "" {
			if err := b.sessions.Delete(r.Context(), sess.SID, sess.PID); err != nil {
				slog.WarnContext(r.Context(), "session record not deleted at logout", "error", err)
			}
		}
		http.SetCookie(w, sessionCookie("", -1))
		_, _, endSession := b.oidc.snapshot()
		target := publicURL + "/"
		if endSession != "" {
			target = endSession + "?" + url.Values{"post_logout_redirect_uri": {publicURL + "/"}}.Encode()
		}
		writeJSON(w, http.StatusOK, map[string]string{"end_session_url": target})
	}
}

// sessionLive requires the server-side record of sess, of the current generation and with the cookie's account, role
// and organization (plan M8s decision 14). Otherwise it answers: 503 session_store_unavailable while the store is
// unreachable, keeping the cookie (the session is valid again once the store answers), or 401 with the cookie cleared.
func (b *bff) sessionLive(w http.ResponseWriter, r *http.Request, sess Session) bool {
	rec, gen, found, err := b.sessions.Get(r.Context(), sess.SID)
	if err != nil {
		slog.ErrorContext(r.Context(), "session store", "error", err)
		httpx.WriteProblem(w, r, problem.SessionStoreUnavailable)
		return false
	}
	if !recordMatches(rec, gen, found, sess) {
		http.SetCookie(w, sessionCookie("", -1))
		httpx.WriteProblem(w, r, problem.Unauthenticated)
		return false
	}
	return true
}

// recordMatches reports whether the record of a session exists, is of the current generation and belongs to the
// cookie's account, role and organization.
func recordMatches(rec sessions.Record, gen int64, found bool, sess Session) bool {
	return found && rec.Gen >= gen && rec.AccountID == sess.PID && rec.Role == sess.Role && rec.Org == sess.Org
}
