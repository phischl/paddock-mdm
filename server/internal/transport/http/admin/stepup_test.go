package admin_test

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/domain/organization"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/transport/http/admin"
)

// fakeStepUpIdP is an OIDC provider that issues one ID token per code with the claims the test sets.
type fakeStepUpIdP struct {
	*httptest.Server
	key *rsa.PrivateKey

	mu     sync.Mutex
	claims map[string]any // claims of the next token; nonce is filled from the authorization request
	nonce  string
	// unavailable is the number of token requests still answered with Authentik's 503 "authentik starting".
	unavailable int
	// tokenCodes are the codes of the token requests received, in order.
	tokenCodes []string
}

func newFakeStepUpIdP(t *testing.T) *fakeStepUpIdP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeStepUpIdP{key: key}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer": f.URL, "authorization_endpoint": f.URL + "/authorize", "token_endpoint": f.URL + "/token",
			"jwks_uri": f.URL + "/jwks", "id_token_signing_alg_values_supported": []string{"RS256"},
			"device_authorization_endpoint": f.URL + "/device", "revocation_endpoint": f.URL + "/revoke",
		})
	})
	mux.HandleFunc("GET /jwks", func(w http.ResponseWriter, _ *http.Request) {
		b64 := base64.RawURLEncoding.EncodeToString
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
			"kty": "RSA", "alg": "RS256", "use": "sig", "kid": "k1",
			"n": b64(key.N.Bytes()), "e": b64(big.NewInt(int64(key.E)).Bytes()),
		}}})
	})
	mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.tokenCodes = append(f.tokenCodes, r.FormValue("code"))
		if f.unavailable > 0 {
			f.unavailable--
			f.mu.Unlock()
			http.Error(w, "authentik starting", http.StatusServiceUnavailable)
			return
		}
		claims := map[string]any{"iss": f.URL, "aud": "paddock-portal-stepup", "exp": time.Now().Add(time.Minute).Unix(),
			"iat": time.Now().Unix(), "nonce": f.nonce}
		for k, v := range f.claims {
			claims[k] = v
		}
		f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "at", "token_type": "Bearer", "expires_in": 60,
			"id_token": f.sign(t, claims)})
	})
	f.Server = httptest.NewServer(mux)
	t.Cleanup(f.Close)
	return f
}

func (f *fakeStepUpIdP) sign(t *testing.T, claims map[string]any) string {
	b64 := base64.RawURLEncoding.EncodeToString
	header, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT", "kid": "k1"})
	payload, _ := json.Marshal(claims)
	signed := b64(header) + "." + b64(payload)
	sum := sha256.Sum256([]byte(signed))
	sig, err := rsa.SignPKCS1v15(rand.Reader, f.key, crypto.SHA256, sum[:])
	if err != nil {
		t.Error(err)
	}
	return signed + "." + b64(sig)
}

// fakeStepUpAccounts resolves the slug acme to the organization of the step-up world's session.
type fakeStepUpAccounts struct{ org uuid.UUID }

func (f *fakeStepUpAccounts) OrganizationID(_ context.Context, slug string) (uuid.UUID, error) {
	if slug == "acme" {
		return f.org, nil
	}
	return uuid.Nil, nil
}

func (f *fakeStepUpAccounts) StepUpMismatch(context.Context, uuid.UUID, uuid.UUID, organization.RoleResolution) error {
	return nil
}

type stepUpWorld struct {
	t       *testing.T
	idp     *fakeStepUpIdP
	tokens  *stepUpProofs
	keys    *admin.Keyring
	handler http.Handler
	session admin.Session
	maxAge  string // max_age the authorization request must carry
	// sessions holds the server-side record of session.
	sessions *fakeSessions
	// onAuthorize runs while the browser is at the provider, between the step-up start and the callback.
	onAuthorize func()
	// clock is Paddock's time (Deps.Now); onAuthorize may advance it.
	clock time.Time
}

func newStepUpWorld(t *testing.T) *stepUpWorld {
	t.Helper()
	return newStepUpWorldWith(t, 0)
}

// newStepUpWorldWith is newStepUpWorld with Deps.StepUpMaxAuthAge (0: the production value).
func newStepUpWorldWith(t *testing.T, maxAuthAge time.Duration) *stepUpWorld {
	t.Helper()
	return newStepUpWorldFor(t, maxAuthAge, stepUpAlice(), nil)
}

// stepUpAlice is the org_admin whose session steps up.
func stepUpAlice() principal.Principal {
	return principal.Principal{Kind: principal.KindAdmin, ID: uuid.Must(uuid.NewV7()), Subject: "sub-alice",
		Display: "alice@acme.test", Role: principal.RoleOrgAdmin, OrganizationID: uuid.Must(uuid.NewV7())}
}

// totpClass is the authenticator class of an Authentik TOTP device.
const totpClass = "authentik_stages_authenticator_totp.totpdevice"

// newStepUpWorldFor is a step-up world for the session of p whose role check uses roles (nil: a fake that resolves
// acme to the session's organization); deps adjust the handler's dependencies.
func newStepUpWorldFor(t *testing.T, maxAuthAge time.Duration, p principal.Principal, roles admin.StepUpAccounts, deps ...func(*admin.Deps)) *stepUpWorld {
	t.Helper()
	idp := newFakeStepUpIdP(t)
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	keys := &admin.Keyring{}
	if err := keys.SetKeys(base64.StdEncoding.EncodeToString(key), ""); err != nil {
		t.Fatal(err)
	}
	stepUp := admin.NewOIDC(admin.OIDCConfig{Issuer: idp.URL, ClientID: "paddock-portal-stepup", ClientSecret: "s",
		PublicURL: "https://admin.test", RedirectPath: "/api/auth/stepup/callback"})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	stepUp.Discover(ctx)
	if !stepUp.Ready() {
		t.Fatal("discovery failed")
	}
	static, err := admin.NewStaticHandler(fstest.MapFS{"index.html": {Data: []byte(testIndex)}})
	if err != nil {
		t.Fatal(err)
	}
	maxAge := "20"
	if maxAuthAge > 0 {
		maxAge = strconv.Itoa(int(maxAuthAge.Seconds()))
	}
	tokens := newStepUpProofs()
	if roles == nil {
		roles = &fakeStepUpAccounts{org: p.OrganizationID}
	}
	sessions := newFakeSessions()
	sessions.records["sid-alice"] = sessionsRecord(p)
	w := &stepUpWorld{t: t, idp: idp, keys: keys, maxAge: maxAge, tokens: tokens, sessions: sessions, clock: time.Now()}
	w.session = admin.NewSession(p, "sid-alice", "en", w.clock)
	d := admin.Deps{Static: static, Keys: keys, OIDC: admin.NewOIDC(admin.OIDCConfig{}), StepUp: stepUp,
		StepUpTokens: tokens, StepUpAccounts: roles, Sessions: sessions, PublicURL: "https://admin.test",
		StepUpMaxAuthAge: maxAuthAge, Now: func() time.Time { return w.clock }}
	for _, f := range deps {
		f(&d)
	}
	w.handler = admin.NewHandler(d)
	return w
}

func (w *stepUpWorld) serve(path string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "https://admin.test"+path, nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	w.handler.ServeHTTP(rec, req)
	return rec
}

func cookieOf(rec *httptest.ResponseRecorder, name string) *http.Cookie {
	for _, c := range rec.Result().Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// stepUp runs a step-up with the claims the provider puts into the ID token and returns the callback response.
func (w *stepUpWorld) stepUp(claims map[string]any) *httptest.ResponseRecorder {
	w.t.Helper()
	value, err := w.keys.Seal(admin.SessionCookie, w.session)
	if err != nil {
		w.t.Fatal(err)
	}
	start := w.serve("/api/auth/stepup?return_to=%2Fdevices%2Fx", &http.Cookie{Name: admin.SessionCookie, Value: value})
	if start.Code != http.StatusFound {
		w.t.Fatalf("start: %d %s", start.Code, start.Body)
	}
	loc, _ := url.Parse(start.Header().Get("Location"))
	q := loc.Query()
	if !strings.HasPrefix(loc.String(), w.idp.URL+"/authorize") || q.Get("prompt") != "login" || q.Get("max_age") != w.maxAge ||
		q.Get("login_hint") != "alice@acme.test" || q.Get("client_id") != "paddock-portal-stepup" ||
		q.Get("redirect_uri") != "https://admin.test/api/auth/stepup/callback" || q.Get("code_challenge_method") != "S256" {
		w.t.Fatalf("authorization request %s", loc)
	}
	state := cookieOf(start, admin.StepUpCookie)
	if state == nil || state.SameSite != http.SameSiteLaxMode || !state.HttpOnly || !state.Secure {
		w.t.Fatalf("step-up cookie %+v", state)
	}
	w.idp.mu.Lock()
	w.idp.claims, w.idp.nonce = claims, q.Get("nonce")
	w.idp.mu.Unlock()
	if w.onAuthorize != nil {
		w.onAuthorize()
	}
	// Authentik redirects back cross-site: the SameSite=Strict session cookie is not sent.
	return w.serve("/api/auth/stepup/callback?code=c&state="+url.QueryEscape(q.Get("state")), state)
}

func TestStepUp(t *testing.T) {
	// good are the claims of a step-up that authenticated at the step-up's start (Paddock's clock in w).
	good := func(w *stepUpWorld) map[string]any {
		return map[string]any{"sub": "sub-alice", "auth_time": w.clock.Unix(), "amr": []string{"pwd", "mfa"}, "jti": "jti-1",
			"groups": []string{"paddock.acme", "paddock.acme.admins"}, "paddock_mfa_classes": []string{admin.StepUpWebAuthnClass}}
	}
	with := func(w *stepUpWorld, k string, v any) map[string]any {
		c := good(w)
		c[k] = v
		return c
	}
	t.Run("fresh step-up of the session's user", func(t *testing.T) {
		w := newStepUpWorld(t)
		res := w.stepUp(good(w))
		if res.Code != http.StatusFound || res.Header().Get("Location") != "/devices/x" {
			t.Fatalf("callback: %d %s", res.Code, res.Header().Get("Location"))
		}
		c := cookieOf(res, admin.SessionCookie)
		if c == nil || c.SameSite != http.SameSiteStrictMode {
			t.Fatalf("session cookie %+v", c)
		}
		var sess admin.Session
		if err := w.keys.Open(admin.SessionCookie, c.Value, &sess); err != nil {
			t.Fatal(err)
		}
		if sess.PID != w.session.PID || sess.StepUpJTI != "jti-1" || time.Since(time.Unix(sess.StepUpAt, 0)) > 5*time.Second ||
			len(sess.StepUpClasses) != 1 || sess.StepUpClasses[0] != admin.StepUpWebAuthnClass ||
			sess.Principal("").StepUpAt.IsZero() || sess.Principal("").StepUpJTI != "jti-1" {
			t.Fatalf("session %+v", sess)
		}
		// The raw ID token is kept for the escrow-reader under its jti (plan M4b.1 decision 7).
		if raw, ok, _ := w.tokens.Get(context.Background(), "jti-1"); !ok || strings.Count(raw, ".") != 2 {
			t.Fatalf("kept step-up token %q, %v", raw, ok)
		}
	})
	for name, claims := range map[string]func(w *stepUpWorld) map[string]any{
		"another user":       func(w *stepUpWorld) map[string]any { return with(w, "sub", "sub-carol") },
		"old authentication": func(w *stepUpWorld) map[string]any { return with(w, "auth_time", w.clock.Unix()-21) },
		"no auth_time":       func(w *stepUpWorld) map[string]any { return with(w, "auth_time", 0) },
		"without MFA":        func(w *stepUpWorld) map[string]any { return with(w, "amr", []string{"pwd"}) },
		"without jti":        func(w *stepUpWorld) map[string]any { return with(w, "jti", "") },
		"without groups":     func(w *stepUpWorld) map[string]any { return with(w, "groups", nil) },
		// The factor is checked by Paddock, not only by Authentik's stage (plan M8f decision 8): a token without the
		// claim (mapping missing), with an empty list or with TOTP only is refused.
		"without authenticator classes": func(w *stepUpWorld) map[string]any { return with(w, "paddock_mfa_classes", nil) },
		"with no authenticator class":   func(w *stepUpWorld) map[string]any { return with(w, "paddock_mfa_classes", []string{}) },
		"with TOTP only":                func(w *stepUpWorld) map[string]any { return with(w, "paddock_mfa_classes", []string{totpClass}) },
		// The login event the session started from, one second before the step-up: what Authentik sends when it skips
		// the step-up flow (stepup.go, checkStepUp).
		"authentication before the step-up": func(w *stepUpWorld) map[string]any { return with(w, "auth_time", w.clock.Unix()-1) },
	} {
		t.Run(name, func(t *testing.T) {
			w := newStepUpWorld(t)
			res := w.stepUp(claims(w))
			if res.Code != http.StatusFound || res.Header().Get("Location") != "/devices/x?stepup=failed" {
				t.Fatalf("callback: %d %s", res.Code, res.Header().Get("Location"))
			}
			if c := cookieOf(res, admin.SessionCookie); c != nil {
				t.Fatalf("session issued: %+v", c)
			}
		})
	}
	// Authentik's front server answers 503 "authentik starting" for a moment while its backend is not ready; the
	// still unused code is exchanged again (regression test of a CI failure).
	t.Run("token endpoint unavailable for a moment", func(t *testing.T) {
		w := newStepUpWorld(t)
		w.idp.mu.Lock()
		w.idp.unavailable = 1
		w.idp.mu.Unlock()
		res := w.stepUp(good(w))
		if res.Code != http.StatusFound || res.Header().Get("Location") != "/devices/x" || cookieOf(res, admin.SessionCookie) == nil {
			t.Fatalf("callback: %d %s", res.Code, res.Header().Get("Location"))
		}
		w.idp.mu.Lock()
		defer w.idp.mu.Unlock()
		if len(w.idp.tokenCodes) != 2 {
			t.Fatalf("token requests %q, want 2", w.idp.tokenCodes)
		}
	})
	t.Run("WebAuthn and TOTP", func(t *testing.T) {
		w := newStepUpWorld(t)
		res := w.stepUp(with(w, "paddock_mfa_classes", []string{totpClass, admin.StepUpWebAuthnClass}))
		if res.Header().Get("Location") != "/devices/x" || cookieOf(res, admin.SessionCookie) == nil {
			t.Fatalf("callback: %s", res.Header().Get("Location"))
		}
	})
	t.Run("development class", func(t *testing.T) {
		// PADDOCK_STEPUP_MFA_CLASS lets the development users step up with TOTP; WebAuthn alone is then refused.
		dev := func(d *admin.Deps) { d.StepUpMFAClass = totpClass }
		w := newStepUpWorldFor(t, 0, stepUpAlice(), nil, dev)
		if res := w.stepUp(with(w, "paddock_mfa_classes", []string{totpClass})); res.Header().Get("Location") != "/devices/x" {
			t.Fatalf("TOTP with the development class: %s", res.Header().Get("Location"))
		}
		w = newStepUpWorldFor(t, 0, stepUpAlice(), nil, dev)
		if res := w.stepUp(good(w)); res.Header().Get("Location") != "/devices/x?stepup=failed" {
			t.Fatalf("WebAuthn with the development class: %s", res.Header().Get("Location"))
		}
	})
	t.Run("authentication during the step-up", func(t *testing.T) {
		w := newStepUpWorld(t)
		start := w.clock
		w.onAuthorize = func() { w.clock = w.clock.Add(3 * time.Second) }
		claims := with(w, "auth_time", start.Add(2*time.Second).Unix())
		if res := w.stepUp(claims); res.Header().Get("Location") != "/devices/x" || cookieOf(res, admin.SessionCookie) == nil {
			t.Fatalf("authentication 2 s after the start: %s", res.Header().Get("Location"))
		}
	})
	t.Run("step-up cookie without a start time", func(t *testing.T) {
		// A cookie sealed before the start time existed (or without it) fails closed, also with a fresh token.
		w := newStepUpWorld(t)
		value, err := w.keys.Seal(admin.SessionCookie, w.session)
		if err != nil {
			t.Fatal(err)
		}
		start := w.serve("/api/auth/stepup?return_to=%2Fdevices%2Fx", &http.Cookie{Name: admin.SessionCookie, Value: value})
		state := cookieOf(start, admin.StepUpCookie)
		if start.Code != http.StatusFound || state == nil {
			t.Fatalf("start: %d", start.Code)
		}
		var st map[string]any
		if err := w.keys.Open(admin.StepUpCookie, state.Value, &st); err != nil {
			t.Fatal(err)
		}
		if _, ok := st["started"]; !ok {
			t.Fatalf("step-up cookie without started: %v", st)
		}
		delete(st, "started")
		if state.Value, err = w.keys.Seal(admin.StepUpCookie, st); err != nil {
			t.Fatal(err)
		}
		loc, _ := url.Parse(start.Header().Get("Location"))
		w.idp.mu.Lock()
		w.idp.claims, w.idp.nonce = good(w), loc.Query().Get("nonce")
		w.idp.mu.Unlock()
		res := w.serve("/api/auth/stepup/callback?code=c&state="+url.QueryEscape(loc.Query().Get("state")), state)
		if res.Header().Get("Location") != "/devices/x?stepup=failed" || cookieOf(res, admin.SessionCookie) != nil {
			t.Fatalf("callback: %d %s", res.Code, res.Header().Get("Location"))
		}
	})
	t.Run("production maximum auth age", func(t *testing.T) {
		// max_age stays below the 30 s window of the escrow-reader and the revocation-issuer (ADR 0034 amendment
		// 2026-10-18), so a repeated step-up is never refused for being too early.
		if admin.StepUpMaxAuthAge != 20*time.Second {
			t.Fatalf("StepUpMaxAuthAge = %s", admin.StepUpMaxAuthAge)
		}
		w := newStepUpWorld(t)
		value, err := w.keys.Seal(admin.SessionCookie, w.session)
		if err != nil {
			t.Fatal(err)
		}
		start := w.serve("/api/auth/stepup?return_to=%2F", &http.Cookie{Name: admin.SessionCookie, Value: value})
		loc, _ := url.Parse(start.Header().Get("Location"))
		if start.Code != http.StatusFound || loc.Query().Get("max_age") != "20" {
			t.Fatalf("start: %d %s", start.Code, loc)
		}
		w = newStepUpWorld(t)
		begin := w.clock
		w.onAuthorize = func() { w.clock = w.clock.Add(25 * time.Second) }
		if res := w.stepUp(with(w, "auth_time", begin.Add(4*time.Second).Unix())); res.Header().Get("Location") != "/devices/x?stepup=failed" {
			t.Fatalf("21 s old login: %s", res.Header().Get("Location"))
		}
	})
	t.Run("shortened maximum auth age", func(t *testing.T) {
		// The step-up started 20 s before the callback; its authentication 16 s before it is too old for max_age 15.
		w := newStepUpWorldWith(t, 15*time.Second)
		start := w.clock
		w.onAuthorize = func() { w.clock = w.clock.Add(20 * time.Second) }
		if res := w.stepUp(with(w, "auth_time", start.Add(4*time.Second).Unix())); res.Header().Get("Location") != "/devices/x?stepup=failed" {
			t.Fatalf("16 s old login with max_age 15: %s", res.Header().Get("Location"))
		}
		w = newStepUpWorldWith(t, 15*time.Second)
		start = w.clock
		w.onAuthorize = func() { w.clock = w.clock.Add(20 * time.Second) }
		if res := w.stepUp(with(w, "auth_time", start.Add(15*time.Second).Unix())); res.Header().Get("Location") != "/devices/x" {
			t.Fatalf("5 s old login with max_age 15: %s", res.Header().Get("Location"))
		}
	})
	t.Run("session ended on the server", func(t *testing.T) {
		w := newStepUpWorld(t)
		delete(w.sessions.records, "sid-alice")
		value, err := w.keys.Seal(admin.SessionCookie, w.session)
		if err != nil {
			t.Fatal(err)
		}
		if res := w.serve("/api/auth/stepup?return_to=%2F", &http.Cookie{Name: admin.SessionCookie, Value: value}); res.Code != http.StatusUnauthorized {
			t.Fatalf("start for an ended session: %d", res.Code)
		}
	})
	t.Run("session ended during the step-up", func(t *testing.T) {
		w := newStepUpWorld(t)
		w.onAuthorize = func() { delete(w.sessions.records, "sid-alice") }
		if res := w.stepUp(good(w)); res.Header().Get("Location") != "/devices/x?stepup=failed" || cookieOf(res, admin.SessionCookie) != nil {
			t.Fatalf("callback for an ended session: %s", res.Header().Get("Location"))
		}
	})
	t.Run("without session", func(t *testing.T) {
		w := newStepUpWorld(t)
		if res := w.serve("/api/auth/stepup?return_to=%2F"); res.Code != http.StatusUnauthorized {
			t.Fatalf("start without session: %d", res.Code)
		}
	})
	t.Run("forged state", func(t *testing.T) {
		w := newStepUpWorld(t)
		res := w.serve("/api/auth/stepup/callback?code=c&state=forged")
		if res.Code != http.StatusFound || res.Header().Get("Location") != "/?stepup=failed" {
			t.Fatalf("callback: %d %s", res.Code, res.Header().Get("Location"))
		}
	})
}
