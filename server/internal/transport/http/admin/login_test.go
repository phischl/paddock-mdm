package admin_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/domain/organization"
	"github.com/phischl/paddock-mdm/server/internal/transport/http/admin"
)

// loginWorld is the portal login against a fake identity provider.
type loginWorld struct {
	t    *testing.T
	e    *env
	idp  *fakeStepUpIdP
	slug string // slug of acme
}

func newLoginWorld(t *testing.T, deps func(*admin.Deps)) *loginWorld {
	t.Helper()
	idp := newFakeStepUpIdP(t)
	oidc := admin.NewOIDC(admin.OIDCConfig{Issuer: idp.URL, ClientID: "paddock-portal", ClientSecret: "s",
		PublicURL: "https://admin.test", RedirectPath: "/api/auth/callback"})
	discover, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	oidc.Discover(discover)
	if !oidc.Ready() {
		t.Fatal("discovery failed")
	}
	e := newEnvWith(t, func(d *admin.Deps) {
		d.OIDC = oidc
		if deps != nil {
			deps(d)
		}
	})
	w := &loginWorld{t: t, e: e, idp: idp}
	if err := e.super.QueryRow(context.Background(), "SELECT slug FROM organization WHERE id = $1", e.acme).Scan(&w.slug); err != nil {
		t.Fatal(err)
	}
	return w
}

// start runs GET /api/auth/login and returns the response.
func (w *loginWorld) start() *httptest.ResponseRecorder {
	w.t.Helper()
	start := httptest.NewRecorder()
	w.e.handler.ServeHTTP(start, httptest.NewRequest(http.MethodGet, "https://admin.test/api/auth/login?return_to=%2F", nil))
	return start
}

// login runs the authorization code flow; the identity provider issues an ID token with claims.
func (w *loginWorld) login(ctx context.Context, claims map[string]any) *httptest.ResponseRecorder {
	w.t.Helper()
	start := w.start()
	loc, err := url.Parse(start.Header().Get("Location"))
	if start.Code != http.StatusFound || err != nil {
		w.t.Fatalf("login start: %d %v", start.Code, err)
	}
	w.idp.mu.Lock()
	w.idp.claims = claims
	w.idp.nonce = loc.Query().Get("nonce")
	w.idp.mu.Unlock()
	req := httptest.NewRequestWithContext(ctx, http.MethodGet,
		"https://admin.test/api/auth/callback?code=c&state="+url.QueryEscape(loc.Query().Get("state")), nil)
	for _, c := range start.Result().Cookies() {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	w.e.handler.ServeHTTP(rec, req)
	return rec
}

// adminClaims are the claims of an organization administrator of acme who signed in with a passkey; amr names the
// authentication methods (nil leaves the claim out).
func (w *loginWorld) adminClaims(username string, amr []string) map[string]any {
	c := map[string]any{"aud": "paddock-portal", "sub": "sub-" + uuid.NewString(), "preferred_username": username,
		"groups":              []string{organization.RoleGroup(w.slug, organization.GroupAdmins)},
		"paddock_mfa_classes": []string{admin.StepUpWebAuthnClass}}
	if amr != nil {
		c["amr"] = amr
	}
	return c
}

// TestLoginDiscardsTheSessionOfAFailedLogin: when a login fails after its session record was created (here: the
// browser goes away while the login commits), the record is deleted, also though the request's context ended.
func TestLoginDiscardsTheSessionOfAFailedLogin(t *testing.T) {
	w := newLoginWorld(t, nil)
	e := w.e

	// The login works and leaves exactly its record.
	if res := w.login(context.Background(), w.adminClaims("erin@acme.test", []string{"pwd", "mfa"})); res.Code != http.StatusFound ||
		cookieOf(res, admin.SessionCookie) == nil {
		t.Fatalf("login: %d %s", res.Code, res.Header().Get("Location"))
	}
	before := len(e.sessions.records)

	ctx, gone := context.WithCancel(context.Background())
	created := false
	// The browser goes away after the record exists, so the login cannot commit.
	e.sessions.afterCreate = func() { created = true; gone() }
	res := w.login(ctx, w.adminClaims("erin@acme.test", []string{"pwd", "mfa"}))
	e.sessions.afterCreate = nil
	if !created {
		t.Fatal("the failed login never created its session record")
	}
	if !strings.Contains(res.Header().Get("Location"), "/login-denied") || cookieOf(res, admin.SessionCookie) != nil {
		t.Fatalf("failed login: %d %s", res.Code, res.Header().Get("Location"))
	}
	if after := len(e.sessions.records); after != before {
		t.Fatalf("%d session records after the failed login, want %d", after, before)
	}
}

// TestLoginStartsWithoutPrompt: the authorize request carries no prompt. With prompt=login Authentik remembers the
// login it forced away and then skips the flow of the next step-up; an existing Authentik session may satisfy the
// sign-in, and TestLoginRefusesATokenWithoutMFA keeps one without a second factor out.
func TestLoginStartsWithoutPrompt(t *testing.T) {
	w := newLoginWorld(t, nil)
	start := w.start()
	loc, err := url.Parse(start.Header().Get("Location"))
	if start.Code != http.StatusFound || err != nil || !strings.HasPrefix(loc.String(), w.idp.URL+"/authorize") ||
		loc.Query().Has("prompt") || loc.Query().Has("max_age") {
		t.Fatalf("login start: %d %s", start.Code, start.Header().Get("Location"))
	}
}

// TestLoginRefusesATokenWithoutMFA: an ID token without "mfa" in amr is refused with mfa_required and exactly one
// audited denial naming the user; with "mfa" the session starts; the development switch lets a token without it pass
// (plan M8x decisions 2, 3 and 7b).
func TestLoginRefusesATokenWithoutMFA(t *testing.T) {
	w := newLoginWorld(t, nil)
	ctx := context.Background()
	events := func(username string) (n int, outcome, errCode, reason, channel string) {
		t.Helper()
		if err := w.e.super.QueryRow(ctx, `SELECT count(*), coalesce(max(outcome), ''), coalesce(max(error_code), ''),
			coalesce(max(params->>'reason'), ''), coalesce(max(params->>'channel'), '') FROM action
			WHERE code = 'admin.login' AND actor->>'display' = $1`,
			username).Scan(&n, &outcome, &errCode, &reason, &channel); err != nil {
			t.Fatal(err)
		}
		return n, outcome, errCode, reason, channel
	}

	for name, amr := range map[string][]string{"no amr": nil, "password only": {"pwd"}} {
		t.Run(name, func(t *testing.T) {
			username := "mfa-" + uuid.NewString() + "@acme.test"
			before := len(w.e.sessions.records)
			res := w.login(ctx, w.adminClaims(username, amr))
			if res.Code != http.StatusFound || res.Header().Get("Location") != "/login-denied?reason=mfa_required" {
				t.Fatalf("login: %d %s", res.Code, res.Header().Get("Location"))
			}
			if cookieOf(res, admin.SessionCookie) != nil {
				t.Fatal("session cookie set without a second factor")
			}
			if after := len(w.e.sessions.records); after != before {
				t.Fatalf("%d session records, want %d", after, before)
			}
			if n, outcome, errCode, reason, channel := events(username); n != 1 || outcome != "denied" || errCode != "mfa_required" ||
				reason != "mfa_required" || channel != "portal" {
				t.Fatalf("audit: %d events, outcome %q, error code %q, reason %q, channel %q", n, outcome, errCode, reason, channel)
			}
		})
	}

	t.Run("with mfa", func(t *testing.T) {
		res := w.login(ctx, w.adminClaims("mfa-"+uuid.NewString()+"@acme.test", []string{"pwd", "mfa"}))
		if res.Code != http.StatusFound || res.Header().Get("Location") != "/" || cookieOf(res, admin.SessionCookie) == nil {
			t.Fatalf("login: %d %s", res.Code, res.Header().Get("Location"))
		}
	})

	t.Run("development switch", func(t *testing.T) {
		dev := newLoginWorld(t, func(d *admin.Deps) { d.LoginMFAOptional = true })
		res := dev.login(ctx, dev.adminClaims("mfa-"+uuid.NewString()+"@acme.test", nil))
		if res.Code != http.StatusFound || res.Header().Get("Location") != "/" || cookieOf(res, admin.SessionCookie) == nil {
			t.Fatalf("login: %d %s", res.Code, res.Header().Get("Location"))
		}
	})
}

// loginEvents are the admin.login events of username: count, outcome, error code and the params reason and channel.
func (w *loginWorld) loginEvents(username string) (n int, outcome, errCode, reason, channel string) {
	w.t.Helper()
	if err := w.e.super.QueryRow(context.Background(), `SELECT count(*), coalesce(max(outcome), ''),
		coalesce(max(error_code), ''), coalesce(max(params->>'reason'), ''), coalesce(max(params->>'channel'), '')
		FROM action WHERE code = 'admin.login' AND actor->>'display' = $1`,
		username).Scan(&n, &outcome, &errCode, &reason, &channel); err != nil {
		w.t.Fatal(err)
	}
	return n, outcome, errCode, reason, channel
}

// TestLoginRequestsTheAuthenticatorClasses: the sign-in asks for the scope that carries paddock_mfa_classes, without
// which every sign-in would be refused with passkey_required.
func TestLoginRequestsTheAuthenticatorClasses(t *testing.T) {
	w := newLoginWorld(t, nil)
	loc, err := url.Parse(w.start().Header().Get("Location"))
	if err != nil || !slices.Contains(strings.Fields(loc.Query().Get("scope")), "paddock_mfa") {
		t.Fatalf("authorize URL %v without the scope paddock_mfa: %v", loc, err)
	}
}

// TestLoginRequiresAPasskey: every portal role signs in only with a login that validated a WebAuthn authenticator
// (ADR 0034 amendment 2026-10-29, PDK-500). An Authentik session from a TOTP sign-in, a token without the claim and a
// token without any class are refused with passkey_required, one denied admin.login and no session; a login with a
// passkey starts the session; groups without a portal role keep their own reason; the development switch lets a
// token without the claim pass.
func TestLoginRequiresAPasskey(t *testing.T) {
	w := newLoginWorld(t, nil)
	ctx := context.Background()
	roles := map[string]string{
		"platform administrator": organization.PlatformAdminsGroup(),
		"organization admin":     organization.RoleGroup(w.slug, organization.GroupAdmins),
		"operator":               organization.RoleGroup(w.slug, organization.GroupOperators),
		"auditor":                organization.RoleGroup(w.slug, organization.GroupAuditors),
	}
	refused := map[string]any{"TOTP only": []string{totpClass}, "no class": []string{}, "claim missing": nil}
	for role, group := range roles {
		for name, classes := range refused {
			t.Run(role+"/"+name, func(t *testing.T) {
				username := "passkey-" + uuid.NewString() + "@acme.test"
				claims := w.adminClaims(username, []string{"pwd", "mfa"})
				claims["groups"] = []string{group}
				if classes == nil {
					delete(claims, "paddock_mfa_classes")
				} else {
					claims["paddock_mfa_classes"] = classes
				}
				before := len(w.e.sessions.records)
				res := w.login(ctx, claims)
				if res.Code != http.StatusFound || res.Header().Get("Location") != "/login-denied?reason=passkey_required" {
					t.Fatalf("login: %d %s", res.Code, res.Header().Get("Location"))
				}
				if cookieOf(res, admin.SessionCookie) != nil {
					t.Fatal("session cookie set without a passkey")
				}
				if after := len(w.e.sessions.records); after != before {
					t.Fatalf("%d session records, want %d", after, before)
				}
				if n, outcome, errCode, reason, channel := w.loginEvents(username); n != 1 || outcome != "denied" ||
					errCode != "passkey_required" || reason != "passkey_required" || channel != "portal" {
					t.Fatalf("audit: %d events, outcome %q, error code %q, reason %q, channel %q", n, outcome, errCode, reason, channel)
				}
			})
		}
		t.Run(role+"/passkey", func(t *testing.T) {
			username := "passkey-" + uuid.NewString() + "@acme.test"
			claims := w.adminClaims(username, []string{"pwd", "mfa"})
			claims["groups"] = []string{group}
			claims["paddock_mfa_classes"] = []string{totpClass, admin.StepUpWebAuthnClass}
			res := w.login(ctx, claims)
			if res.Code != http.StatusFound || res.Header().Get("Location") != "/" || cookieOf(res, admin.SessionCookie) == nil {
				t.Fatalf("login: %d %s", res.Code, res.Header().Get("Location"))
			}
			if n, outcome, _, _, _ := w.loginEvents(username); n != 1 || outcome != "success" {
				t.Fatalf("audit: %d events, outcome %q", n, outcome)
			}
		})
	}

	t.Run("no portal role", func(t *testing.T) {
		claims := w.adminClaims("passkey-"+uuid.NewString()+"@acme.test", []string{"pwd", "mfa"})
		claims["groups"] = []string{"staff"}
		claims["paddock_mfa_classes"] = []string{totpClass}
		if res := w.login(ctx, claims); res.Header().Get("Location") != "/login-denied?reason=no_role" {
			t.Fatalf("login: %d %s", res.Code, res.Header().Get("Location"))
		}
	})

	t.Run("development switch", func(t *testing.T) {
		dev := newLoginWorld(t, func(d *admin.Deps) { d.LoginMFAOptional = true })
		claims := dev.adminClaims("passkey-"+uuid.NewString()+"@acme.test", nil)
		delete(claims, "paddock_mfa_classes")
		res := dev.login(ctx, claims)
		if res.Code != http.StatusFound || res.Header().Get("Location") != "/" || cookieOf(res, admin.SessionCookie) == nil {
			t.Fatalf("login: %d %s", res.Code, res.Header().Get("Location"))
		}
	})
}

// TestLoginDeniedNamesTheReason: a refused login names why on /login-denied and in the audit param denial_reason
// (plan M8x decision 31).
func TestLoginDeniedNamesTheReason(t *testing.T) {
	w := newLoginWorld(t, nil)
	ctx := context.Background()
	mfa := []string{"pwd", "mfa"}
	cases := map[string][]string{
		"no_role":                {"staff"},
		"multiple_organizations": {organization.RoleGroup(w.slug, organization.GroupAdmins), organization.RoleGroup("globex", organization.GroupAdmins)},
		"multiple_roles":         {organization.RoleGroup(w.slug, organization.GroupAdmins), organization.RoleGroup(w.slug, organization.GroupAuditors)},
		"organization_inactive":  {organization.RoleGroup("gone-"+uuid.NewString()[:8], organization.GroupAdmins)},
	}
	for reason, groups := range cases {
		t.Run(reason, func(t *testing.T) {
			username := "denied-" + uuid.NewString() + "@acme.test"
			claims := w.adminClaims(username, mfa)
			claims["groups"] = groups
			res := w.login(ctx, claims)
			if res.Code != http.StatusFound || res.Header().Get("Location") != "/login-denied?reason="+reason ||
				cookieOf(res, admin.SessionCookie) != nil {
				t.Fatalf("login: %d %s", res.Code, res.Header().Get("Location"))
			}
			var n int
			var outcome, param string
			if err := w.e.super.QueryRow(ctx, `SELECT count(*), coalesce(max(outcome), ''), coalesce(max(params->>'denial_reason'), '')
				FROM action WHERE code = 'admin.login' AND actor->>'display' = $1`, username).Scan(&n, &outcome, &param); err != nil {
				t.Fatal(err)
			}
			if n != 1 || outcome != "denied" || param != reason {
				t.Fatalf("audit: %d events, outcome %q, denial_reason %q", n, outcome, param)
			}
		})
	}
}

// TestLoginNamesASealedKeyStore: while no session key is loaded (OpenBao sealed at the start) the sign-in and the
// callback send the browser to /login-denied?reason=key_store_sealed instead of a 500 (plan M8x decision 28).
func TestLoginNamesASealedKeyStore(t *testing.T) {
	w := newLoginWorld(t, func(d *admin.Deps) { d.Keys = &admin.Keyring{} })
	for _, path := range []string{"/api/auth/login?return_to=%2F", "/api/auth/callback?code=c&state=s"} {
		rec := httptest.NewRecorder()
		w.e.handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "https://admin.test"+path, nil))
		if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/login-denied?reason=key_store_sealed" {
			t.Fatalf("%s: %d %q", path, rec.Code, rec.Header().Get("Location"))
		}
	}
}

// TestLoginRepeatsAnUnavailableTokenRequest is the regression test of a CI failure: Authentik's front server answers
// 503 "authentik starting" for a moment while its backend is not ready, and the sign-in failed with login_failed. The
// code exchange repeats the token request with the same, still unused code instead.
func TestLoginRepeatsAnUnavailableTokenRequest(t *testing.T) {
	w := newLoginWorld(t, nil)
	w.idp.mu.Lock()
	w.idp.unavailable = 2
	w.idp.mu.Unlock()
	res := w.login(context.Background(), w.adminClaims("erin@acme.test", []string{"pwd", "mfa"}))
	if res.Code != http.StatusFound || cookieOf(res, admin.SessionCookie) == nil ||
		strings.HasPrefix(res.Header().Get("Location"), "/login-denied") {
		t.Fatalf("login: %d %s", res.Code, res.Header().Get("Location"))
	}
	w.idp.mu.Lock()
	defer w.idp.mu.Unlock()
	if strings.Join(w.idp.tokenCodes, ",") != "c,c,c" {
		t.Fatalf("token requests with codes %q, want code c three times", w.idp.tokenCodes)
	}
}

// TestLoginGivesUpOnAnUnavailableTokenEndpoint: the repeats are bounded; a provider that stays unavailable fails the
// sign-in with login_failed.
func TestLoginGivesUpOnAnUnavailableTokenEndpoint(t *testing.T) {
	w := newLoginWorld(t, nil)
	w.idp.mu.Lock()
	w.idp.unavailable = 100
	w.idp.mu.Unlock()
	res := w.login(context.Background(), w.adminClaims("erin@acme.test", []string{"pwd", "mfa"}))
	if res.Code != http.StatusFound || res.Header().Get("Location") != "/login-denied?reason=login_failed" ||
		cookieOf(res, admin.SessionCookie) != nil {
		t.Fatalf("login: %d %s", res.Code, res.Header().Get("Location"))
	}
	w.idp.mu.Lock()
	defer w.idp.mu.Unlock()
	// Four attempts for each of the two client authentication styles oauth2 tries when the endpoint's is unknown.
	if n := len(w.idp.tokenCodes); n != 8 {
		t.Fatalf("%d token requests, want 8", n)
	}
}
