package admin_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
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

// adminClaims are the claims of an organization administrator of acme; amr names the authentication methods (nil
// leaves the claim out).
func (w *loginWorld) adminClaims(username string, amr []string) map[string]any {
	c := map[string]any{"aud": "paddock-portal", "sub": "sub-" + uuid.NewString(), "preferred_username": username,
		"groups": []string{organization.RoleGroup(w.slug, organization.GroupAdmins)}}
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

// TestLoginStartsWithPromptLogin: the authorize request always asks Authentik to run the login flow again, so an
// existing Authentik session never satisfies a portal sign-in (plan M8x decision 1).
func TestLoginStartsWithPromptLogin(t *testing.T) {
	w := newLoginWorld(t, nil)
	start := w.start()
	loc, err := url.Parse(start.Header().Get("Location"))
	if start.Code != http.StatusFound || err != nil || loc.Query().Get("prompt") != "login" {
		t.Fatalf("login start: %d %s", start.Code, start.Header().Get("Location"))
	}
}

// TestLoginRefusesATokenWithoutMFA: an ID token without "mfa" in amr is refused with mfa_required and exactly one
// audited denial naming the user; with "mfa" the session starts; the development switch lets a token without it pass
// (plan M8x decisions 2, 3 and 7b).
func TestLoginRefusesATokenWithoutMFA(t *testing.T) {
	w := newLoginWorld(t, nil)
	ctx := context.Background()
	events := func(username string) (n int, outcome, errCode, reason string) {
		t.Helper()
		if err := w.e.super.QueryRow(ctx, `SELECT count(*), coalesce(max(outcome), ''), coalesce(max(error_code), ''),
			coalesce(max(params->>'reason'), '') FROM action WHERE code = 'admin.login' AND actor->>'display' = $1`,
			username).Scan(&n, &outcome, &errCode, &reason); err != nil {
			t.Fatal(err)
		}
		return n, outcome, errCode, reason
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
			if n, outcome, errCode, reason := events(username); n != 1 || outcome != "denied" || errCode != "mfa_required" ||
				reason != "mfa_required" {
				t.Fatalf("audit: %d events, outcome %q, error code %q, reason %q", n, outcome, errCode, reason)
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
