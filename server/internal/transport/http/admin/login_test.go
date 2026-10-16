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

// TestLoginDiscardsTheSessionOfAFailedLogin: when a login fails after its session record was created (here: the
// browser goes away while the login commits), the record is deleted, also though the request's context ended.
func TestLoginDiscardsTheSessionOfAFailedLogin(t *testing.T) {
	idp := newFakeStepUpIdP(t)
	oidc := admin.NewOIDC(admin.OIDCConfig{Issuer: idp.URL, ClientID: "paddock-portal", ClientSecret: "s",
		PublicURL: "https://admin.test", RedirectPath: "/api/auth/callback"})
	discover, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	oidc.Discover(discover)
	if !oidc.Ready() {
		t.Fatal("discovery failed")
	}
	e := newEnvWith(t, func(d *admin.Deps) { d.OIDC = oidc })
	var slug string
	if err := e.super.QueryRow(context.Background(), "SELECT slug FROM organization WHERE id = $1", e.acme).Scan(&slug); err != nil {
		t.Fatal(err)
	}

	login := func(ctx context.Context) *httptest.ResponseRecorder {
		t.Helper()
		start := httptest.NewRecorder()
		e.handler.ServeHTTP(start, httptest.NewRequest(http.MethodGet, "https://admin.test/api/auth/login?return_to=%2F", nil))
		loc, err := url.Parse(start.Header().Get("Location"))
		if start.Code != http.StatusFound || err != nil {
			t.Fatalf("login start: %d %v", start.Code, err)
		}
		idp.mu.Lock()
		idp.claims = map[string]any{"aud": "paddock-portal", "sub": "sub-" + uuid.NewString(), "preferred_username": "erin@acme.test",
			"groups": []string{organization.RoleGroup(slug, organization.GroupAdmins)}}
		idp.nonce = loc.Query().Get("nonce")
		idp.mu.Unlock()
		req := httptest.NewRequestWithContext(ctx, http.MethodGet,
			"https://admin.test/api/auth/callback?code=c&state="+url.QueryEscape(loc.Query().Get("state")), nil)
		for _, c := range start.Result().Cookies() {
			req.AddCookie(c)
		}
		rec := httptest.NewRecorder()
		e.handler.ServeHTTP(rec, req)
		return rec
	}

	// The login works and leaves exactly its record.
	if res := login(context.Background()); res.Code != http.StatusFound || cookieOf(res, admin.SessionCookie) == nil {
		t.Fatalf("login: %d %s", res.Code, res.Header().Get("Location"))
	}
	before := len(e.sessions.records)

	ctx, gone := context.WithCancel(context.Background())
	created := false
	// The browser goes away after the record exists, so the login cannot commit.
	e.sessions.afterCreate = func() { created = true; gone() }
	res := login(ctx)
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
