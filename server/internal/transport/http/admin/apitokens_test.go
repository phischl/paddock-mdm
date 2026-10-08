package admin_test

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/server/internal/platform/httpx"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/transport/http/admin/adminapi"
)

// createAPIToken creates an API token through the portal path with a stepped-up org admin session of org.
func (e *env) createAPIToken(org string, cookie *http.Cookie, name string, role adminapi.ApiTokenRole) adminapi.ApiTokenCreated {
	e.t.Helper()
	r := e.do(call{method: "POST", path: "/api/v1/api-tokens", cookie: e.steppedUp(cookie, time.Now()), body: map[string]any{
		"name": name, "role": role, "expires_at": time.Now().Add(48 * time.Hour).UTC().Format(time.RFC3339),
	}})
	if r.status != http.StatusCreated {
		e.t.Fatalf("create api token in %s: %d %s", org, r.status, r.body)
	}
	var created adminapi.ApiTokenCreated
	r.decode(e.t, &created)
	return created
}

func bearer(secret string) map[string]string {
	return map[string]string{"Authorization": "Bearer " + secret}
}

// TestAPITokenBearerPath covers plan M6c decision 9: the bearer header replaces the session cookie, unknown secrets are
// refused without an audit event, revoked ones with exactly one api_token.use_denied, the token principal is
// attributed in the audit trail, and the CSRF header is still required.
func TestAPITokenBearerPath(t *testing.T) {
	e := newEnv(t)
	alice := e.session(e.acme, principal.RoleOrgAdmin)

	r := e.do(call{method: "POST", path: "/api/v1/api-tokens", cookie: alice, body: map[string]any{
		"name": "no step-up", "role": "org_auditor", "expires_at": time.Now().Add(48 * time.Hour).UTC().Format(time.RFC3339),
	}})
	if r.status != http.StatusForbidden || r.problemCode(t) != "step_up_required" {
		t.Fatalf("create without step-up: %d %s", r.status, r.body)
	}
	e.expectEvent(r, "api_token.created:denied:step_up_required")

	created := e.createAPIToken("acme", alice, "ci", adminapi.ApiTokenRoleOrgAdmin)
	if len(created.Secret) != 47 || !strings.HasPrefix(created.Secret, "pdk_") || created.Token.Prefix != created.Secret[:12] ||
		created.Token.Status != adminapi.ApiTokenStatusActive {
		t.Fatalf("created %+v", created.Token)
	}
	got := e.do(call{method: "GET", path: "/api/v1/api-tokens/" + created.Token.Id.String(), cookie: alice})
	if got.status != http.StatusOK || strings.Contains(string(got.body), created.Secret) || strings.Contains(string(got.body), "secret") {
		t.Fatalf("get: %d %s", got.status, got.body)
	}

	me := e.do(call{method: "GET", path: "/api/v1/me", headers: bearer(created.Secret)})
	var m adminapi.Me
	me.decode(t, &m)
	if me.status != http.StatusOK || m.ApiToken == nil || m.ApiToken.Name != "ci" || m.ApiToken.Id != created.Token.Id ||
		m.Id != created.Token.Id || m.Username != "ci" || m.Role != adminapi.MeRoleOrgAdmin || m.Organization == nil || m.Organization.Id != e.acme {
		t.Fatalf("bearer /me: %d %s", me.status, me.body)
	}
	sessionMe := e.do(call{method: "GET", path: "/api/v1/me", cookie: alice})
	if strings.Contains(string(sessionMe.body), "api_token") {
		t.Fatalf("session /me carries api_token: %s", sessionMe.body)
	}
	if r := e.do(call{method: "PATCH", path: "/api/v1/me", headers: bearer(created.Secret), body: map[string]any{"locale": "en"}}); r.status != http.StatusForbidden {
		t.Fatalf("bearer PATCH /me: %d %s", r.status, r.body)
	}

	// The token acts as its role and is attributed in the audit trail.
	r = e.do(call{method: "POST", path: "/api/v1/device-groups", headers: bearer(created.Secret), body: map[string]any{"name": "by token"}})
	if r.status != http.StatusCreated {
		t.Fatalf("create group with token: %d %s", r.status, r.body)
	}
	e.expectEvent(r, "device_group.created:success:")
	var actorType, actorID, actorDisplay string
	if err := e.super.QueryRow(context.Background(), "SELECT actor->>'type', actor->>'id', actor->>'display' FROM action WHERE correlation_id = $1",
		r.header.Get(httpx.HeaderRequestID)).Scan(&actorType, &actorID, &actorDisplay); err != nil {
		t.Fatal(err)
	}
	if actorType != "api_token" || actorID != created.Token.Id.String() || actorDisplay != "ci" {
		t.Fatalf("actor %s %s %s", actorType, actorID, actorDisplay)
	}
	// A token never has a step-up, so it cannot create tokens.
	r = e.do(call{method: "POST", path: "/api/v1/api-tokens", headers: bearer(created.Secret), body: map[string]any{
		"name": "by token", "role": "org_auditor", "expires_at": time.Now().Add(48 * time.Hour).UTC().Format(time.RFC3339),
	}})
	if r.status != http.StatusForbidden || r.problemCode(t) != "step_up_required" {
		t.Fatalf("token creating a token: %d %s", r.status, r.body)
	}
	e.expectEvent(r, "api_token.created:denied:step_up_required")
	// The CSRF header is still required on mutating requests.
	r = e.do(call{method: "POST", path: "/api/v1/device-groups", headers: bearer(created.Secret), body: map[string]any{"name": "no csrf"},
		noCSRF: true, skipReqCheck: true})
	if r.status != http.StatusForbidden || r.problemCode(t) != "csrf_missing" {
		t.Fatalf("bearer without CSRF: %d %s", r.status, r.body)
	}
	e.expectEvent(r, "device_group.created:denied:csrf_missing")
	// Platform endpoints refuse organization principals.
	if r := e.do(call{method: "GET", path: "/api/platform/v1/organizations", headers: bearer(created.Secret)}); r.status != http.StatusForbidden {
		t.Fatalf("bearer on platform API: %d %s", r.status, r.body)
	}

	// Unknown and malformed secrets: 401 without an audit event.
	for _, s := range []string{"pdk_" + strings.Repeat("A", 43), "not-a-token", created.Secret[:46]} {
		r := e.do(call{method: "GET", path: "/api/v1/device-groups", headers: bearer(s)})
		if r.status != http.StatusUnauthorized || r.problemCode(t) != "unauthenticated" {
			t.Fatalf("secret %q: %d %s", s, r.status, r.body)
		}
		if ev := e.events(r.header.Get(httpx.HeaderRequestID)); len(ev) != 0 {
			t.Fatalf("unknown secret recorded: %v", ev)
		}
	}

	// Revoked: 401 and exactly one api_token.use_denied.
	r = e.do(call{method: "POST", path: "/api/v1/api-tokens/" + created.Token.Id.String() + "/revoke", cookie: alice})
	if r.status != http.StatusOK {
		t.Fatalf("revoke: %d %s", r.status, r.body)
	}
	e.expectEvent(r, "api_token.revoked:success:")
	r = e.do(call{method: "POST", path: "/api/v1/api-tokens/" + created.Token.Id.String() + "/revoke", cookie: alice})
	if r.status != http.StatusConflict || r.problemCode(t) != "invalid_state" {
		t.Fatalf("second revoke: %d %s", r.status, r.body)
	}
	r = e.do(call{method: "GET", path: "/api/v1/device-groups", headers: bearer(created.Secret)})
	if r.status != http.StatusUnauthorized || r.problemCode(t) != "unauthenticated" {
		t.Fatalf("revoked token: %d %s", r.status, r.body)
	}
	e.expectEvent(r, "api_token.use_denied:denied:forbidden")
}

// TestAPITokenListAndIsolation: the list follows the contract with its status filter; tokens of another
// organization are invisible (404) and auditors read but do not create or revoke.
func TestAPITokenListAndIsolation(t *testing.T) {
	e := newEnv(t)
	alice := e.session(e.acme, principal.RoleOrgAdmin)
	auditor := e.session(e.acme, principal.RoleOrgAuditor)
	operator := e.session(e.acme, principal.RoleOrgOperator)
	carol := e.session(e.globex, principal.RoleOrgAdmin)
	a := e.createAPIToken("acme", alice, "acme one", adminapi.ApiTokenRoleOrgOperator)
	e.createAPIToken("acme", alice, "acme two", adminapi.ApiTokenRoleOrgAuditor)
	g := e.createAPIToken("globex", carol, "globex one", adminapi.ApiTokenRoleOrgAdmin)
	e.do(call{method: "POST", path: "/api/v1/api-tokens/" + a.Token.Id.String() + "/revoke", cookie: alice})

	var page adminapi.ApiTokenPage
	r := e.do(call{method: "GET", path: "/api/v1/api-tokens?page_size=10&sort=-name", cookie: auditor})
	r.decode(t, &page)
	if r.status != http.StatusOK || page.Total != 2 || page.Items[0].Name != "acme two" || page.Sort != "-name" {
		t.Fatalf("list: %d %s", r.status, r.body)
	}
	r = e.do(call{method: "GET", path: "/api/v1/api-tokens?status=revoked&q=acme", cookie: auditor})
	r.decode(t, &page)
	if page.Total != 1 || page.Items[0].Id != a.Token.Id || page.Items[0].RevokedAt == nil || page.Items[0].CreatedBy.Display != "org_admin@test" {
		t.Fatalf("revoked filter: %s", r.body)
	}
	if strings.Contains(string(r.body), g.Token.Id.String()) {
		t.Fatal("globex token listed for acme")
	}
	for _, path := range []string{"/api/v1/api-tokens/" + g.Token.Id.String()} {
		if r := e.do(call{method: "GET", path: path, cookie: alice}); r.status != http.StatusNotFound {
			t.Fatalf("GET globex token: %d", r.status)
		}
	}
	r = e.do(call{method: "POST", path: "/api/v1/api-tokens/" + g.Token.Id.String() + "/revoke", cookie: alice})
	if r.status != http.StatusNotFound || r.problemCode(t) != "not_found" {
		t.Fatalf("revoke globex token: %d %s", r.status, r.body)
	}
	e.expectEvent(r, "api_token.revoked:failure:not_found")
	r = e.do(call{method: "POST", path: "/api/v1/api-tokens", cookie: e.steppedUp(auditor, time.Now()), body: map[string]any{
		"name": "auditor", "role": "org_auditor", "expires_at": time.Now().Add(48 * time.Hour).UTC().Format(time.RFC3339),
	}})
	if r.status != http.StatusForbidden {
		t.Fatalf("auditor creating a token: %d %s", r.status, r.body)
	}
	e.expectEvent(r, "api_token.created:denied:forbidden")
	r = e.do(call{method: "POST", path: "/api/v1/api-tokens", cookie: e.steppedUp(operator, time.Now()), body: map[string]any{
		"name": "operator admin", "role": "org_admin", "expires_at": time.Now().Add(48 * time.Hour).UTC().Format(time.RFC3339),
	}})
	if r.status != http.StatusForbidden || r.problemCode(t) != "forbidden" {
		t.Fatalf("operator creating an admin token: %d %s", r.status, r.body)
	}
	e.expectEvent(r, "api_token.created:denied:forbidden")
	r = e.do(call{method: "POST", path: "/api/v1/api-tokens", cookie: e.steppedUp(alice, time.Now()), body: map[string]any{
		"name": "acme two", "role": "org_auditor", "expires_at": time.Now().Add(48 * time.Hour).UTC().Format(time.RFC3339),
	}})
	if r.status != http.StatusConflict || r.problemCode(t) != "name_taken" {
		t.Fatalf("name taken: %d %s", r.status, r.body)
	}
	r = e.do(call{method: "POST", path: "/api/v1/api-tokens", cookie: e.steppedUp(alice, time.Now()), body: map[string]any{
		"name": "too soon", "role": "org_auditor", "expires_at": time.Now().Add(30 * time.Minute).UTC().Format(time.RFC3339),
	}})
	if r.status != http.StatusBadRequest || r.problemCode(t) != "invalid_request" {
		t.Fatalf("expiry too soon: %d %s", r.status, r.body)
	}
}
