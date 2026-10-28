package admin_test

import (
	"context"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/transport/http/admin"
	"github.com/phischl/paddock-mdm/server/internal/transport/http/admin/adminapi"
)

// TestMeNamesTheOrganizationDomains: GET /api/v1/me carries the domains of the signed-in administrator's
// organization, an empty list for an organization without domains, and no organization for a platform administrator
// (plan M8x decision 13).
func TestMeNamesTheOrganizationDomains(t *testing.T) {
	e := newEnv(t)
	suffix := e.acme.String()[28:]
	domains := []string{"acme-" + suffix + ".test", "corp-" + suffix + ".test"}
	if _, err := e.super.Exec(context.Background(), "UPDATE organization SET domains = $2 WHERE id = $1", e.acme, domains); err != nil {
		t.Fatal(err)
	}
	me := func(c *http.Cookie) adminapi.Me {
		t.Helper()
		var m adminapi.Me
		if r := e.do(call{method: "GET", path: "/api/v1/me", cookie: c}); r.status != http.StatusOK {
			t.Fatalf("GET /api/v1/me: %d", r.status)
		} else {
			r.decode(t, &m)
		}
		return m
	}
	if m := me(e.session(e.acme, principal.RoleOrgAuditor)); m.Organization == nil || !slices.Equal(m.Organization.Domains, domains) {
		t.Fatalf("acme: %+v", m.Organization)
	}
	if m := me(e.session(e.globex, principal.RoleOrgAdmin)); m.Organization == nil || m.Organization.Domains == nil ||
		len(m.Organization.Domains) != 0 {
		t.Fatalf("globex without domains: %+v", m.Organization)
	}
	if m := me(e.platformSession()); m.Organization != nil {
		t.Fatalf("platform admin: %+v", m.Organization)
	}
}

// TestMeNamesTheStepUpFreshness: step_up_valid_until is null before a step-up, the end of the window after one, and
// null again once the window has passed (plan M8x decision 35).
func TestMeNamesTheStepUpFreshness(t *testing.T) {
	e := newEnv(t)
	get := func(c *http.Cookie) adminapi.Me {
		t.Helper()
		var m adminapi.Me
		if r := e.do(call{method: "GET", path: "/api/v1/me", cookie: c}); r.status != http.StatusOK {
			t.Fatalf("GET /api/v1/me: %d", r.status)
		} else {
			r.decode(t, &m)
		}
		return m
	}
	alice := e.session(e.acme, principal.RoleOrgAdmin)
	if m := get(alice); m.StepUpValidUntil != nil {
		t.Fatalf("before a step-up: %v", m.StepUpValidUntil)
	}
	at := time.Now().Truncate(time.Second)
	m := get(e.steppedUp(alice, at))
	if m.StepUpValidUntil == nil || !m.StepUpValidUntil.Equal(at.Add(app.StepUpValidity)) {
		t.Fatalf("after a step-up at %s: %v, want %s", at, m.StepUpValidUntil, at.Add(app.StepUpValidity))
	}
	if m := get(e.steppedUp(alice, time.Now().Add(-app.StepUpValidity-time.Second))); m.StepUpValidUntil != nil {
		t.Fatalf("after the window: %v", m.StepUpValidUntil)
	}
}

// TestMeNamesTheServerVersion (PDK-430): every portal role reads the build version of the server in GET and PATCH
// /api/v1/me; without a session the endpoint answers 401, so the login page learns no version.
func TestMeNamesTheServerVersion(t *testing.T) {
	const version = "0.1.0-alpha.5"
	e := newEnvWith(t, func(d *admin.Deps) { d.ServerVersion = version })
	sessions := map[string]*http.Cookie{
		"platform_admin": e.platformSession(),
		"org_admin":      e.session(e.acme, principal.RoleOrgAdmin),
		"org_operator":   e.session(e.acme, principal.RoleOrgOperator),
		"org_auditor":    e.session(e.acme, principal.RoleOrgAuditor),
	}
	for role, c := range sessions {
		var m adminapi.Me
		r := e.do(call{method: "GET", path: "/api/v1/me", cookie: c})
		if r.status != http.StatusOK {
			t.Fatalf("%s: GET /api/v1/me: %d", role, r.status)
		}
		r.decode(t, &m)
		if m.ServerVersion != version {
			t.Fatalf("%s: server_version %q, want %q", role, m.ServerVersion, version)
		}
	}

	var patched adminapi.Me
	e.do(call{method: "PATCH", path: "/api/v1/me", cookie: sessions["org_admin"], body: map[string]any{"locale": "de"}}).decode(t, &patched)
	if patched.ServerVersion != version {
		t.Fatalf("PATCH /api/v1/me: server_version %q, want %q", patched.ServerVersion, version)
	}

	if r := e.do(call{method: "GET", path: "/api/v1/me"}); r.status != http.StatusUnauthorized || strings.Contains(string(r.body), version) {
		t.Fatalf("without a session: %d %s", r.status, r.body)
	}
}

// TestMeNamesTheChannel: GET and PATCH /api/v1/me answer channel portal for a portal session of either kind and api for
// an API token (ADR 0044); mcp is produced by MCP sessions.
func TestMeNamesTheChannel(t *testing.T) {
	e := newEnv(t)
	alice := e.session(e.acme, principal.RoleOrgAdmin)
	token := e.createAPIToken("acme", alice, "channel", adminapi.ApiTokenRoleOrgAuditor)
	for name, c := range map[string]call{
		"organization session": {method: "GET", path: "/api/v1/me", cookie: alice},
		"platform session":     {method: "GET", path: "/api/v1/me", cookie: e.platformSession()},
		"api token":            {method: "GET", path: "/api/v1/me", headers: bearer(token.Secret)},
		"patch":                {method: "PATCH", path: "/api/v1/me", cookie: alice, body: map[string]any{"locale": "en"}},
	} {
		want := adminapi.MeChannel("portal")
		if name == "api token" {
			want = "api"
		}
		r := e.do(c)
		if r.status != http.StatusOK {
			t.Fatalf("%s: %d %s", name, r.status, r.body)
		}
		var m adminapi.Me
		r.decode(t, &m)
		if m.Channel != want {
			t.Fatalf("%s: channel %q, want %q", name, m.Channel, want)
		}
	}
}
