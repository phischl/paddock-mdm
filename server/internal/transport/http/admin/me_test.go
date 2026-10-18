package admin_test

import (
	"context"
	"net/http"
	"slices"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/principal"
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
