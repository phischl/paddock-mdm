package acceptance

import (
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/test/acceptance/internal/authflow"
	"github.com/phischl/paddock-mdm/test/acceptance/internal/env"
)

// platformOrg is the platform pseudo-organization of the audit log.
var platformOrg = uuid.Nil

// TestLoginGate is gate A4 (plan M0 §8, AC6): only members of exactly one Paddock admin group get a session;
// every rejected login is audited as admin.login denied; platform and organization scopes are separated.
func TestLoginGate(t *testing.T) {
	idx := auditIndex(t)

	t.Run("user without a Paddock admin group is denied", func(t *testing.T) {
		// Member of the organization's root group only: Authentik admits the user to the application, Paddock
		// finds no admin role.
		user, pw := tempUser(t, "member", env.RootGroup("acme"))
		p, err := loginAs(t, user, pw)
		if !errors.Is(err, authflow.ErrDenied) || p == nil || !strings.HasPrefix(p.Final, "/login-denied?reason=not_authorized") {
			t.Fatalf("login = %v (final %q), want /login-denied?reason=not_authorized", err, finalOf(p))
		}
		expectNoSession(t, p)
		ev := expectOneIndexEvent(t, idx, platformOrg, "correlation_id = $1", p.LoginRequestID, "admin.login", "denied", auditPollTimeout)
		if ev.ActorDisplay != user {
			t.Fatalf("denied login recorded for %q, want %q", ev.ActorDisplay, user)
		}
	})

	t.Run("user without any Paddock group is stopped by Authentik", func(t *testing.T) {
		user, pw := tempUser(t, "outsider")
		p, err := loginAs(t, user, pw)
		if err == nil {
			t.Fatalf("login succeeded (final %q)", finalOf(p))
		}
		expectNoSession(t, p)
	})

	t.Run("user in admin groups of two organizations is denied", func(t *testing.T) {
		user, pw := tempUser(t, "twoorgs", env.RoleGroup("acme", "admins"), env.RoleGroup("globex", "admins"))
		p, err := loginAs(t, user, pw)
		if !errors.Is(err, authflow.ErrDenied) || !strings.HasPrefix(p.Final, "/login-denied?reason=not_authorized") {
			t.Fatalf("login = %v (final %q), want /login-denied?reason=not_authorized", err, finalOf(p))
		}
		expectNoSession(t, p)
		expectOneIndexEvent(t, idx, platformOrg, "correlation_id = $1", p.LoginRequestID, "admin.login", "denied", auditPollTimeout)
	})

	t.Run("platform admin has no organization data", func(t *testing.T) {
		root := login(t, env.PlatformAdmin)
		res := call(t, root, http.MethodGet, "/api/v1/device-groups", nil)
		expectStatus(t, res, http.StatusForbidden, "no_organization")
		res = call(t, root, http.MethodGet, "/api/v1/audit-events", nil)
		expectStatus(t, res, http.StatusForbidden, "no_organization")
	})

	t.Run("organization admin has no platform access", func(t *testing.T) {
		alice := login(t, env.Alice)
		res := call(t, alice, http.MethodGet, "/api/platform/v1/organizations", nil)
		expectStatus(t, res, http.StatusForbidden, "forbidden")
	})
}

func finalOf(p *env.Portal) string {
	if p == nil {
		return ""
	}
	return p.Final
}

// expectNoSession checks that a rejected login left no usable portal session behind.
func expectNoSession(t *testing.T, p *env.Portal) {
	t.Helper()
	if p == nil {
		return
	}
	res, err := p.Do(testContext(t, time.Minute), http.MethodGet, "/api/v1/me", nil)
	if err != nil {
		t.Fatal(err)
	}
	expectStatus(t, res, http.StatusUnauthorized, "unauthenticated")
}
