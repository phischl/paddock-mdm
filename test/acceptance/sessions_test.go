package acceptance

import (
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/test/acceptance/internal/authflow"
	"github.com/phischl/paddock-mdm/test/acceptance/internal/env"
	"github.com/phischl/paddock-mdm/test/acceptance/internal/stack"
)

// accountRoundTimeout is how long the worker round admin-accounts may take to notice a change: its interval in the
// development stack (PADDOCK_IDENTITY_SYNC_INTERVAL, 60 s) plus slack.
const accountRoundTimeout = 70 * time.Second

// cookieCopy is a second portal client with a copy of p's cookies: the same session in another "browser".
func cookieCopy(t *testing.T, p *env.Portal) *env.Portal {
	t.Helper()
	u, err := url.Parse(stack.AdminURL())
	if err != nil {
		t.Fatal(err)
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	jar.SetCookies(u, p.Client.Jar.Cookies(u))
	c := *p.Client
	c.Jar = jar
	return &env.Portal{User: p.User, Client: &c}
}

// meStatus is the status of GET /api/v1/me for p.
func meStatus(t *testing.T, p *env.Portal) int {
	t.Helper()
	return call(t, p, http.MethodGet, "/api/v1/me", nil).Status
}

// waitUnauthenticated polls GET /api/v1/me until it answers 401 or timeout passes.
func waitUnauthenticated(t *testing.T, p *env.Portal, timeout time.Duration) {
	t.Helper()
	for deadline := time.Now().Add(timeout); ; time.Sleep(2 * time.Second) {
		status := meStatus(t, p)
		if status == http.StatusUnauthorized {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("session of %s still answers %d after %s", p.User, status, timeout)
		}
	}
}

// revokedEvents waits until the organization has an admin.sessions_revoked event of username and returns them all.
func revokedEvents(t *testing.T, idx *env.AuditIndex, org uuid.UUID, username string) []env.IndexEvent {
	t.Helper()
	ctx := testContext(t, time.Minute)
	for deadline := time.Now().Add(auditPollTimeout); ; time.Sleep(time.Second) {
		events, err := idx.Events(ctx, org, "code = 'admin.sessions_revoked' AND target->>'display' = $1", username)
		if err != nil {
			t.Fatal(err)
		}
		if len(events) > 0 || time.Now().After(deadline) {
			return events
		}
	}
}

// revokedEvent waits for the one admin.sessions_revoked event of username in the organization.
func revokedEvent(t *testing.T, idx *env.AuditIndex, org uuid.UUID, username string, timeout time.Duration) env.IndexEvent {
	t.Helper()
	return expectOneIndexEvent(t, idx, org, "code = 'admin.sessions_revoked' AND target->>'display' = $1", username,
		"admin.sessions_revoked", "success", timeout)
}

// TestSessionsLogout is gate S9 of plan M8s: signing out ends the session on the server, so a copy of the cookie is
// refused afterwards.
func TestSessionsLogout(t *testing.T) {
	alice := login(t, env.Alice)
	copied := cookieCopy(t, alice)
	if status := meStatus(t, copied); status != http.StatusOK {
		t.Fatalf("copied cookie before logout: %d", status)
	}
	expectStatus(t, call(t, alice, http.MethodPost, "/api/auth/logout", nil), http.StatusOK, "")
	if status := meStatus(t, copied); status != http.StatusUnauthorized {
		t.Fatalf("copied cookie after logout: %d, want 401", status)
	}
}

// TestSessionsStepUpMismatch is gate S10: an administrator removed from the admins group fails the next step-up, every
// session of the account ends and the revocation is recorded with reason step_up_role_mismatch.
func TestSessionsStepUpMismatch(t *testing.T) {
	alice := login(t, env.Alice)
	org := orgOf(t, alice)
	idx := auditIndex(t)
	ak, err := env.NewAuthentik()
	if err != nil {
		t.Fatal(err)
	}
	// The worker round may notice the removal before the step-up does (reason removed); then the case runs once more
	// with a new administrator.
	for attempt := 1; attempt <= 2; attempt++ {
		u := mfaTempUser(t, "s10", env.RoleGroup("acme", "admins"))
		ctx := testContext(t, 3*time.Minute)
		if err := ak.RemoveFromGroup(ctx, u.username, env.RoleGroup("acme", "admins")); err != nil {
			t.Fatal(err)
		}
		res, err := authflow.StepUp(ctx, u.Client, stack.AdminURL(), "/settings", u.username, u.password, u.totp, false)
		if err != nil {
			t.Fatalf("step-up: %v", err)
		}
		if !strings.Contains(res.Final, "stepup=failed") {
			t.Fatalf("step-up of a removed administrator returned to %s", res.Final)
		}
		if status := meStatus(t, u.Portal); status != http.StatusUnauthorized {
			t.Fatalf("session after the refused step-up: %d, want 401", status)
		}
		events := revokedEvents(t, idx, org, u.username)
		raced := false
		for _, ev := range events {
			raced = raced || ev.Params["reason"] == "removed"
		}
		if raced && attempt == 1 {
			t.Log("the worker round noticed the removal before the step-up; repeating once")
			continue
		}
		if sessions, _ := firstParam(events, "sessions").(float64); len(events) != 1 ||
			events[0].Params["reason"] != "step_up_role_mismatch" || sessions < 1 {
			t.Fatalf("events %+v, want one with reason step_up_role_mismatch and sessions >= 1", events)
		}
		return
	}
	t.Fatal("the worker round was first twice")
}

// TestSessionsDeactivation is gate S11: deactivating the user in the identity provider ends its portal sessions
// within the worker's interval; after reactivation the user signs in again.
func TestSessionsDeactivation(t *testing.T) {
	alice := login(t, env.Alice)
	org := orgOf(t, alice)
	idx := auditIndex(t)
	ak, err := env.NewAuthentik()
	if err != nil {
		t.Fatal(err)
	}
	user, password := tempUser(t, "s11", env.RoleGroup("acme", "admins"))
	p, err := loginAs(t, user, password)
	if err != nil {
		t.Fatal(err)
	}
	ctx := testContext(t, 3*time.Minute)
	pk, err := ak.UserPK(ctx, user)
	if err != nil || pk == 0 {
		t.Fatalf("user pk: %d %v", pk, err)
	}
	if err := ak.SetActive(ctx, pk, false); err != nil {
		t.Fatal(err)
	}
	waitUnauthenticated(t, p, accountRoundTimeout)
	if ev := revokedEvent(t, idx, org, user, auditPollTimeout); ev.Params["reason"] != "deactivated" {
		t.Fatalf("event params %v", ev.Params)
	}
	if err := ak.SetActive(ctx, pk, true); err != nil {
		t.Fatal(err)
	}
	again, err := loginAs(t, user, password)
	if err != nil {
		t.Fatalf("login after reactivation: %v", err)
	}
	if m := whoami(t, again); m.Role != "org_admin" {
		t.Fatalf("role after reactivation %s", m.Role)
	}
}

// TestSessionsRoleChange is gate S12: moving an administrator to the auditors group ends its sessions within the
// worker's interval; the next login has the auditor role and the change is recorded.
func TestSessionsRoleChange(t *testing.T) {
	alice := login(t, env.Alice)
	org := orgOf(t, alice)
	idx := auditIndex(t)
	ak, err := env.NewAuthentik()
	if err != nil {
		t.Fatal(err)
	}
	user, password := tempUser(t, "s12", env.RoleGroup("acme", "admins"))
	p, err := loginAs(t, user, password)
	if err != nil {
		t.Fatal(err)
	}
	if err := ak.MoveGroup(testContext(t, time.Minute), user, env.RoleGroup("acme", "admins"), env.RoleGroup("acme", "auditors")); err != nil {
		t.Fatal(err)
	}
	waitUnauthenticated(t, p, accountRoundTimeout)
	ev := revokedEvent(t, idx, org, user, auditPollTimeout)
	if ev.Params["reason"] != "role_changed" || ev.Params["old_role"] != "org_admin" || ev.Params["new_role"] != "org_auditor" {
		t.Fatalf("event params %v", ev.Params)
	}
	again, err := loginAs(t, user, password)
	if err != nil {
		t.Fatalf("login after the role change: %v", err)
	}
	if m := whoami(t, again); m.Role != "org_auditor" {
		t.Fatalf("role after the change %s, want org_auditor", m.Role)
	}
}

// TestSessionsEndAll is gate S13. It ends every portal session of the stack, so it runs only with
// PADDOCK_ACCEPTANCE_DISRUPTIVE=1, in its own CI step after the main run.
func TestSessionsEndAll(t *testing.T) {
	if os.Getenv("PADDOCK_ACCEPTANCE_DISRUPTIVE") != "1" {
		t.Skip("ends every portal session; set PADDOCK_ACCEPTANCE_DISRUPTIVE=1")
	}
	alice := login(t, env.Alice)
	root := login(t, env.PlatformAdmin)
	idx := auditIndex(t)

	res := call(t, alice, http.MethodPost, "/api/platform/v1/sessions/end-all", nil)
	expectStatus(t, res, http.StatusForbidden, "forbidden")
	res = call(t, root, http.MethodPost, "/api/platform/v1/sessions/end-all", nil)
	expectStatus(t, res, http.StatusForbidden, "step_up_required")
	expectOneIndexEvent(t, idx, platformOrg, "correlation_id = $1", res.RequestID, "platform.sessions_ended", "denied", auditPollTimeout)

	stepUp(t, root, env.PlatformAdmin, true)
	res = call(t, root, http.MethodPost, "/api/platform/v1/sessions/end-all", nil)
	expectStatus(t, res, http.StatusOK, "")
	var ended struct {
		Generation int64 `json:"generation"`
	}
	if err := res.JSON(&ended); err != nil || ended.Generation < 1 {
		t.Fatalf("generation %d %v", ended.Generation, err)
	}
	for name, p := range map[string]*env.Portal{"alice": alice, "platform admin": root} {
		if status := meStatus(t, p); status != http.StatusUnauthorized {
			t.Errorf("%s's session after end all: %d, want 401", name, status)
		}
	}
	// Every helper signs in again; the event is read with a new session.
	for _, user := range []string{env.PlatformAdmin, env.Alice, env.Dave, env.Bob, env.Carol} {
		if p := login(t, user); meStatus(t, p) != http.StatusOK {
			t.Fatalf("%s cannot sign in again", user)
		}
	}
	expectOneIndexEvent(t, idx, platformOrg, "correlation_id = $1", res.RequestID, "platform.sessions_ended", "success", auditPollTimeout)
}

// firstParam is a parameter of the first event (nil without events).
func firstParam(events []env.IndexEvent, name string) any {
	if len(events) == 0 {
		return nil
	}
	return events[0].Params[name]
}

// TestAPITokenCreatorInactive is the gate of PDK-184: an API token stops working once the worker round moved its
// creator to a role that may not hold the token's role, and its refused use is recorded with reason creator_inactive.
func TestAPITokenCreatorInactive(t *testing.T) {
	alice := login(t, env.Alice)
	org := orgOf(t, alice)
	idx := auditIndex(t)
	ak, err := env.NewAuthentik()
	if err != nil {
		t.Fatal(err)
	}
	u := steppedUpTempUser(t, "pdk184", env.RoleGroup("acme", "operators"))
	res := postAPIToken(t, u.Portal, apiTokenName("creator"), "org_operator", 2*time.Hour)
	expectStatus(t, res, http.StatusCreated, "")
	var created apiTokenCreated
	if err := res.JSON(&created); err != nil {
		t.Fatal(err)
	}
	token := tokenPortal(t, created.Secret)
	if status := meStatus(t, token); status != http.StatusOK {
		t.Fatalf("token of an active operator: %d", status)
	}
	if err := ak.MoveGroup(testContext(t, time.Minute), u.username, env.RoleGroup("acme", "operators"), env.RoleGroup("acme", "auditors")); err != nil {
		t.Fatal(err)
	}
	waitUnauthenticated(t, token, accountRoundTimeout)
	for deadline := time.Now().Add(auditPollTimeout); ; time.Sleep(time.Second) {
		events, err := idx.Events(testContext(t, time.Minute), org, "code = 'api_token.use_denied' AND target->>'id' = $1", created.Token.ID)
		if err != nil {
			t.Fatal(err)
		}
		if len(events) > 0 && events[len(events)-1].Params["reason"] == "creator_inactive" {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("use_denied events %+v, want reason creator_inactive", events)
		}
	}
}

// TestSessionsPlatformAdminRemoved is the gate of PDK-185: a platform administrator removed from the platform group
// loses the portal session within the worker's interval, and the revocation is recorded once in the platform
// pseudo-organization.
func TestSessionsPlatformAdminRemoved(t *testing.T) {
	idx := auditIndex(t)
	ak, err := env.NewAuthentik()
	if err != nil {
		t.Fatal(err)
	}
	user, password := tempUser(t, "pdk185", "paddock.platform.admins")
	p, err := loginAs(t, user, password)
	if err != nil {
		t.Fatal(err)
	}
	if m := whoami(t, p); m.Role != "platform_admin" {
		t.Fatalf("role %s, want platform_admin", m.Role)
	}
	if err := ak.RemoveFromGroup(testContext(t, time.Minute), user, "paddock.platform.admins"); err != nil {
		t.Fatal(err)
	}
	waitUnauthenticated(t, p, accountRoundTimeout)
	if ev := revokedEvent(t, idx, platformOrg, user, auditPollTimeout); ev.Params["reason"] != "removed" {
		t.Fatalf("event params %v", ev.Params)
	}
}
