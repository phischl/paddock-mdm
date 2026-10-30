package acceptance

import (
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"slices"
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
		// The deadline is checked against the poll's start, as in expectOneIndexEvent (PDK-551, PDK-561).
		polled := time.Now()
		events, err := idx.Events(ctx, org, "code = 'admin.sessions_revoked' AND target->>'display' = $1", username)
		if err != nil {
			t.Fatal(err)
		}
		if len(events) > 0 || polled.After(deadline) {
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

// authentikUser is the username of the Authentik session in p's cookie jar, "" when Authentik answers that the request
// is not authenticated.
func authentikUser(t *testing.T, p *env.Portal) string {
	t.Helper()
	req, err := http.NewRequestWithContext(testContext(t, time.Minute), http.MethodGet, stack.AuthURL()+"/api/v3/core/users/me/", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Accept", "application/json")
	res, err := authflow.Do(p.Client, req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	var body struct {
		User struct {
			Username string `json:"username"`
		} `json:"user"`
	}
	switch {
	case res.StatusCode == http.StatusUnauthorized || res.StatusCode == http.StatusForbidden:
		return ""
	case res.StatusCode != http.StatusOK:
		t.Fatalf("GET /api/v3/core/users/me/: HTTP %d", res.StatusCode)
	}
	if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	return body.User.Username
}

// TestSessionsLogoutEndsAuthentikSession (PDK-532): the logout's end_session_url is Authentik's brand invalidation
// flow, and running it ends the Authentik session of the browser, so the next sign-in asks for credentials again
// instead of reusing it.
func TestSessionsLogoutEndsAuthentikSession(t *testing.T) {
	alice := login(t, env.Alice)
	if user := authentikUser(t, alice); user != env.Alice {
		t.Fatalf("Authentik session before logout: %q, want %s", user, env.Alice)
	}
	res := call(t, alice, http.MethodPost, "/api/auth/logout", nil)
	expectStatus(t, res, http.StatusOK, "")
	var body struct {
		EndSessionURL string `json:"end_session_url"`
	}
	if err := res.JSON(&body); err != nil {
		t.Fatal(err)
	}
	auth, err := url.Parse(stack.AuthURL())
	if err != nil {
		t.Fatal(err)
	}
	next, err := url.Parse(body.EndSessionURL)
	if err != nil || next.Scheme != auth.Scheme || next.Host != auth.Host || next.Path != "/flows/-/default/invalidation/" {
		t.Fatalf("end_session_url %q, want the brand invalidation flow on %s", body.EndSessionURL, auth.Host)
	}

	// The browser follows the redirects to the flow page, whose flow the executor API then runs.
	ctx := testContext(t, time.Minute)
	for hop := 0; !strings.HasPrefix(next.Path, "/if/flow/"); hop++ {
		if hop == 5 {
			t.Fatalf("no flow page after %d redirects from %s", hop, body.EndSessionURL)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, next.String(), nil)
		if err != nil {
			t.Fatal(err)
		}
		r, err := authflow.Do(alice.Client, req)
		if err != nil {
			t.Fatal(err)
		}
		_ = r.Body.Close()
		loc, err := r.Location()
		if r.StatusCode < 300 || r.StatusCode >= 400 || err != nil {
			t.Fatalf("GET %s: HTTP %d %v", next, r.StatusCode, err)
		}
		next = loc
	}
	if _, err := authflow.RunFlow(ctx, alice.Client, next.String(), "", "", nil); err != nil {
		t.Fatalf("invalidation flow %s: %v", next, err)
	}

	if user := authentikUser(t, alice); user != "" {
		t.Fatalf("Authentik session after logout: %q, want none", user)
	}
	if status := meStatus(t, alice); status != http.StatusUnauthorized {
		t.Fatalf("portal session after logout: %d, want 401", status)
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
		// A member of the organization's root group, as synced users are: Authentik's portal-member policy then still
		// lets the step-up run, and the callback sees that the groups no longer grant the admin role. A user in no
		// Paddock group at all is refused by Authentik before the callback; the worker round ends that session.
		u := mfaTempUser(t, "s10", env.RootGroup("acme"), env.RoleGroup("acme", "admins"))
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
	// Each waits for the same worker round with its own temporary user, so the four session gates run together after
	// the sequential gates (PDK-189).
	t.Parallel()
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
	// Each waits for the same worker round with its own temporary user, so the four session gates run together after
	// the sequential gates (PDK-189).
	t.Parallel()
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
	ak, err := env.NewAuthentik()
	if err != nil {
		t.Fatal(err)
	}
	// identitySessions counts the Authentik sessions of user (plan M8f decision 20).
	identitySessions := func(user string) int {
		t.Helper()
		var res struct {
			Results []json.RawMessage `json:"results"`
		}
		if err := ak.Get(testContext(t, time.Minute), "/core/authenticated_sessions/?user__username="+url.QueryEscape(user), &res); err != nil {
			t.Fatal(err)
		}
		return len(res.Results)
	}
	if n := identitySessions(env.Alice); n < 1 {
		t.Fatalf("alice has %d Authentik sessions after signing in, want at least 1", n)
	}

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
	for _, user := range []string{env.Alice, env.PlatformAdmin} {
		if n := identitySessions(user); n != 0 {
			t.Errorf("%s has %d Authentik sessions after end all, want 0", user, n)
		}
	}
	// Every helper signs in again; the event is read with a new session.
	for _, user := range []string{env.PlatformAdmin, env.Alice, env.Dave, env.Bob, env.Carol} {
		if p := login(t, user); meStatus(t, p) != http.StatusOK {
			t.Fatalf("%s cannot sign in again", user)
		}
	}
	ev := expectOneIndexEvent(t, idx, platformOrg, "correlation_id = $1", res.RequestID, "platform.sessions_ended", "success", auditPollTimeout)
	if ended, users := numParam(ev, "identity_sessions_ended"), numParam(ev, "identity_users"); ended < 2 || users < 5 {
		t.Fatalf("identity_sessions_ended %v, identity_users %v; want at least 2 and 5: %+v", ended, users, ev.Params)
	}
}

// numParam is a numeric event parameter (-1 when absent).
func numParam(ev env.IndexEvent, name string) float64 {
	if v, ok := ev.Params[name].(float64); ok {
		return v
	}
	return -1
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
	// Each waits for the same worker round with its own temporary user, so the four session gates run together after
	// the sequential gates (PDK-189).
	t.Parallel()
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
		// The deadline is checked against the poll's start, as in expectOneIndexEvent (PDK-551, PDK-561).
		polled := time.Now()
		events, err := idx.Events(testContext(t, time.Minute), org, "code = 'api_token.use_denied' AND target->>'id' = $1", created.Token.ID)
		if err != nil {
			t.Fatal(err)
		}
		if len(events) > 0 && events[len(events)-1].Params["reason"] == "creator_inactive" {
			return
		}
		if polled.After(deadline) {
			t.Fatalf("use_denied events %+v, want reason creator_inactive", events)
		}
	}
}

// TestSessionsPlatformAdminRemoved is the gate of PDK-185: a platform administrator removed from the platform group
// loses the portal session within the worker's interval, and the revocation is recorded once in the platform
// pseudo-organization.
func TestSessionsPlatformAdminRemoved(t *testing.T) {
	// Each waits for the same worker round with its own temporary user, so the four session gates run together after
	// the sequential gates (PDK-189).
	t.Parallel()
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

// platformAdminsGroup is the group that grants the role platform_admin.
const platformAdminsGroup = "paddock.platform.admins"

// TestSessionsPlatformEmptied is the gate of PDK-534: when the last members leave paddock.platform.admins, the worker's
// platform round ends their portal sessions (admin.sessions_revoked, reason removed) within two rounds, and the second
// round that misses them revokes their role. It empties the platform group of the stack, so it runs only with
// PADDOCK_ACCEPTANCE_DISRUPTIVE=1, alone; the cleanup puts the members back whatever happened and checks that the
// development platform administrator signs in with its role again.
func TestSessionsPlatformEmptied(t *testing.T) {
	if os.Getenv("PADDOCK_ACCEPTANCE_DISRUPTIVE") != "1" {
		t.Skip("empties paddock.platform.admins; set PADDOCK_ACCEPTANCE_DISRUPTIVE=1")
	}
	ak, err := env.NewAuthentik()
	if err != nil {
		t.Fatal(err)
	}
	// A run killed before its cleanup (a test timeout or an interrupt skips t.Cleanup) leaves the development platform
	// administrator outside the group; a new run repairs that before it reads the members it will restore.
	if err := ak.AddToGroup(testContext(t, time.Minute), env.PlatformAdmin, platformAdminsGroup); err != nil {
		t.Fatal(err)
	}
	members, err := ak.GroupMembers(testContext(t, time.Minute), platformAdminsGroup)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { restorePlatformAdmins(t, ak, members) })

	created := time.Now()
	user, password := tempUser(t, "pdk534", platformAdminsGroup)
	root := login(t, env.PlatformAdmin)
	second, err := loginAs(t, user, password)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []*env.Portal{root, second} {
		if m := whoami(t, p); m.Role != "platform_admin" {
			t.Fatalf("role of %s %s, want platform_admin", p.User, m.Role)
		}
	}
	idx := auditIndex(t)
	// admin.role_revoked follows only for a member a round has stored, so the temporary user's grant comes first; the
	// development platform administrator is stored since the stack's first round.
	if ev := platformEventsSince(t, idx, "admin.role_granted", "params->>'username'", user, created, roleEventWait); len(ev) != 1 {
		t.Fatalf("admin.role_granted of %s: %+v, want one", user, ev)
	}
	if n := paddockSQL(t, "SELECT count(*) FROM platform_role_member WHERE role = 'platform_admin' AND username = '"+
		env.PlatformAdmin+"' AND missing_since IS NULL"); n != "1" {
		t.Fatalf("stored listed platform_admin rows of %s: %s, want 1", env.PlatformAdmin, n)
	}
	emptied := time.Now()
	for _, m := range append(slices.Clone(members), user) {
		if err := ak.RemoveFromGroup(testContext(t, time.Minute), m, platformAdminsGroup); err != nil {
			t.Fatal(err)
		}
	}
	if left, err := ak.GroupMembers(testContext(t, time.Minute), platformAdminsGroup); err != nil || len(left) != 0 {
		t.Fatalf("%s after removing every member: %v (%v), want empty", platformAdminsGroup, left, err)
	}

	// The first round that lists the empty group ends the sessions; a round that started before the last removal may
	// still list a member, so the bound is two rounds.
	for _, p := range []*env.Portal{root, second} {
		waitUnauthenticated(t, p, 2*accountRoundTimeout)
	}
	for _, u := range []string{env.PlatformAdmin, user} {
		ev := platformEventsSince(t, idx, "admin.sessions_revoked", "target->>'display'", u, emptied, auditPollTimeout)
		if len(ev) != 1 || ev[0].Outcome != "success" || ev[0].Params["reason"] != "removed" {
			t.Fatalf("admin.sessions_revoked of %s since the group was emptied: %+v, want one success with reason removed", u, ev)
		}
	}
	// A revocation needs two consecutive listings that miss the member; the first may have run before the sessions
	// ended, so the second follows within one more round.
	for _, u := range []string{env.PlatformAdmin, user} {
		ev := platformEventsSince(t, idx, "admin.role_revoked", "params->>'username'", u, emptied, accountRoundTimeout+roleAuditWait)
		if len(ev) != 1 || ev[0].Outcome != "success" || ev[0].Params["role"] != "platform_admin" {
			t.Fatalf("admin.role_revoked of %s since the group was emptied: %+v, want one success for platform_admin", u, ev)
		}
	}
}

// platformEventsSince waits up to wait until the platform pseudo-organization has an event code whose field (a SQL
// expression of the index) is username, occurred after since, and returns them all. The username comes from the test
// itself (a development user or a random temporary one), never from the stack.
func platformEventsSince(t *testing.T, idx *env.AuditIndex, code, field, username string, since time.Time, wait time.Duration) []env.IndexEvent {
	t.Helper()
	where := "code = '" + code + "' AND " + field + " = '" + username + "' AND occurred_at > $1"
	for deadline := time.Now().Add(wait); ; time.Sleep(2 * time.Second) {
		events, err := idx.Events(testContext(t, time.Minute), platformOrg, where, since)
		if err != nil {
			t.Fatal(err)
		}
		if len(events) > 0 || time.Now().After(deadline) {
			return events
		}
	}
}

// restorePlatformAdmins puts members back into paddock.platform.admins and checks that the development platform
// administrator signs in with its role again, so a failure midway leaves the following gates, the development seed and
// the e2e suite a stack they can sign in to. A member deleted in the meantime is skipped.
func restorePlatformAdmins(t *testing.T, ak *env.Authentik, members []string) {
	t.Helper()
	for _, m := range members {
		var err error
		for deadline := time.Now().Add(time.Minute); ; time.Sleep(2 * time.Second) {
			var pk int
			if pk, err = ak.UserPK(testContext(t, time.Minute), m); err == nil {
				if pk == 0 {
					break
				}
				err = ak.AddToGroup(testContext(t, time.Minute), m, platformAdminsGroup)
			}
			if err == nil || time.Now().After(deadline) {
				break
			}
		}
		if err != nil {
			t.Errorf("restore %s in %s: %v; add it back in Authentik before the next gate", m, platformAdminsGroup, err)
		}
	}
	p, err := env.Login(testContext(t, time.Minute), env.PlatformAdmin, "")
	if err != nil {
		t.Errorf("%s cannot sign in after the restore: %v", env.PlatformAdmin, err)
		return
	}
	if m := whoami(t, p); m.Role != "platform_admin" {
		t.Errorf("role of %s after the restore %s, want platform_admin", env.PlatformAdmin, m.Role)
	}
}
