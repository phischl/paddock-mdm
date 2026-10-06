package admin_test

import (
	"context"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/platform/httpx"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/transport/http/admin/adminapi"
)

// domains sets the domains of org (platform API) and returns the response.
func (e *env) domains(org uuid.UUID, domains ...string) result {
	e.t.Helper()
	return e.do(call{method: "PATCH", path: "/api/platform/v1/organizations/" + org.String(), cookie: e.platformSession(),
		body: map[string]any{"domains": domains}})
}

// outboxSubjects returns subject and scope of the state change rows of org, oldest first.
func (e *env) outboxSubjects(org uuid.UUID) []string {
	e.t.Helper()
	rows, err := e.super.Query(context.Background(),
		"SELECT subject || '|' || (payload->>'scope') FROM outbox WHERE subject LIKE 'state.%' AND organization_id = $1 ORDER BY id", org)
	if err != nil {
		e.t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			e.t.Fatal(err)
		}
		out = append(out, s)
	}
	return out
}

// actionParam returns a param of the action recorded for a request.
func (e *env) actionParam(r result, key string) string {
	e.t.Helper()
	var v string
	if err := e.super.QueryRow(context.Background(), "SELECT coalesce(params->>$2, '') FROM action WHERE correlation_id = $1",
		r.header.Get("X-Request-Id"), key).Scan(&v); err != nil {
		e.t.Fatal(err)
	}
	return v
}

func TestOrganizationDomains(t *testing.T) {
	e := newEnv(t)
	res := e.domains(e.acme, "acme-"+e.acme.String()[:8]+".test", "acme-mail.test")
	if res.status != http.StatusOK {
		t.Fatalf("set domains: %d %s", res.status, res.body)
	}
	e.expectEvent(res, "organization.domains_changed:success:")
	var o adminapi.Organization
	res.decode(t, &o)
	if len(o.Domains) != 2 || !strings.HasPrefix(o.Domains[0], "acme-") {
		t.Fatalf("domains %v", o.Domains)
	}
	// The same domain for another organization.
	taken := e.domains(e.globex, "acme-mail.test")
	if taken.status != http.StatusConflict || taken.problemCode(t) != "domain_taken" {
		t.Fatalf("taken: %d %s", taken.status, taken.body)
	}
	e.expectEvent(taken, "organization.domains_changed:failure:domain_taken")
	if bad := e.domains(e.globex, "Not A Domain"); bad.status != http.StatusBadRequest {
		t.Fatalf("invalid domain: %d", bad.status)
	}
	// Organization administrators may not change domains.
	alice := e.session(e.acme, principal.RoleOrgAdmin)
	denied := e.do(call{method: "PATCH", path: "/api/platform/v1/organizations/" + e.acme.String(), cookie: alice,
		body: map[string]any{"domains": []string{"x.test"}}})
	if denied.status != http.StatusForbidden {
		t.Fatalf("org admin: %d", denied.status)
	}
	if subjects := e.outboxSubjects(e.acme); !slices.Contains(subjects, "state."+e.acme.String()+"|org") {
		t.Fatalf("no recompile of the organization: %v", subjects)
	}
}

func TestUserLifecycleAndLock(t *testing.T) {
	e := newEnv(t)
	domain := "u" + e.acme.String()[:8] + ".test"
	if res := e.domains(e.acme, domain); res.status != http.StatusOK {
		t.Fatalf("domains: %d", res.status)
	}
	alice := e.session(e.acme, principal.RoleOrgAdmin)
	operator := e.session(e.acme, principal.RoleOrgOperator)
	carol := e.session(e.globex, principal.RoleOrgAdmin)

	created := e.do(call{method: "POST", path: "/api/v1/users", cookie: operator, body: map[string]any{
		"username": "Dave@" + domain, "display_name": "Dave", "email": "dave@" + domain,
	}})
	if created.status != http.StatusCreated {
		t.Fatalf("create: %d %s", created.status, created.body)
	}
	e.expectEvent(created, "user.created:success:")
	var c adminapi.UserCreated
	created.decode(t, &c)
	if c.User.Username != "dave@"+domain || c.User.Source != "local" || !strings.Contains(c.RecoveryLink, "paddock-recovery") {
		t.Fatalf("created %+v", c)
	}
	if strings.Contains(string(e.actionParam(created, "recovery_link")), "flow_token") {
		t.Fatal("the recovery link was audited")
	}
	for name, body := range map[string]map[string]any{
		"duplicate":    {"username": "dave@" + domain, "display_name": "Dave 2"},
		"wrong domain": {"username": "dave@elsewhere.test", "display_name": "Dave"},
	} {
		res := e.do(call{method: "POST", path: "/api/v1/users", cookie: alice, body: body})
		want := map[string]int{"duplicate": http.StatusConflict, "wrong domain": http.StatusBadRequest}[name]
		if res.status != want {
			t.Fatalf("%s: %d %s", name, res.status, res.body)
		}
	}

	// Another organization does not see the user.
	if res := e.do(call{method: "GET", path: "/api/v1/users/" + c.User.Id.String(), cookie: carol}); res.status != http.StatusNotFound {
		t.Fatalf("cross-organization get: %d", res.status)
	}
	list := e.do(call{method: "GET", path: "/api/v1/users?q=dave&source=local", cookie: operator})
	var page adminapi.UserPage
	list.decode(t, &page)
	if page.Total != 1 || page.Items[0].Id != c.User.Id {
		t.Fatalf("list %+v", page)
	}

	upd := e.do(call{method: "PATCH", path: "/api/v1/users/" + c.User.Id.String(), cookie: operator, body: map[string]any{"display_name": "Dave D."}})
	if upd.status != http.StatusOK {
		t.Fatalf("update: %d %s", upd.status, upd.body)
	}
	e.expectEvent(upd, "user.updated:success:")

	// Only administrators lock; the lock reaches the compiler's priority lane.
	if res := e.do(call{method: "POST", path: "/api/v1/users/" + c.User.Id.String() + "/lock", cookie: operator}); res.status != http.StatusForbidden {
		t.Fatalf("operator lock: %d", res.status)
	}
	locked := e.do(call{method: "POST", path: "/api/v1/users/" + c.User.Id.String() + "/lock", cookie: alice})
	if locked.status != http.StatusOK {
		t.Fatalf("lock: %d %s", locked.status, locked.body)
	}
	e.expectEvent(locked, "user.locked:success:")
	var u adminapi.User
	locked.decode(t, &u)
	pk := e.authentikPK(c.User.Id)
	if !u.Locked || u.LockIncomplete || u.LockedAt == nil || !e.idp.locked[pk] {
		t.Fatalf("after lock %+v, idp %v", u, e.idp.locked)
	}
	if subjects := e.outboxSubjects(e.acme); !slices.Contains(subjects, "state.priority."+e.acme.String()+"|user") {
		t.Fatalf("no priority state change: %v", subjects)
	}
	unlocked := e.do(call{method: "POST", path: "/api/v1/users/" + c.User.Id.String() + "/unlock", cookie: alice})
	unlocked.decode(t, &u)
	if unlocked.status != http.StatusOK || u.Locked || e.idp.locked[pk] {
		t.Fatalf("unlock: %d %+v", unlocked.status, u)
	}

	// A lock while Authentik is down still marks the user locked for the devices; the attempt fails.
	e.idp.fail = true
	failed := e.do(call{method: "POST", path: "/api/v1/users/" + c.User.Id.String() + "/lock", cookie: alice})
	e.idp.fail = false
	if failed.status != http.StatusBadGateway {
		t.Fatalf("lock with Authentik down: %d", failed.status)
	}
	e.expectEvent(failed, "user.locked:failure:upstream_unavailable")
	got := e.do(call{method: "GET", path: "/api/v1/users/" + c.User.Id.String(), cookie: alice})
	var d adminapi.UserDetail
	got.decode(t, &d)
	if !d.Locked || !d.LockIncomplete {
		t.Fatalf("a failed Authentik call must leave the user locked and the lock incomplete: %+v", d)
	}
	// Locking again retries the Authentik part and completes the lock.
	retried := e.do(call{method: "POST", path: "/api/v1/users/" + c.User.Id.String() + "/lock", cookie: alice})
	if retried.status != http.StatusOK {
		t.Fatalf("retry lock: %d %s", retried.status, retried.body)
	}
	e.expectEvent(retried, "user.locked:success:")
	retried.decode(t, &u)
	if !u.Locked || u.LockIncomplete || !e.idp.locked[pk] {
		t.Fatalf("after the retry %+v, idp %v", u, e.idp.locked)
	}

	del := e.do(call{method: "DELETE", path: "/api/v1/users/" + c.User.Id.String(), cookie: alice})
	if del.status != http.StatusNoContent || len(e.idp.users) != 0 {
		t.Fatalf("delete: %d, idp users %v", del.status, e.idp.users)
	}
	e.expectEvent(del, "user.deleted:success:")
}

func TestSyncedUserIsReadOnly(t *testing.T) {
	e := newEnv(t)
	alice := e.session(e.acme, principal.RoleOrgAdmin)
	id := uuid.Must(uuid.NewV7())
	if _, err := e.super.Exec(context.Background(), `INSERT INTO app_user (id, organization_id, authentik_pk, username, display_name, source)
		VALUES ($1, $2, $3, $4, 'Erin', 'synced')`, id, e.acme, "9"+id.String()[30:], "erin-"+id.String()[30:]+"@upstream.test"); err != nil {
		t.Fatal(err)
	}
	for _, c := range []call{
		{method: "PATCH", path: "/api/v1/users/" + id.String(), cookie: alice, body: map[string]any{"display_name": "x"}},
		{method: "DELETE", path: "/api/v1/users/" + id.String(), cookie: alice},
	} {
		res := e.do(c)
		if res.status != http.StatusConflict || res.problemCode(t) != "attribute_owned_upstream" {
			t.Fatalf("%s: %d %s", c.method, res.status, res.body)
		}
	}
	// Paddock-owned attributes stay writable: a synced user can be locked.
	if res := e.do(call{method: "POST", path: "/api/v1/users/" + id.String() + "/lock", cookie: alice}); res.status != http.StatusOK {
		t.Fatalf("lock synced user: %d %s", res.status, res.body)
	}
}

func TestGroupsProfilesAndEffectiveProfile(t *testing.T) {
	e := newEnv(t)
	domain := "g" + e.acme.String()[:8] + ".test"
	e.domains(e.acme, domain)
	alice := e.session(e.acme, principal.RoleOrgAdmin)
	auditor := e.session(e.acme, principal.RoleOrgAuditor)

	var dave adminapi.UserCreated
	e.do(call{method: "POST", path: "/api/v1/users", cookie: alice, body: map[string]any{"username": "dave@" + domain, "display_name": "Dave"}}).decode(t, &dave)
	device := e.insertDevice(e.acme, "laptop-"+domain, "active")

	grpRes := e.do(call{method: "POST", path: "/api/v1/user-groups", cookie: alice, body: map[string]any{"slug": "ops", "name": "Operations"}})
	if grpRes.status != http.StatusCreated {
		t.Fatalf("create group: %d %s", grpRes.status, grpRes.body)
	}
	var grp adminapi.UserGroup
	grpRes.decode(t, &grp)
	if !strings.HasSuffix(grp.AuthentikName, ".g.ops") || grp.Source != "local" {
		t.Fatalf("group %+v", grp)
	}
	if dup := e.do(call{method: "POST", path: "/api/v1/user-groups", cookie: alice, body: map[string]any{"slug": "ops", "name": "x"}}); dup.status != http.StatusConflict {
		t.Fatalf("duplicate slug: %d", dup.status)
	}

	// Two restricted profiles, harmless alone, combine into a root-equivalent set (gate P2).
	copyHelper := e.profile(alice, map[string]any{"name": "deploy", "class": "restricted",
		"commands": []string{"/usr/bin/cp /srv/build/helper /opt/tools/helper"}})
	runHelper := e.profile(alice, map[string]any{"name": "run", "class": "restricted", "commands": []string{"/opt/tools/helper --sync"}})
	if copyHelper.RootEquivalent || runHelper.RootEquivalent {
		t.Fatal("a harmless profile is flagged")
	}
	for _, command := range []string{
		"/usr/bin/a, /usr/bin/b",
		// '#' after whitespace starts a sudoers comment: this would grant /usr/bin/x with any arguments.
		"/usr/bin/x #y, /usr/bin/z",
	} {
		bad := e.do(call{method: "POST", path: "/api/v1/permission-profiles", cookie: alice, body: map[string]any{
			"name": "bad", "class": "restricted", "commands": []string{command},
		}})
		if bad.status != http.StatusUnprocessableEntity || bad.problemCode(t) != "invalid_command" {
			t.Fatalf("invalid command %q: %d %s", command, bad.status, bad.body)
		}
		e.expectEvent(bad, "permission_profile.created:failure:invalid_command")
	}
	root := e.profile(alice, map[string]any{"name": "editor", "class": "restricted", "commands": []string{"/usr/bin/vim /etc/hosts"}})
	if !root.RootEquivalent || len(root.RootEquivalentCommands) != 1 {
		t.Fatalf("vim profile %+v", root)
	}

	e.assign(alice, map[string]any{"profile_id": copyHelper.Id, "subject_type": "user", "subject_id": dave.User.Id})
	assignment := e.assign(alice, map[string]any{"profile_id": runHelper.Id, "subject_type": "group", "subject_id": grp.Id})

	// Membership is a privilege change: the event carries the highest class before and after.
	add := e.do(call{method: "POST", path: "/api/v1/user-groups/" + grp.Id.String() + "/members", cookie: alice,
		body: map[string]any{"user_id": dave.User.Id}})
	if add.status != http.StatusNoContent {
		t.Fatalf("add member: %d %s", add.status, add.body)
	}
	e.expectEvent(add, "user_group.member_added:success:")
	if before, after := e.actionParam(add, "effective_class_before"), e.actionParam(add, "effective_class_after"); before != "restricted" || after != "full" {
		t.Fatalf("classes %s → %s, want restricted → full (root-equivalent combination)", before, after)
	}
	if members := e.idp.members[grpPK(e, grp.AuthentikName)]; len(members) != 1 {
		t.Fatalf("Authentik members %v", members)
	}

	eff := e.do(call{method: "GET", path: "/api/v1/users/" + dave.User.Id.String() + "/effective-profile?device_id=" + device.String(), cookie: auditor})
	if eff.status != http.StatusOK {
		t.Fatalf("effective profile: %d %s", eff.status, eff.body)
	}
	var ep adminapi.UserEffectiveProfile
	eff.decode(t, &ep)
	if ep.Class != "restricted" || ep.ReportedClass != "full" || !ep.RootEquivalent || len(ep.Commands) != 2 {
		t.Fatalf("effective %+v", ep)
	}
	fromGroup := false
	for _, d := range ep.Derivation {
		if d.Kind == "command" && d.Item == "/opt/tools/helper --sync" && d.AssignmentId == assignment.Id && d.ProfileName == "run" &&
			d.Subject.Type == "group" && *d.Subject.Id == grp.Id {
			fromGroup = true
		}
	}
	if !fromGroup {
		t.Fatalf("derivation lacks the group assignment: %+v", ep.Derivation)
	}

	sudo := e.do(call{method: "GET", path: "/api/v1/devices/" + device.String() + "/effective-sudo", cookie: auditor})
	var es adminapi.EffectiveSudo
	sudo.decode(t, &es)
	if sudo.status != http.StatusOK || len(es.Entries) != 1 || es.Entries[0].User.Id != dave.User.Id {
		t.Fatalf("effective sudo: %d %+v", sudo.status, es)
	}

	// A profile that is assigned cannot be deleted; its class change is audited.
	if res := e.do(call{method: "DELETE", path: "/api/v1/permission-profiles/" + runHelper.Id.String(), cookie: alice}); res.status != http.StatusConflict {
		t.Fatalf("delete assigned profile: %d", res.status)
	}
	// Changing the class to full needs a fresh step-up (plan M4a decision 7).
	for _, cookie := range []*http.Cookie{alice, e.steppedUp(alice, time.Now().Add(-301*time.Second))} {
		res := e.do(call{method: "PATCH", path: "/api/v1/permission-profiles/" + runHelper.Id.String(), cookie: cookie, body: map[string]any{"class": "full"}})
		if res.status != http.StatusForbidden || res.problemCode(t) != "step_up_required" {
			t.Fatalf("class change without fresh step-up: %d %s", res.status, res.body)
		}
		e.expectEvent(res, "permission_profile.updated:denied:step_up_required")
	}
	toFull := e.do(call{method: "PATCH", path: "/api/v1/permission-profiles/" + runHelper.Id.String(), cookie: e.steppedUp(alice, time.Now()), body: map[string]any{"class": "full"}})
	var full adminapi.PermissionProfile
	toFull.decode(t, &full)
	if toFull.status != http.StatusOK || full.Class != "full" || len(full.Commands) != 0 {
		t.Fatalf("class change: %d %+v", toFull.status, full)
	}
	if e.actionParam(toFull, "old_class") != "restricted" {
		t.Fatal("old class not audited")
	}
	// Assigning a full profile needs a fresh step-up as well.
	fullAssignment := map[string]any{"profile_id": runHelper.Id, "subject_type": "user", "subject_id": dave.User.Id}
	denied := e.do(call{method: "POST", path: "/api/v1/profile-assignments", cookie: alice, body: fullAssignment})
	if denied.status != http.StatusForbidden || denied.problemCode(t) != "step_up_required" {
		t.Fatalf("full assignment without step-up: %d %s", denied.status, denied.body)
	}
	e.expectEvent(denied, "profile_assignment.created:denied:step_up_required")
	granted := e.assign(e.steppedUp(alice, time.Now()), fullAssignment)
	if res := e.do(call{method: "DELETE", path: "/api/v1/profile-assignments/" + granted.Id.String(), cookie: alice}); res.status != http.StatusNoContent {
		t.Fatalf("delete full assignment: %d", res.status)
	}

	// Removing the member and the group.
	rm := e.do(call{method: "DELETE", path: "/api/v1/user-groups/" + grp.Id.String() + "/members/" + dave.User.Id.String(), cookie: alice})
	if rm.status != http.StatusNoContent || e.actionParam(rm, "effective_class_after") != "restricted" {
		t.Fatalf("remove member: %d after=%s", rm.status, e.actionParam(rm, "effective_class_after"))
	}
	if res := e.do(call{method: "DELETE", path: "/api/v1/user-groups/" + grp.Id.String(), cookie: alice}); res.status != http.StatusNoContent {
		t.Fatalf("delete group: %d", res.status)
	}
	// The group's assignment went with it.
	if res := e.do(call{method: "GET", path: "/api/v1/profile-assignments/" + assignment.Id.String(), cookie: alice}); res.status != http.StatusNotFound {
		t.Fatalf("assignment of a deleted group: %d", res.status)
	}
}

func grpPK(e *env, name string) string {
	for pk, n := range e.idp.groups {
		if n == name {
			return pk
		}
	}
	return ""
}

// TestPatternCommandsAreRefused: sudo regular expressions and globs widen a restricted command, so every pattern
// character is refused with 422 invalid_command naming it; a profile stored before the check was tightened is
// reported with its invalid commands (plan M3.1 decision 1).
func TestPatternCommandsAreRefused(t *testing.T) {
	e := newEnv(t)
	alice := e.session(e.acme, principal.RoleOrgAdmin)
	for _, char := range []string{"^", "$", "*", "?", "[", "]"} {
		res := e.do(call{method: "POST", path: "/api/v1/permission-profiles", cookie: alice, body: map[string]any{
			"name": "pattern", "class": "restricted", "commands": []string{"/usr/bin/systemctl restart x" + char},
		}})
		var p httpx.Problem
		res.decode(t, &p)
		if res.status != http.StatusUnprocessableEntity || p.Code != "invalid_command" ||
			!strings.Contains(p.Detail, "character '"+char+"' is not allowed") {
			t.Fatalf("%s: %d %s", char, res.status, res.body)
		}
		e.expectEvent(res, "permission_profile.created:failure:invalid_command")
	}

	valid := e.profile(alice, map[string]any{"name": "nginx", "class": "restricted", "commands": []string{"/usr/bin/systemctl restart nginx.service"}})
	if len(valid.InvalidCommands) != 0 {
		t.Fatalf("valid profile reported invalid: %+v", valid)
	}
	id := uuid.Must(uuid.NewV7())
	if _, err := e.super.Exec(context.Background(), `INSERT INTO permission_profile (id, organization_id, name, class, commands)
		VALUES ($1, $2, 'legacy', 'restricted', '{"/usr/bin/journalctl","/usr/bin/systemctl ^.*$"}')`, id, e.acme); err != nil {
		t.Fatal(err)
	}
	res := e.do(call{method: "GET", path: "/api/v1/permission-profiles/" + id.String(), cookie: alice})
	var legacy adminapi.PermissionProfile
	res.decode(t, &legacy)
	if res.status != http.StatusOK || !slices.Equal(legacy.InvalidCommands, []string{"/usr/bin/systemctl ^.*$"}) {
		t.Fatalf("legacy profile: %d %s", res.status, res.body)
	}
	// The stored profile cannot be saved until the command is fixed.
	patch := e.do(call{method: "PATCH", path: "/api/v1/permission-profiles/" + id.String(), cookie: alice, body: map[string]any{"lecture": "always"}})
	if patch.status != http.StatusUnprocessableEntity || patch.problemCode(t) != "invalid_command" {
		t.Fatalf("patch of the legacy profile: %d %s", patch.status, patch.body)
	}
}

func (e *env) profile(cookie *http.Cookie, body map[string]any) adminapi.PermissionProfile {
	e.t.Helper()
	res := e.do(call{method: "POST", path: "/api/v1/permission-profiles", cookie: cookie, body: body})
	if res.status != http.StatusCreated {
		e.t.Fatalf("create profile: %d %s", res.status, res.body)
	}
	var p adminapi.PermissionProfile
	res.decode(e.t, &p)
	return p
}

func (e *env) assign(cookie *http.Cookie, body map[string]any) adminapi.ProfileAssignment {
	e.t.Helper()
	res := e.do(call{method: "POST", path: "/api/v1/profile-assignments", cookie: cookie, body: body})
	if res.status != http.StatusCreated {
		e.t.Fatalf("assign: %d %s", res.status, res.body)
	}
	var a adminapi.ProfileAssignment
	res.decode(e.t, &a)
	return a
}

func TestLoginSettingsAssignmentAndSuspension(t *testing.T) {
	e := newEnv(t)
	domain := "l" + e.acme.String()[:8] + ".test"
	e.domains(e.acme, domain)
	alice := e.session(e.acme, principal.RoleOrgAdmin)
	operator := e.session(e.acme, principal.RoleOrgOperator)

	var s adminapi.LoginSettings
	e.do(call{method: "GET", path: "/api/v1/settings/login", cookie: operator}).decode(t, &s)
	if !s.HelloEnabled || s.HelloPinMinLength != 6 || len(s.SudoersDAllowlist) != 1 || s.BootPinMinLength != 8 {
		t.Fatalf("defaults %+v", s)
	}
	put := map[string]any{
		"hello_enabled": true, "hello_pin_min_length": 8, "user_lock_session_action": "terminate",
		"break_glass_accounts": []string{"paddock"}, "sudoers_d_allowlist": []string{"README", "90-paddock"},
		"sudo_lecture_text": "Be careful.", "local_admin_username": "paddock-admin", "local_admin_rotation_days": 30,
		"notice_text": "Managed device.\r\nBe nice.", "boot_pin_min_length": 12,
	}
	if s.LocalAdminUsername != "paddock-admin" || s.LocalAdminRotationDays != 30 || s.RotateAfterRevealHours != nil {
		t.Fatalf("local admin defaults %+v", s)
	}
	if res := e.do(call{method: "PUT", path: "/api/v1/settings/login", cookie: operator, body: put}); res.status != http.StatusForbidden {
		t.Fatalf("operator changes settings: %d", res.status)
	}
	res := e.do(call{method: "PUT", path: "/api/v1/settings/login", cookie: alice, body: put})
	if res.status != http.StatusOK {
		t.Fatalf("settings: %d %s", res.status, res.body)
	}
	e.expectEvent(res, "settings.login_changed:success:")
	var saved adminapi.LoginSettings
	res.decode(t, &saved)
	if saved.NoticeText != "Managed device.\nBe nice." || saved.BootPinMinLength != 12 {
		t.Fatalf("notice %q, boot PIN length %d", saved.NoticeText, saved.BootPinMinLength)
	}
	put["sudoers_d_allowlist"] = []string{"paddock-u-0123456789abcdef"}
	if res := e.do(call{method: "PUT", path: "/api/v1/settings/login", cookie: alice, body: put}); res.status != http.StatusBadRequest {
		t.Fatalf("Paddock file allow-listed: %d", res.status)
	}
	put["sudoers_d_allowlist"] = []string{"README"}

	// The local administrator's name can change until a device has an active password for it (plan M4a decision 13).
	put["local_admin_username"], put["rotate_after_reveal_hours"] = "fleet-admin", 24
	res = e.do(call{method: "PUT", path: "/api/v1/settings/login", cookie: alice, body: put})
	var changed adminapi.LoginSettings
	res.decode(t, &changed)
	if res.status != http.StatusOK || changed.LocalAdminUsername != "fleet-admin" || changed.RotateAfterRevealHours == nil || *changed.RotateAfterRevealHours != 24 {
		t.Fatalf("local admin settings: %d %s", res.status, res.body)
	}
	adminDevice := e.insertDevice(e.acme, "admin-"+domain, "active")
	if _, err := e.super.Exec(context.Background(), `INSERT INTO escrow_secret (id, organization_id, device_id, kind, generation, status,
		ciphertext, key_version) VALUES ($1, $2, $3, 'admin_password', 1, 'active', '\x01', 1)`, uuid.New(), e.acme, adminDevice); err != nil {
		t.Fatal(err)
	}
	put["local_admin_username"] = "other-admin"
	locked := e.do(call{method: "PUT", path: "/api/v1/settings/login", cookie: alice, body: put})
	if locked.status != http.StatusConflict || locked.problemCode(t) != "setting_locked" {
		t.Fatalf("rename with an active password: %d %s", locked.status, locked.body)
	}
	e.expectEvent(locked, "settings.login_changed:failure:setting_locked")
	put["local_admin_username"], put["local_admin_rotation_days"] = "fleet-admin", 7
	if res := e.do(call{method: "PUT", path: "/api/v1/settings/login", cookie: alice, body: put}); res.status != http.StatusOK {
		t.Fatalf("other settings with an active password: %d %s", res.status, res.body)
	}

	var dave adminapi.UserCreated
	e.do(call{method: "POST", path: "/api/v1/users", cookie: alice, body: map[string]any{"username": "dave@" + domain, "display_name": "Dave"}}).decode(t, &dave)
	device := e.insertDevice(e.acme, "kiosk-"+domain, "active")
	set := e.do(call{method: "PUT", path: "/api/v1/devices/" + device.String() + "/login-assignment", cookie: operator,
		body: map[string]any{"users": []uuid.UUID{dave.User.Id}, "groups": []uuid.UUID{}}})
	if set.status != http.StatusOK {
		t.Fatalf("login assignment: %d %s", set.status, set.body)
	}
	e.expectEvent(set, "device.login_assignment_changed:success:")
	var d adminapi.DeviceDetail
	set.decode(t, &d)
	if len(d.LoginAssignment.Users) != 1 || d.LoginManagement {
		t.Fatalf("detail %+v", d.LoginAssignment)
	}
	perDevice := grpPK(e, "paddock."+e.slug(e.acme)+".d."+device.String())
	if perDevice == "" || !slices.Equal(e.idp.members[perDevice], []string{e.authentikPK(dave.User.Id)}) {
		t.Fatalf("per-device group %q members %v (groups %v)", perDevice, e.idp.members[perDevice], e.idp.groups)
	}
	// Removing the last direct user removes the per-device group.
	e.do(call{method: "PUT", path: "/api/v1/devices/" + device.String() + "/login-assignment", cookie: operator,
		body: map[string]any{"users": []uuid.UUID{}, "groups": []uuid.UUID{}}})
	if grpPK(e, "paddock."+e.slug(e.acme)+".d."+device.String()) != "" {
		t.Fatal("per-device group kept without direct users")
	}

	sus := e.do(call{method: "POST", path: "/api/v1/devices/" + device.String() + "/suspend-logins", cookie: operator})
	sus.decode(t, &d)
	if sus.status != http.StatusOK || !d.LoginsSuspended {
		t.Fatalf("suspend: %d", sus.status)
	}
	e.expectEvent(sus, "device.logins_suspended:success:")
	if subjects := e.outboxSubjects(e.acme); !slices.Contains(subjects, "state.priority."+e.acme.String()+"|device") {
		t.Fatalf("suspension not on the priority lane: %v", subjects)
	}
	res = e.do(call{method: "POST", path: "/api/v1/devices/" + device.String() + "/resume-logins", cookie: operator})
	res.decode(t, &d)
	if res.status != http.StatusOK || d.LoginsSuspended {
		t.Fatalf("resume: %d", res.status)
	}
	// Unknown subjects are refused.
	bad := e.do(call{method: "PUT", path: "/api/v1/devices/" + device.String() + "/login-assignment", cookie: operator,
		body: map[string]any{"users": []uuid.UUID{uuid.New()}, "groups": []uuid.UUID{}}})
	if bad.status != http.StatusBadRequest {
		t.Fatalf("unknown user: %d", bad.status)
	}
}

func (e *env) authentikPK(user uuid.UUID) string {
	e.t.Helper()
	var pk string
	if err := e.super.QueryRow(context.Background(), "SELECT authentik_pk FROM app_user WHERE id = $1", user).Scan(&pk); err != nil {
		e.t.Fatal(err)
	}
	return pk
}

func (e *env) slug(org uuid.UUID) string {
	e.t.Helper()
	var s string
	if err := e.super.QueryRow(context.Background(), "SELECT slug FROM organization WHERE id = $1", org).Scan(&s); err != nil {
		e.t.Fatal(err)
	}
	return s
}
