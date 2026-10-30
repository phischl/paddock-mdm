package acceptance

import (
	"context"
	"net/http"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/test/acceptance/internal/env"
)

// roleEventWait bounds the wait for a grant: one round of admin-accounts or platform-admins (the sync interval, 60 s in
// the development stack) plus the round's duration and the audit pipeline.
const roleEventWait = syncRound

// roleAuditWait bounds the audit pipeline (outbox, relay, audit writer) from a committed revocation to the index.
const roleAuditWait = time.Minute

// roleMemberState returns the stored state of username's org_operator membership in org: "listed", "marked" (a listing
// missed it and set missing_since) or "absent" (no row: never granted or revoked). It reads Paddock's database as the
// superuser, because the worker's rounds leave no other trace of a listing that changed nothing.
func roleMemberState(t *testing.T, org uuid.UUID, username string) string {
	t.Helper()
	return paddockSQL(t, "SELECT coalesce((SELECT CASE WHEN missing_since IS NULL THEN 'listed' ELSE 'marked' END"+
		" FROM organization_role_member WHERE organization_id = '"+org.String()+"' AND role = 'org_operator'"+
		" AND username = '"+username+"'), 'absent')")
}

// waitRoleMemberState polls until username's org_operator membership in org is in one of the states want and returns
// it; wait bounds one round of the organization (PDK-425: each round is awaited on its own evidence, so the bound does
// not have to cover two rounds whose recurrence grows with the number of organizations).
func waitRoleMemberState(t *testing.T, step string, org uuid.UUID, username string, wait time.Duration, want ...string) string {
	t.Helper()
	deadline := time.Now().Add(wait)
	for {
		state := roleMemberState(t, org, username)
		if slices.Contains(want, state) {
			return state
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s: membership of %s in %s is %q after %s, want one of %v", step, username, org, state, wait, want)
		}
		time.Sleep(5 * time.Second)
	}
}

// waitRoleEvents polls the audit index of org until it holds at least one event code for username and returns them.
func waitRoleEvents(t *testing.T, idx *env.AuditIndex, org uuid.UUID, code, username string, wait time.Duration) []env.IndexEvent {
	t.Helper()
	ctx := testContext(t, wait+time.Minute)
	deadline := time.Now().Add(wait)
	for {
		found, err := idx.Events(ctx, org, "code = '"+code+"' AND params->>'username' = $1", username)
		if err != nil {
			t.Fatal(err)
		}
		if len(found) > 0 {
			return found
		}
		if time.Now().After(deadline) {
			t.Fatalf("no %s for %s in %s within %s", code, username, org, wait)
		}
		time.Sleep(5 * time.Second)
	}
}

// expectRoleEvent checks that events is exactly one successful event with the given params.
func expectRoleEvent(t *testing.T, step string, events []env.IndexEvent, params map[string]any) {
	t.Helper()
	if len(events) != 1 || events[0].Outcome != "success" {
		t.Fatalf("%s: events %+v, want exactly one success", step, events)
	}
	for k, v := range params {
		if events[0].Params[k] != v {
			t.Fatalf("%s: param %s = %v, want %v (%+v)", step, k, events[0].Params[k], v, events[0].Params)
		}
	}
}

// TestRoleMembership is the gate of plan M8b §3.7 (R1–R4): every grant and revocation of a Paddock role in Authentik
// is recorded by the worker within one round, platform roles in the platform pseudo-organization, and the first
// snapshot of a new organization records its members as baseline once.
func TestRoleMembership(t *testing.T) {
	ak, err := env.NewAuthentik()
	if err != nil {
		t.Fatal(err)
	}
	idx := auditIndex(t)
	acme := orgOf(t, login(t, env.Alice))
	ctx := testContext(t, 20*time.Minute)

	// R1, R2: a temporary user joins and leaves acme's operators.
	operators := env.RootGroup("acme") + ".operators"
	op := newDeviceUser(t, ak, "r1", "acme.test")
	if err := ak.AddToGroup(ctx, op.name, operators); err != nil {
		t.Fatal(err)
	}
	expectRoleEvent(t, "R1", waitRoleEvents(t, idx, acme, "admin.role_granted", op.name, roleEventWait),
		map[string]any{"role": "org_operator", "username": op.name, "group": operators, "baseline": false})
	if err := ak.RemoveFromGroup(ctx, op.name, operators); err != nil {
		t.Fatal(err)
	}
	// A revocation needs two consecutive listings that miss the member (a single paged listing can skip one). R2 waits
	// on the evidence of each round instead of one bound for both: the first round marks the member (missing_since),
	// the next one deletes it together with the revocation's audit action; then only the audit pipeline remains. The
	// mark may already be gone when both rounds pass between two polls. Still exactly one revocation and no other grant.
	if waitRoleMemberState(t, "R2 first round", acme, op.name, roleEventWait, "marked", "absent") == "marked" {
		waitRoleMemberState(t, "R2 second round", acme, op.name, roleEventWait, "absent")
	}
	expectRoleEvent(t, "R2", waitRoleEvents(t, idx, acme, "admin.role_revoked", op.name, roleAuditWait),
		map[string]any{"role": "org_operator", "username": op.name, "group": operators})
	time.Sleep(auditSettleDelay)
	granted, err := idx.Events(ctx, acme, "code = 'admin.role_granted' AND params->>'username' = $1", op.name)
	if err != nil || len(granted) != 1 {
		t.Fatalf("R2: grants of %s after the revocation: %+v (%v), want still one", op.name, granted, err)
	}

	// R3: a temporary user joins paddock.platform.admins.
	platformAdmins := "paddock.platform.admins"
	pa := newDeviceUser(t, ak, "r3", "platform.test")
	if err := ak.AddToGroup(ctx, pa.name, platformAdmins); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ak.RemoveFromGroup(context.Background(), pa.name, platformAdmins) })
	expectRoleEvent(t, "R3", waitRoleEvents(t, idx, platformOrg, "admin.role_granted", pa.name, roleEventWait),
		map[string]any{"role": "platform_admin", "username": pa.name, "group": platformAdmins, "baseline": false})

	// R4: a new organization whose administrators group has one member when it is first compared. The group is
	// created with its member before the organization exists; provisioning adopts the existing group by name, so the
	// member is there before the organization becomes active and before any round can compare it.
	root := login(t, env.PlatformAdmin)
	first := newDeviceUser(t, ak, "r4", "r4.test")
	body := newOrg()
	admins := env.RootGroup(body["slug"]) + ".admins"
	if _, err := ak.EnsureGroup(ctx, admins); err != nil {
		t.Fatal(err)
	}
	if err := ak.AddToGroup(ctx, first.name, admins); err != nil {
		t.Fatal(err)
	}
	res := call(t, root, http.MethodPost, "/api/platform/v1/organizations", body)
	expectStatus(t, res, http.StatusCreated, "")
	org := responseID(t, res)
	expectRoleEvent(t, "R4", waitRoleEvents(t, idx, org, "admin.role_granted", first.name, roleEventWait),
		map[string]any{"role": "org_admin", "username": first.name, "group": admins, "baseline": true})
	// Then silence: a further round records nothing for the organization.
	time.Sleep(roleEventWait / 2)
	all, err := idx.Events(ctx, org, "code LIKE $1", "admin.role\\_%")
	if err != nil || len(all) != 1 {
		t.Fatalf("R4: role events of the new organization after a further round: %+v (%v), want only the baseline", all, err)
	}
}
