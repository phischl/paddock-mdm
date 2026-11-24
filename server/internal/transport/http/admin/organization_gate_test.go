package admin_test

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
	"github.com/phischl/paddock-mdm/server/internal/principal"
)

// TestDeletingOrganizationRefused: once an organization is deleting, its sessions read and change nothing; the api
// answers 403 organization_inactive (plan M17 amendment 2026-11-14 d point 4), and a refused action is recorded once
// in the platform pseudo-organization, never in the organization (amendment f point 1).
func TestDeletingOrganizationRefused(t *testing.T) {
	e := newEnv(t)
	org := e.org("gate")
	alice := e.session(org, principal.RoleOrgAdmin)
	if r := e.do(call{method: "GET", path: "/api/v1/device-groups", cookie: alice}); r.status != http.StatusOK {
		t.Fatalf("list of an active organization: %d %s", r.status, r.body)
	}
	if _, err := e.super.Exec(context.Background(), `UPDATE organization SET status = 'deleting',
		deletion_requested_at = now(), deletion_requested_by = 'platform admin', deletion_reason = 'contract ended',
		delete_after = now(), offboarding_step = 'database' WHERE id = $1`, org); err != nil {
		t.Fatal(err)
	}
	if err := e.orgPool.RefreshOrganizationStatus(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, c := range []call{
		{method: "GET", path: "/api/v1/device-groups", cookie: alice},
		{method: "POST", path: "/api/v1/device-groups", cookie: alice, body: map[string]any{"name": "Late"}},
	} {
		r := e.do(c)
		if r.status != http.StatusForbidden || r.problemCode(t) != "organization_inactive" {
			t.Errorf("%s %s: %d %s, want 403 organization_inactive", c.method, c.path, r.status, r.body)
		}
	}
	var groups int
	if err := e.super.QueryRow(context.Background(), "SELECT count(*) FROM device_group WHERE organization_id = $1", org).
		Scan(&groups); err != nil || groups != 0 {
		t.Errorf("device groups of the deleting organization: %d, %v", groups, err)
	}
	// The refused POST is recorded once, in the platform pseudo-organization (plan M17 amendment 2026-11-14 f point 1).
	var events int
	var attempted, status, actorType string
	if err := e.super.QueryRow(context.Background(), `SELECT count(*), max(params->>'attempted_code'),
		max(params->>'status'), max(actor->>'type') FROM action WHERE code = 'organization.inactive_denied'
		AND organization_id = $1 AND outcome = 'denied' AND error_code = 'organization_inactive'
		AND params->>'organization_id' = $2`, audit.PlatformOrganizationID, org.String()).
		Scan(&events, &attempted, &status, &actorType); err != nil {
		t.Fatal(err)
	}
	if events != 1 || attempted != "device_group.created" || status != "deleting" || actorType != "admin" {
		t.Errorf("platform events: %d, attempted %q, status %q, actor %q; want one device_group.created, deleting, admin",
			events, attempted, status, actorType)
	}
	var inOrg int
	if err := e.super.QueryRow(context.Background(), "SELECT count(*) FROM action WHERE organization_id = $1", org).
		Scan(&inOrg); err != nil || inOrg != 0 {
		t.Errorf("events in the deleting organization: %d, %v", inOrg, err)
	}
	other := e.session(e.org("kept"), principal.RoleOrgAdmin)
	if r := e.do(call{method: "GET", path: "/api/v1/device-groups", cookie: other}); r.status != http.StatusOK {
		t.Errorf("list of another organization: %d %s", r.status, r.body)
	}
}

// TestDeletingOrganizationStepUpDenialRecordedOnce (PDK-1113): a step-up action without a fresh step-up in a deleting
// organization fails the step-up check before the gate; the gate refuses its record in the organization, so the
// attempt is recorded once as organization.inactive_denied in the platform pseudo-organization and answered with 403
// organization_inactive, matching the event.
func TestDeletingOrganizationStepUpDenialRecordedOnce(t *testing.T) {
	e := newEnv(t)
	org := e.org("stepup-gate")
	alice := e.session(org, principal.RoleOrgAdmin)
	if _, err := e.super.Exec(context.Background(), `UPDATE organization SET status = 'deleting',
		deletion_requested_at = now(), deletion_requested_by = 'platform admin', deletion_reason = 'contract ended',
		delete_after = now(), offboarding_step = 'database' WHERE id = $1`, org); err != nil {
		t.Fatal(err)
	}
	if err := e.orgPool.RefreshOrganizationStatus(context.Background()); err != nil {
		t.Fatal(err)
	}
	r := e.do(call{method: "PUT", path: "/api/v1/settings/watched-units", cookie: alice,
		body: map[string]any{"units": []string{"wazuh-agent.service"}}})
	if r.status != http.StatusForbidden || r.problemCode(t) != "organization_inactive" {
		t.Fatalf("step-up action of a deleting organization: %d %s, want 403 organization_inactive", r.status, r.body)
	}
	var events int
	var code, attempted, status string
	if err := e.super.QueryRow(context.Background(), `SELECT count(*), max(code), max(params->>'attempted_code'),
		max(params->>'status') FROM action WHERE params->>'organization_id' = $1 OR organization_id = $1::uuid`,
		org.String()).Scan(&events, &code, &attempted, &status); err != nil {
		t.Fatal(err)
	}
	if events != 1 || code != "organization.inactive_denied" || attempted != "settings.watched_units_changed" ||
		status != "deleting" {
		t.Errorf("events: %d, code %q, attempted %q, status %q; want one organization.inactive_denied of "+
			"settings.watched_units_changed, deleting", events, code, attempted, status)
	}
}

// TestDeletingOrganizationForeignPrincipalGetsNotFound (PDK-1113, main §123): the organization_inactive precedence
// applies only to the principal's own organization. A principal of another, active organization acting on resources
// of a deleting organization still gets 404 not_found (or its own denial), never organization_inactive; nothing names
// the deleting organization, and each attempt is recorded once in the principal's own organization.
func TestDeletingOrganizationForeignPrincipalGetsNotFound(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	gone, kept := e.org("gone-foreign"), e.org("kept-foreign")
	alice := e.session(gone, principal.RoleOrgAdmin)
	bob := e.session(kept, principal.RoleOrgAdmin)
	created := e.do(call{method: "POST", path: "/api/v1/device-groups", cookie: alice, body: map[string]any{"name": "G"}})
	if created.status != http.StatusCreated {
		t.Fatalf("create group: %d %s", created.status, created.body)
	}
	var group struct {
		ID string `json:"id"`
	}
	created.decode(t, &group)
	device := e.insertDevice(gone, "lt-gone", "active")
	if _, err := e.super.Exec(ctx, `UPDATE organization SET status = 'deleting',
		deletion_requested_at = now(), deletion_requested_by = 'platform admin', deletion_reason = 'contract ended',
		delete_after = now(), offboarding_step = 'database' WHERE id = $1`, gone); err != nil {
		t.Fatal(err)
	}
	if err := e.orgPool.RefreshOrganizationStatus(ctx); err != nil {
		t.Fatal(err)
	}
	countIn := func(org uuid.UUID) int {
		var n int
		if err := e.super.QueryRow(ctx, "SELECT count(*) FROM action WHERE organization_id = $1", org).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	goneBefore := countIn(gone)

	for _, c := range []struct {
		call   call
		status int
		code   string
	}{
		{call{method: "PATCH", path: "/api/v1/device-groups/" + group.ID, cookie: bob, body: map[string]any{"name": "X"}},
			http.StatusNotFound, "not_found"},
		{call{method: "DELETE", path: "/api/v1/device-groups/" + group.ID, cookie: bob}, http.StatusNotFound, "not_found"},
		{call{method: "POST", path: "/api/v1/devices/" + device.String() + "/disk/recovery-key", cookie: bob,
			body: map[string]any{"confirm_hostname": "lt-gone"}}, http.StatusForbidden, "step_up_required"},
		{call{method: "POST", path: "/api/platform/v1/organizations/" + gone.String() + "/recovery-export", cookie: bob,
			body: exportBody(exportPassphrase)}, http.StatusForbidden, "forbidden"},
	} {
		r := e.do(c.call)
		if r.status != c.status || r.problemCode(t) != c.code || strings.Contains(string(r.body), "organization_inactive") {
			t.Errorf("%s %s: %d %s, want %d %s", c.call.method, c.call.path, r.status, r.body, c.status, c.code)
		}
	}

	var named int
	if err := e.super.QueryRow(ctx, `SELECT count(*) FROM action WHERE code = 'organization.inactive_denied'
		AND params->>'organization_id' = $1`, gone.String()).Scan(&named); err != nil || named != 0 {
		t.Errorf("organization.inactive_denied naming the deleting organization: %d, %v", named, err)
	}
	if after := countIn(gone); after != goneBefore {
		t.Errorf("action rows in the deleting organization: %d after the flip, %d before", after, goneBefore)
	}
	rows, err := e.super.Query(ctx, `SELECT error_code FROM action WHERE organization_id = $1 AND outcome <> 'success'
		ORDER BY started_at`, kept)
	if err != nil {
		t.Fatal(err)
	}
	var codes []string
	for rows.Next() {
		var code *string
		if err := rows.Scan(&code); err != nil {
			t.Fatal(err)
		}
		if code != nil {
			codes = append(codes, *code)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if strings.Join(codes, ",") != "not_found,not_found,step_up_required,forbidden" {
		t.Errorf("attempts recorded in the principal's organization: %v, want not_found, not_found, step_up_required, "+
			"forbidden", codes)
	}
}
