package admin_test

import (
	"context"
	"net/http"
	"testing"

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
