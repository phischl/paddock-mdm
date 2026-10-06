package admin_test

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/transport/http/admin"
	"github.com/phischl/paddock-mdm/server/internal/transport/http/admin/adminapi"
)

// TestRevocationRequests (plan M4c decision 7): Lock and Destroy need an organization administrator, a fresh step-up
// per approval and the typed hostname; a Destroy needs a second administrator; the requests are recorded with the
// raw step-up tokens (never returned) and handed to the issuer through the outbox.
func TestRevocationRequests(t *testing.T) {
	e := newEnv(t)
	now := time.Now()
	alice := e.steppedUp(e.session(e.acme, principal.RoleOrgAdmin), now)
	bob := e.steppedUp(e.session(e.acme, principal.RoleOrgAdmin), now)
	operator := e.steppedUp(e.session(e.acme, principal.RoleOrgOperator), now)
	carol := e.steppedUp(e.session(e.globex, principal.RoleOrgAdmin), now)
	dev := e.insertDevice(e.acme, "lt-revoke", "active")
	lock := "/api/v1/devices/" + dev.String() + "/lock"
	destroy := "/api/v1/devices/" + dev.String() + "/destroy"
	confirm := map[string]any{"confirm_hostname": "lt-revoke", "reason": "stolen"}

	if r := e.do(call{method: "POST", path: lock, cookie: e.session(e.acme, principal.RoleOrgAdmin), body: confirm}); r.status != http.StatusForbidden ||
		!strings.Contains(string(r.body), "step_up_required") {
		t.Fatalf("without step-up: %d %s", r.status, r.body)
	}
	if r := e.do(call{method: "POST", path: lock, cookie: operator, body: confirm}); r.status != http.StatusForbidden {
		t.Fatalf("operator: %d %s", r.status, r.body)
	}
	if r := e.do(call{method: "POST", path: lock, cookie: carol, body: confirm}); r.status != http.StatusNotFound {
		t.Fatalf("other organization: %d %s", r.status, r.body)
	}
	if r := e.do(call{method: "POST", path: lock, cookie: alice, body: map[string]any{"confirm_hostname": "lt-other"}}); r.status != http.StatusBadRequest {
		t.Fatalf("wrong hostname: %d %s", r.status, r.body)
	}

	r := e.do(call{method: "POST", path: lock, cookie: alice, body: confirm})
	if r.status != http.StatusCreated {
		t.Fatalf("lock: %d %s", r.status, r.body)
	}
	e.expectEvent(r, "revocation.requested:success:")
	var locked adminapi.RevocationRequest
	r.decode(t, &locked)
	if locked.Status != "approved" || locked.Action != "lock" || locked.Hostname != "lt-revoke" || locked.Reason != "stolen" ||
		len(locked.Approvals) != 1 || locked.Approvals[0].Role != "requester" || strings.Contains(string(r.body), "token-") {
		t.Fatalf("lock request %s", r.body)
	}
	var outbox int
	if err := e.super.QueryRow(context.Background(), "SELECT count(*) FROM outbox WHERE subject = 'revocation.' || $1::text AND msg_id = 'revocation:' || $2::text",
		e.acme, locked.Id).Scan(&outbox); err != nil || outbox != 1 {
		t.Fatalf("revocation.approved messages %d, %v", outbox, err)
	}
	var stored string
	if err := e.super.QueryRow(context.Background(), "SELECT stepup_id_token FROM revocation_approval WHERE request_id = $1", locked.Id).Scan(&stored); err != nil ||
		!strings.HasPrefix(stored, "token-") {
		t.Fatalf("stored step-up token %q, %v", stored, err)
	}
	// One step-up token approves one request; a second open Lock is a conflict.
	if r := e.do(call{method: "POST", path: destroy, cookie: alice, body: confirm}); r.status != http.StatusForbidden ||
		!strings.Contains(string(r.body), "step_up_required") {
		t.Fatalf("reused step-up: %d %s", r.status, r.body)
	}
	alice = e.steppedUp(alice, time.Now())
	if r := e.do(call{method: "POST", path: lock, cookie: alice, body: confirm}); r.status != http.StatusConflict {
		t.Fatalf("second open lock: %d %s", r.status, r.body)
	}

	// Destroy: requested until a second administrator approves; the requester cannot approve it.
	alice = e.steppedUp(alice, time.Now())
	r = e.do(call{method: "POST", path: destroy, cookie: alice, body: confirm})
	if r.status != http.StatusCreated {
		t.Fatalf("destroy: %d %s", r.status, r.body)
	}
	var destroyed adminapi.RevocationRequest
	r.decode(t, &destroyed)
	if destroyed.Status != "requested" {
		t.Fatalf("destroy request %s", r.body)
	}
	approve := "/api/v1/revocation-requests/" + destroyed.Id.String() + "/approve"
	alice = e.steppedUp(alice, time.Now())
	r = e.do(call{method: "POST", path: approve, cookie: alice, body: map[string]any{"confirm_hostname": "lt-revoke"}})
	if r.status != http.StatusForbidden {
		t.Fatalf("self approval: %d %s", r.status, r.body)
	}
	e.expectEvent(r, "revocation.approved:denied:forbidden")
	if r := e.do(call{method: "POST", path: approve, cookie: carol, body: map[string]any{"confirm_hostname": "lt-revoke"}}); r.status != http.StatusNotFound {
		t.Fatalf("approval from another organization: %d %s", r.status, r.body)
	}
	r = e.do(call{method: "POST", path: approve, cookie: bob, body: map[string]any{"confirm_hostname": "lt-revoke"}})
	if r.status != http.StatusOK {
		t.Fatalf("approval: %d %s", r.status, r.body)
	}
	e.expectEvent(r, "revocation.approved:success:")
	var approved adminapi.RevocationRequest
	r.decode(t, &approved)
	if approved.Status != "approved" || len(approved.Approvals) != 2 || approved.Approvals[1].Role != "approver" {
		t.Fatalf("approved %s", r.body)
	}
	cancel := "/api/v1/revocation-requests/" + destroyed.Id.String() + "/cancel"
	bob = e.steppedUp(bob, time.Now())
	if r := e.do(call{method: "POST", path: cancel, cookie: bob, body: map[string]any{"confirm_hostname": "lt-revoke"}}); r.status != http.StatusForbidden {
		t.Fatalf("cancel by another administrator: %d %s", r.status, r.body)
	}
	alice = e.steppedUp(alice, time.Now())
	if r := e.do(call{method: "POST", path: cancel, cookie: alice, body: map[string]any{"confirm_hostname": "lt-revoke"}}); r.status != http.StatusOK {
		t.Fatalf("cancel: %d %s", r.status, r.body)
	}

	var page adminapi.RevocationRequestPage
	e.do(call{method: "GET", path: "/api/v1/revocation-requests?action=destroy&device_id=" + dev.String(), cookie: alice}).decode(t, &page)
	if page.Total != 1 || page.Items[0].Status != "cancelled" {
		t.Fatalf("list %+v", page)
	}
	if r := e.do(call{method: "GET", path: "/api/v1/revocation-requests", cookie: carol}); r.status != http.StatusOK || strings.Contains(string(r.body), dev.String()) {
		t.Fatalf("other organization sees the requests: %s", r.body)
	}
}

// TestRevocationFrozen: an administrator frozen after an exceeded limit is denied (ADR 0014).
func TestRevocationFrozen(t *testing.T) {
	e := newEnv(t)
	alice := e.steppedUp(e.session(e.acme, principal.RoleOrgAdmin), time.Now())
	dev := e.insertDevice(e.acme, "lt-frozen", "active")
	var admin string
	if err := e.super.QueryRow(context.Background(), "SELECT id FROM admin_account WHERE organization_id = $1 AND role = 'org_admin' ORDER BY id DESC LIMIT 1", e.acme).Scan(&admin); err != nil {
		t.Fatal(err)
	}
	prior := e.insertDevice(e.acme, "lt-prior", "active")
	if _, err := e.super.Exec(context.Background(), `INSERT INTO revocation_request (id, organization_id, device_id, action, status, requested_by, finished_at)
		VALUES ('0190f000-0000-7000-8000-0000000000f1', $1, $2, 'lock', 'rejected', $3, now())`, e.acme, prior, admin); err != nil {
		t.Fatal(err)
	}
	if _, err := e.super.Exec(context.Background(), `INSERT INTO revocation_freeze (organization_id, admin_id, request_id, frozen_until)
		VALUES ($1, $2, '0190f000-0000-7000-8000-0000000000f1', now() + interval '1 day')`, e.acme, admin); err != nil {
		t.Fatal(err)
	}
	r := e.do(call{method: "POST", path: "/api/v1/devices/" + dev.String() + "/lock", cookie: alice, body: map[string]any{"confirm_hostname": "lt-frozen"}})
	if r.status != http.StatusForbidden || !strings.Contains(string(r.body), "revocation_frozen") {
		t.Fatalf("frozen: %d %s", r.status, r.body)
	}
	e.expectEvent(r, "revocation.requested:denied:revocation_frozen")
}

// TestRevocationDisabled (gate R5, plan M4c decision 1): with the feature flag off every revocation endpoint answers
// 403 revocation_disabled and records the attempt as denied.
func TestRevocationDisabled(t *testing.T) {
	e := newEnvWith(t, func(d *admin.Deps) { d.Revocations = app.NewRevocations(d.Runner, nil, nil, false) })
	alice := e.steppedUp(e.session(e.acme, principal.RoleOrgAdmin), time.Now())
	dev := e.insertDevice(e.acme, "lt-off", "active")
	body := map[string]any{"confirm_hostname": "lt-off"}
	for _, path := range []string{
		"/api/v1/devices/" + dev.String() + "/lock",
		"/api/v1/devices/" + dev.String() + "/destroy",
		"/api/v1/revocation-requests/" + dev.String() + "/approve",
		"/api/v1/revocation-requests/" + dev.String() + "/reject",
		"/api/v1/revocation-requests/" + dev.String() + "/cancel",
	} {
		r := e.do(call{method: "POST", path: path, cookie: alice, body: body})
		if r.status != http.StatusForbidden || !strings.Contains(string(r.body), "revocation_disabled") {
			t.Fatalf("%s: %d %s", path, r.status, r.body)
		}
		if got := e.events(r.header.Get("X-Request-Id")); len(got) != 1 || !strings.HasSuffix(got[0], ":denied:revocation_disabled") {
			t.Fatalf("%s audit %v", path, got)
		}
	}
}
