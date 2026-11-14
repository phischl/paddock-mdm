package admin_test

import (
	"context"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/transport/http/admin/adminapi"
)

// TestOrganizationDeletionAPI (plan M17 §6 and §8.2): the deletion request and its cancel over the platform API, with
// one audit event per attempt, the deletion object on the organization and the pending deletion on GET /api/v1/me of
// the organization's administrators.
func TestOrganizationDeletionAPI(t *testing.T) {
	e := newEnv(t)
	var slug string
	if err := e.super.QueryRow(context.Background(), "SELECT slug FROM organization WHERE id = $1", e.acme).Scan(&slug); err != nil {
		t.Fatal(err)
	}
	var device uuid.UUID
	for range 2 {
		device = uuid.Must(uuid.NewV7())
		if _, err := e.super.Exec(context.Background(), "INSERT INTO device (id, organization_id, hostname, state) VALUES ($1, $2, $3, 'active')",
			device, e.acme, "del-"+uuid.NewString()[:8]); err != nil {
			t.Fatal(err)
		}
	}
	root := e.platformSession()
	stepped := e.steppedUp(root, time.Now())
	alice := e.session(e.acme, principal.RoleOrgAdmin)
	path := "/api/platform/v1/organizations/" + e.acme.String()
	body := func(confirm string, grace int) map[string]any {
		return map[string]any{"confirm_slug": confirm, "reason": "contract ended", "grace_days": grace}
	}

	if r := e.do(call{method: "POST", path: path + "/delete", cookie: root, body: body(slug, 30)}); r.status != http.StatusForbidden ||
		r.problemCode(t) != "step_up_required" {
		t.Fatalf("without a step-up: %d %s", r.status, r.body)
	} else {
		e.expectEvent(r, "organization.deletion_requested:denied:step_up_required")
	}
	aliceStepped := e.steppedUp(alice, time.Now())
	if r := e.do(call{method: "POST", path: path + "/delete", cookie: aliceStepped, body: body(slug, 30)}); r.status != http.StatusForbidden {
		t.Fatalf("organization administrator: %d %s", r.status, r.body)
	} else {
		e.expectEvent(r, "organization.deletion_requested:denied:forbidden")
	}
	if r := e.do(call{method: "POST", path: "/api/platform/v1/organizations/" + uuid.NewString() + "/delete", cookie: stepped,
		body: body(slug, 30)}); r.status != http.StatusNotFound || r.problemCode(t) != "not_found" {
		t.Fatalf("unknown organization: %d %s", r.status, r.body)
	}
	for name, b := range map[string]map[string]any{
		"wrong slug":    body(slug+"x", 30),
		"grace 6":       body(slug, 6),
		"grace 0":       body(slug, 0),
		"grace 91":      body(slug, 91),
		"reason of 1":   {"confirm_slug": slug, "reason": "r", "grace_days": 30},
		"reason of 501": {"confirm_slug": slug, "reason": strings.Repeat("r", 501), "grace_days": 30},
	} {
		r := e.do(call{method: "POST", path: path + "/delete", cookie: stepped, body: b, skipReqCheck: true})
		if r.status != http.StatusBadRequest || r.problemCode(t) != "invalid_request" {
			t.Fatalf("%s: %d %s", name, r.status, r.body)
		}
		e.expectEvent(r, "organization.deletion_requested:failure:invalid_request")
	}
	if r := e.do(call{method: "POST", path: path + "/cancel-deletion", cookie: root}); r.status != http.StatusConflict ||
		r.problemCode(t) != "invalid_state" {
		t.Fatalf("cancel without a deletion: %d %s", r.status, r.body)
	}

	requested := e.do(call{method: "POST", path: path + "/delete", cookie: stepped, body: body(slug, 30)})
	if requested.status != http.StatusAccepted {
		t.Fatalf("request: %d %s", requested.status, requested.body)
	}
	e.expectEvent(requested, "organization.deletion_requested:success:")
	var o adminapi.Organization
	requested.decode(t, &o)
	if o.Status != "active" || o.Deletion == nil || o.Deletion.UninstallsIssued != 2 || o.Deletion.UninstallsSkipped != 0 ||
		o.Deletion.Reason != "contract ended" || o.Deletion.RequestedBy != "root@test" || o.Deletion.Step != nil ||
		o.Deletion.DeleteAfter.Sub(o.Deletion.RequestedAt) != 30*24*time.Hour {
		t.Fatalf("organization %+v deletion %+v", o, o.Deletion)
	}
	if r := e.do(call{method: "POST", path: path + "/delete", cookie: stepped, body: body(slug, 30)}); r.status != http.StatusConflict ||
		r.problemCode(t) != "invalid_state" {
		t.Fatalf("second request: %d %s", r.status, r.body)
	}

	// The organization administrator sees why the device leaves and cannot withdraw it per device.
	var dev adminapi.Device
	e.do(call{method: "GET", path: "/api/v1/devices/" + device.String(), cookie: alice}).decode(t, &dev)
	if dev.Uninstall == nil || dev.Uninstall.Reason == nil || *dev.Uninstall.Reason != adminapi.OrganizationOffboarding ||
		dev.Uninstall.Mode != "leave" {
		t.Fatalf("device uninstall %+v", dev.Uninstall)
	}
	if r := e.do(call{method: "POST", path: "/api/v1/devices/" + device.String() + "/uninstall/cancel", cookie: alice}); r.status != http.StatusConflict ||
		r.problemCode(t) != "invalid_state" {
		t.Fatalf("per-device cancel: %d %s", r.status, r.body)
	} else {
		e.expectEvent(r, "device.uninstall_cancelled:failure:invalid_state")
	}

	var me adminapi.Me
	r := e.do(call{method: "GET", path: "/api/v1/me", cookie: alice})
	r.decode(t, &me)
	if me.OrganizationDeletion == nil || !me.OrganizationDeletion.DeleteAfter.Equal(o.Deletion.DeleteAfter) {
		t.Fatalf("me while pending: %+v", me.OrganizationDeletion)
	}
	carol := e.session(e.globex, principal.RoleOrgAdmin)
	var other adminapi.Me
	e.do(call{method: "GET", path: "/api/v1/me", cookie: carol}).decode(t, &other)
	if other.OrganizationDeletion != nil {
		t.Fatalf("me of another organization: %+v", other.OrganizationDeletion)
	}
	if r := e.do(call{method: "POST", path: path + "/cancel-deletion", cookie: alice}); r.status != http.StatusForbidden {
		t.Fatalf("cancel by an organization administrator: %d", r.status)
	}

	cancelled := e.do(call{method: "POST", path: path + "/cancel-deletion", cookie: root})
	if cancelled.status != http.StatusOK {
		t.Fatalf("cancel: %d %s", cancelled.status, cancelled.body)
	}
	e.expectEvent(cancelled, "organization.deletion_cancelled:success:")
	cancelled.decode(t, &o)
	if o.Deletion != nil {
		t.Fatalf("deletion after the cancel: %+v", o.Deletion)
	}
	var open int
	if err := e.super.QueryRow(context.Background(), `SELECT count(*) FROM device WHERE organization_id = $1 AND uninstall_requested_at IS NOT NULL`,
		e.acme).Scan(&open); err != nil || open != 0 {
		t.Fatalf("pending uninstalls after the cancel: %d %v", open, err)
	}
	var after adminapi.Me
	e.do(call{method: "GET", path: "/api/v1/me", cookie: alice}).decode(t, &after)
	if after.OrganizationDeletion != nil {
		t.Fatalf("me after the cancel: %+v", after.OrganizationDeletion)
	}
}

// TestOrganizationListHidesDeleted: without a status filter the organization list leaves out tombstones; status=deleted
// and status=deleting list them.
func TestOrganizationListHidesDeleted(t *testing.T) {
	e := newEnv(t)
	root := e.platformSession()
	tok := "hd" + strings.ReplaceAll(uuid.NewString()[:8], "-", "")
	for suffix, status := range map[string]string{"a": "active", "b": "deleting", "c": "deleted"} {
		_, err := e.super.Exec(context.Background(), `INSERT INTO organization (id, slug, name, status, deletion_requested_at, delete_after,
			deleted_at) VALUES ($1, $2, 'Hidden', $3, now(), now(), CASE WHEN $3 = 'deleted' THEN now() END)`,
			uuid.Must(uuid.NewV7()), tok+"-"+suffix, status)
		if err != nil {
			t.Fatal(err)
		}
	}
	for query, want := range map[string][]string{
		"":                {tok + "-a", tok + "-b"},
		"status=deleted":  {tok + "-c"},
		"status=deleting": {tok + "-b"},
	} {
		q, _ := url.ParseQuery(query)
		q.Set("q", tok)
		if got := e.list(root, "/api/platform/v1/organizations", q).names("slug"); !slices.Equal(got, want) {
			t.Errorf("%q: %v, want %v", query, got, want)
		}
	}
}
