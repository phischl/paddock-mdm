package admin_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/phischl/paddock-mdm/server/internal/platform/httpx"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/transport/http/admin/adminapi"
)

// TestPrivacySettings: GET/PUT /api/v1/settings/privacy (plan M10 decisions 7–8): a new organization has the
// defaults, readers see them, only administrators change them, out-of-range days are 400 invalid_request, and every
// attempt records one settings.privacy_changed event with the three new values.
func TestPrivacySettings(t *testing.T) {
	e := newEnv(t)
	alice := e.session(e.acme, principal.RoleOrgAdmin)
	operator := e.session(e.acme, principal.RoleOrgOperator)
	auditor := e.session(e.acme, principal.RoleOrgAuditor)
	const path = "/api/v1/settings/privacy"

	fresh := e.org("fresh")
	var rows int
	if err := e.super.QueryRow(context.Background(), `SELECT count(*) FROM organization_privacy_settings
		WHERE organization_id = $1 AND retired_inventory_days = 30 AND NOT audit_search_recorded AND NOT inventory_view_recorded`,
		fresh).Scan(&rows); err != nil || rows != 1 {
		t.Fatalf("default row of a new organization: %d, %v", rows, err)
	}
	var defaults adminapi.PrivacySettings
	if res := e.do(call{method: "GET", path: path, cookie: e.session(fresh, principal.RoleOrgAuditor)}); res.status != http.StatusOK {
		t.Fatalf("auditor GET: %d %s", res.status, res.body)
	} else {
		res.decode(t, &defaults)
	}
	if defaults.RetiredInventoryDays != 30 || defaults.AuditSearchRecorded || defaults.InventoryViewRecorded || defaults.UpdatedAt.IsZero() {
		t.Fatalf("defaults of a new organization %+v", defaults)
	}

	put := map[string]any{"retired_inventory_days": 14, "audit_search_recorded": true, "inventory_view_recorded": false}
	res := e.do(call{method: "PUT", path: path, cookie: alice, body: put})
	if res.status != http.StatusOK {
		t.Fatalf("admin PUT: %d %s", res.status, res.body)
	}
	e.expectEvent(res, "settings.privacy_changed:success:")
	if got := e.privacyParams(res); got != "14|true|false|"+e.acme.String() {
		t.Fatalf("event params and target %s", got)
	}
	var saved adminapi.PrivacySettings
	res.decode(t, &saved)
	if saved.RetiredInventoryDays != 14 || !saved.AuditSearchRecorded || saved.InventoryViewRecorded {
		t.Fatalf("saved %+v", saved)
	}

	for _, days := range []int{0, 366} {
		put["retired_inventory_days"] = days
		bad := e.do(call{method: "PUT", path: path, cookie: alice, body: put, skipReqCheck: true})
		if bad.status != http.StatusBadRequest || bad.problemCode(t) != "invalid_request" {
			t.Fatalf("%d days: %d %s", days, bad.status, bad.body)
		}
		e.expectEvent(bad, "settings.privacy_changed:failure:invalid_request")
	}

	put["retired_inventory_days"] = 7
	denied := e.do(call{method: "PUT", path: path, cookie: operator, body: put})
	if denied.status != http.StatusForbidden || denied.problemCode(t) != "forbidden" {
		t.Fatalf("operator PUT: %d %s", denied.status, denied.body)
	}
	e.expectEvent(denied, "settings.privacy_changed:denied:forbidden")

	var read adminapi.PrivacySettings
	if res := e.do(call{method: "GET", path: path, cookie: auditor}); res.status != http.StatusOK {
		t.Fatalf("auditor GET: %d %s", res.status, res.body)
	} else {
		res.decode(t, &read)
	}
	if read.RetiredInventoryDays != 14 || !read.AuditSearchRecorded {
		t.Fatalf("after the denied and invalid attempts %+v", read)
	}

	var other adminapi.PrivacySettings
	e.do(call{method: "GET", path: path, cookie: e.session(e.globex, principal.RoleOrgAdmin)}).decode(t, &other)
	if other.RetiredInventoryDays != 30 || other.AuditSearchRecorded {
		t.Fatalf("another organization's settings changed: %+v", other)
	}
}

// privacyParams returns the three params and the target ID of the action recorded for a request.
func (e *env) privacyParams(r result) string {
	e.t.Helper()
	var out string
	if err := e.super.QueryRow(context.Background(), `SELECT params->>'retired_inventory_days' || '|' ||
		(params->>'audit_search_recorded') || '|' || (params->>'inventory_view_recorded') || '|' || coalesce(target->>'id', '-')
		FROM action WHERE correlation_id = $1`, r.header.Get(httpx.HeaderRequestID)).Scan(&out); err != nil {
		e.t.Fatal(err)
	}
	return out
}
