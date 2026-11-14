package admin_test

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/transport/http/admin/adminapi"
)

// TestPatchSLASettingsAPI: GET/PUT /api/v1/settings/patch-sla (plan M13c decision 17): readers see the defaults, only
// administrators change them, out-of-range days are 400 invalid_request, each attempt records one event.
func TestPatchSLASettingsAPI(t *testing.T) {
	e := newEnv(t)
	const path = "/api/v1/settings/patch-sla"
	fresh := e.org("sla")
	var got adminapi.PatchSlaSettings
	if res := e.do(call{method: "GET", path: path, cookie: e.session(fresh, principal.RoleOrgOperator)}); res.status != http.StatusOK {
		t.Fatalf("operator GET: %d %s", res.status, res.body)
	} else {
		res.decode(t, &got)
	}
	if got.CriticalDays != 7 || got.HighDays != 30 || got.MediumDays != 90 || got.LowDays != 0 || got.UpdatedAt.IsZero() {
		t.Fatalf("defaults %+v", got)
	}
	put := map[string]any{"critical_days": 3, "high_days": 14, "medium_days": 60, "low_days": 0}
	res := e.do(call{method: "PUT", path: path, cookie: e.session(fresh, principal.RoleOrgAdmin), body: put})
	if res.status != http.StatusOK {
		t.Fatalf("admin PUT: %d %s", res.status, res.body)
	}
	e.expectEvent(res, "settings.patch_sla_changed:success:")
	put["critical_days"] = 400
	bad := e.do(call{method: "PUT", path: path, cookie: e.session(fresh, principal.RoleOrgAdmin), body: put, skipReqCheck: true})
	if bad.status != http.StatusBadRequest || bad.problemCode(t) != "invalid_request" {
		t.Fatalf("400 days: %d %s", bad.status, bad.body)
	}
	e.expectEvent(bad, "settings.patch_sla_changed:failure:invalid_request")
	put["critical_days"] = 5
	denied := e.do(call{method: "PUT", path: path, cookie: e.session(fresh, principal.RoleOrgAuditor), body: put})
	if denied.status != http.StatusForbidden || denied.problemCode(t) != "forbidden" {
		t.Fatalf("auditor PUT: %d %s", denied.status, denied.body)
	}
	e.expectEvent(denied, "settings.patch_sla_changed:denied:forbidden")
}

// TestPatchComplianceAPI: GET /api/v1/patch-compliance and its export (plan M13c decision 18): every organization role
// reads the report; the CSV export names the file and has a row per breach and is recorded; a foreign device group is
// 404; an unknown format is 400.
func TestPatchComplianceAPI(t *testing.T) {
	e := newEnv(t)
	org := e.org("patch")
	dev := uuid.Must(uuid.NewV7())
	for _, q := range []struct {
		sql  string
		args []any
	}{
		{"INSERT INTO device (id, organization_id, hostname, state) VALUES ($1, $2, 'laptop-1', 'active')", []any{dev, org}},
		{"INSERT INTO device_inventory_ref (device_id, organization_id, external_id) VALUES ($1, $2, 'h1')", []any{dev, org}},
		{`INSERT INTO vulnerability_finding (device_id, organization_id, cve, software_name, software_version, severity, fixed_version,
			first_seen_at) VALUES ($1, $2, 'CVE-2026-0001', 'openssl', '1', 'critical', '2', $3)`, []any{dev, org, time.Now().Add(-8 * 24 * time.Hour)}},
	} {
		if _, err := e.super.Exec(context.Background(), q.sql, q.args...); err != nil {
			t.Fatal(err)
		}
	}
	for _, role := range []principal.Role{principal.RoleOrgAdmin, principal.RoleOrgOperator, principal.RoleOrgAuditor} {
		res := e.do(call{method: "GET", path: "/api/v1/patch-compliance", cookie: e.session(org, role)})
		if res.status != http.StatusOK {
			t.Fatalf("%s: %d %s", role, res.status, res.body)
		}
		if strings.Contains(string(res.body), `"period"`) {
			t.Fatalf("%s: the report is a snapshot and has no period: %s", role, res.body)
		}
		var r adminapi.PatchComplianceReport
		res.decode(t, &r)
		if r.Summary.Devices != 1 || r.Summary.Breached != 1 || r.DevicesTotal != 1 || r.RowCap != 1000 || r.DeviceGroupId != nil ||
			len(r.Devices) != 1 || r.Devices[0].Breached[0].SlaDays != 7 || r.Devices[0].Breached[0].DaysOpen != 8 {
			t.Fatalf("%s: report %+v", role, r)
		}
	}
	foreignGroup := uuid.Must(uuid.NewV7())
	if _, err := e.super.Exec(context.Background(), "INSERT INTO device_group (id, organization_id, name) VALUES ($1, $2, 'other')", foreignGroup, e.acme); err != nil {
		t.Fatal(err)
	}
	if res := e.do(call{method: "GET", path: "/api/v1/patch-compliance?device_group_id=" + foreignGroup.String(),
		cookie: e.session(org, principal.RoleOrgAuditor)}); res.status != http.StatusNotFound || res.problemCode(t) != "not_found" {
		t.Fatalf("foreign group: %d %s", res.status, res.body)
	}

	exp := e.do(call{method: "GET", path: "/api/v1/patch-compliance/export?format=csv", cookie: e.session(org, principal.RoleOrgOperator)})
	if exp.status != http.StatusOK || !strings.HasPrefix(exp.header.Get("Content-Type"), "text/csv") ||
		!strings.Contains(exp.header.Get("Content-Disposition"), `filename="paddock-patch-compliance-patch-`) ||
		!strings.Contains(string(exp.body), "breach,critical,,"+dev.String()+",laptop-1,CVE-2026-0001,openssl,8,2,7") {
		t.Fatalf("csv export: %d %v %s", exp.status, exp.header, exp.body)
	}
	e.expectEvent(exp, "patch_compliance.exported:success:")
	bad := e.do(call{method: "GET", path: "/api/v1/patch-compliance/export?format=xml", cookie: e.session(org, principal.RoleOrgOperator),
		skipReqCheck: true})
	if bad.status != http.StatusBadRequest {
		t.Fatalf("format xml: %d %s", bad.status, bad.body)
	}
}
