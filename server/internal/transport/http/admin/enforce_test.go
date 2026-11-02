package admin_test

import (
	"context"
	"net/http"
	"net/url"
	"testing"

	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/transport/http/admin/adminapi"
)

// TestEnforceDeviceRoute (plan M11 decisions 42 and 43): the adoption filters of the device list, the typed hostname of
// POST /devices/{id}/enforce, its state and role checks, and the answer in the contract.
func TestEnforceDeviceRoute(t *testing.T) {
	e := newEnv(t)
	bob := e.session(e.acme, principal.RoleOrgOperator)
	dave := e.session(e.acme, principal.RoleOrgAuditor)
	carol := e.session(e.globex, principal.RoleOrgAdmin)
	dev := e.insertDevice(e.acme, "lt-adopted", "active")
	e.insertDevice(e.acme, "lt-enforced", "active")
	if _, err := e.super.Exec(context.Background(), "UPDATE device SET enrollment_method = 'adopted', config_mode = 'report_only' WHERE id = $1", dev); err != nil {
		t.Fatal(err)
	}
	enforce := "/api/v1/devices/" + dev.String() + "/enforce"

	for _, filter := range []url.Values{{"enrollment_method": {"adopted"}}, {"config_mode": {"report_only"}}} {
		if page := e.list(bob, "/api/v1/devices", filter); page.Total != 1 {
			t.Fatalf("%v: total %d", filter, page.Total)
		}
	}
	if r := e.do(call{method: "POST", path: enforce, cookie: dave, body: adminapi.DeviceEnforce{Hostname: "lt-adopted"}}); r.status != http.StatusForbidden {
		t.Fatalf("auditor: %d", r.status)
	}
	if r := e.do(call{method: "POST", path: enforce, cookie: carol, body: adminapi.DeviceEnforce{Hostname: "lt-adopted"}}); r.status != http.StatusNotFound {
		t.Fatalf("globex: %d", r.status)
	}
	wrong := e.do(call{method: "POST", path: enforce, cookie: bob, body: adminapi.DeviceEnforce{Hostname: "lt-other"}})
	if wrong.status != http.StatusBadRequest || wrong.problemCode(t) != "invalid_request" {
		t.Fatalf("wrong hostname: %d %s", wrong.status, wrong.body)
	}
	e.expectEvent(wrong, "device.enforcement_enabled:failure:invalid_request")
	ok := e.do(call{method: "POST", path: enforce, cookie: bob, body: adminapi.DeviceEnforce{Hostname: "lt-adopted"}})
	if ok.status != http.StatusOK {
		t.Fatalf("enforce: %d %s", ok.status, ok.body)
	}
	e.expectEvent(ok, "device.enforcement_enabled:success:")
	var d adminapi.Device
	ok.decode(t, &d)
	if d.ConfigMode != adminapi.ConfigModeEnforce || d.ConfigModeChangedAt == nil || d.EnrollmentMethod != adminapi.EnrollmentMethodAdopted {
		t.Fatalf("device %+v", d)
	}
	again := e.do(call{method: "POST", path: enforce, cookie: bob, body: adminapi.DeviceEnforce{Hostname: "lt-adopted"}})
	if again.status != http.StatusConflict || again.problemCode(t) != "invalid_state" {
		t.Fatalf("enforce twice: %d %s", again.status, again.body)
	}
	if page := e.list(bob, "/api/v1/devices", url.Values{"config_mode": {"report_only"}}); page.Total != 0 {
		t.Fatalf("report-only after enforce: %d", page.Total)
	}

	// The plan error of the report-only report keeps its report's mode after enforcement (plan M11 amendment R6.15).
	for _, q := range []string{
		`INSERT INTO bundle (device_id, version, organization_id, content_sha256, envelope_sha256, object_key) VALUES ($1, 1, $2, '\x01', '\x02', 'k')`,
		`INSERT INTO device_bundle_report (device_id, organization_id, version, outcome, mode, occurred_at) VALUES ($1, $2, 1, 'applied', 'report_only', now())`,
		`INSERT INTO device_resource_status (device_id, organization_id, resource_id, status, bundle_version, occurred_at) VALUES ($1, $2, 'unit:x.service', 'failed', 1, now())`,
	} {
		if _, err := e.super.Exec(context.Background(), q, dev, e.acme); err != nil {
			t.Fatal(err)
		}
	}
	status := e.do(call{method: "GET", path: "/api/v1/devices/" + dev.String() + "/config-status", cookie: dave})
	var rows adminapi.DeviceResourceStatusPage
	status.decode(t, &rows)
	if status.status != http.StatusOK || len(rows.Items) != 1 || rows.Items[0].ReportMode != adminapi.ConfigModeReportOnly {
		t.Fatalf("config status %d %s", status.status, status.body)
	}
}
