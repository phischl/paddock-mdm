package admin_test

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/transport/http/admin/adminapi"
)

// TestSoftwareStatusEndpoints (ticket PDK-411): what a device reports about the catalog's applications on the device's
// and on the entry's page, the derived states and the filters over both, the read roles, and that another
// organization's device or entry is 404.
func TestSoftwareStatusEndpoints(t *testing.T) {
	e := newEnv(t)
	auditor := e.session(e.acme, principal.RoleOrgAuditor)
	carol := e.session(e.globex, principal.RoleOrgAdmin)
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := e.super.Exec(context.Background(), sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	dev := e.insertDevice(e.acme, "status-a1", "active")
	exec(`UPDATE device SET os_release = '{"id":"ubuntu","version_id":"24.04"}' WHERE id = $1`, dev)
	globexDev := e.insertDevice(e.globex, "status-g1", "active")
	entry := func(org uuid.UUID, name, packages string) uuid.UUID {
		id := uuid.Must(uuid.NewV7())
		exec(`INSERT INTO software_catalog_entry (id, organization_id, name, packages) VALUES ($1, $2, $3, $4::jsonb)`, id, org, name, packages)
		exec(`INSERT INTO software_assignment (id, organization_id, catalog_entry_id, intent) VALUES ($1, $2, $3, 'required')`, uuid.Must(uuid.NewV7()), org, id)
		return id
	}
	editor := entry(e.acme, "Editor", `[{"distribution":"ubuntu","release":"*","architecture":"*","package":"nano"}]`)
	tool := entry(e.acme, "Debian tool", `[{"distribution":"debian","release":"*","architecture":"*","package":"deb-tool"}]`)
	browser := entry(e.acme, "Browser", `[{"distribution":"ubuntu","release":"*","architecture":"*","package":"firefox"}]`)
	globexEntry := entry(e.globex, "Globex app", `[{"distribution":"ubuntu","release":"*","architecture":"*","package":"nano"}]`)
	exec(`INSERT INTO device_software_status (device_id, organization_id, catalog_entry_id, package, intent, state, version, reason, error, reported_at)
		VALUES ($1, $2, $3, 'nano', 'required', 'failed', '7.2', 'apt_failed', 'E: unable to locate package', now())`, dev, e.acme, editor)

	var managed adminapi.DeviceManagedSoftwarePage
	e.get(t, auditor, "/api/v1/devices/"+dev.String()+"/managed-software", &managed)
	if managed.Total != 3 || managed.Items[0].Name != "Browser" || managed.Items[0].State != adminapi.DeviceSoftwareStateUnknown || managed.Items[0].ReportedAt != nil ||
		managed.Items[0].Package != "firefox" || managed.Items[1].State != adminapi.DeviceSoftwareStateNotApplicable ||
		managed.Items[2].State != adminapi.DeviceSoftwareStateFailed || managed.Items[2].Version != "7.2" || managed.Items[2].Reason != "apt_failed" || managed.Items[2].ReportedAt == nil {
		t.Fatalf("managed software %+v", managed)
	}
	if managed.Truncated {
		t.Fatal("truncated without a truncated report")
	}
	exec(`INSERT INTO device_status (device_id, organization_id, software_truncated) VALUES ($1, $2, true)`, dev, e.acme)
	e.get(t, auditor, "/api/v1/devices/"+dev.String()+"/managed-software", &managed)
	if !managed.Truncated {
		t.Fatal("a truncated report is not shown")
	}
	e.get(t, auditor, "/api/v1/devices/"+dev.String()+"/managed-software?state=failed", &managed)
	if managed.Total != 1 || managed.Items[0].CatalogEntryId != editor {
		t.Fatalf("state=failed %+v", managed)
	}
	e.get(t, auditor, "/api/v1/devices/"+dev.String()+"/managed-software?state=not_applicable&intent=required&q=debian", &managed)
	if managed.Total != 1 || managed.Items[0].CatalogEntryId != tool {
		t.Fatalf("state=not_applicable %+v", managed)
	}
	e.get(t, auditor, "/api/v1/devices/"+dev.String()+"/managed-software?sort=-reported_at&page_size=10", &managed)
	if managed.Items[len(managed.Items)-1].CatalogEntryId != editor || managed.Sort != "-reported_at" {
		t.Fatalf("-reported_at %+v", managed)
	}

	var devices adminapi.SoftwareCatalogDevicePage
	e.get(t, auditor, "/api/v1/software-catalog/"+editor.String()+"/devices", &devices)
	if devices.Total != 1 || devices.Items[0].DeviceId != dev || devices.Items[0].State != adminapi.DeviceSoftwareStateFailed || devices.Items[0].Hostname != "status-a1" {
		t.Fatalf("catalog devices %+v", devices)
	}
	// PDK-716: a device without name and groups has "" and [] (never null); with a name and two groups it lists both.
	if devices.Items[0].Name != "" || devices.Items[0].DeviceGroupIds == nil || len(devices.Items[0].DeviceGroupIds) != 0 {
		t.Fatalf("device without name and groups %+v", devices.Items[0])
	}
	groups := []uuid.UUID{uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())}
	for i, g := range groups {
		exec(`INSERT INTO device_group (id, organization_id, name) VALUES ($1, $2, $3)`, g, e.acme, fmt.Sprintf("Group %d", i))
		exec(`INSERT INTO device_group_member (organization_id, device_group_id, device_id) VALUES ($1, $2, $3)`, e.acme, g, dev)
	}
	exec(`UPDATE device SET name = 'status-laptop' WHERE id = $1`, dev)
	e.get(t, auditor, "/api/v1/software-catalog/"+editor.String()+"/devices", &devices)
	gotGroups := slices.Clone(devices.Items[0].DeviceGroupIds)
	slices.SortFunc(gotGroups, func(a, b uuid.UUID) int { return strings.Compare(a.String(), b.String()) })
	slices.SortFunc(groups, func(a, b uuid.UUID) int { return strings.Compare(a.String(), b.String()) })
	if devices.Items[0].Name != "status-laptop" || !slices.Equal(gotGroups, groups) {
		t.Fatalf("device with name and groups %+v", devices.Items[0])
	}
	e.get(t, auditor, "/api/v1/software-catalog/"+editor.String()+"/devices?device_group_id="+groups[0].String(), &devices)
	if devices.Total != 1 || devices.Items[0].DeviceId != dev {
		t.Fatalf("group filter %+v", devices)
	}
	e.get(t, auditor, "/api/v1/software-catalog/"+browser.String()+"/devices?state=unknown&q=status", &devices)
	if devices.Total != 1 || devices.Items[0].Package != "firefox" || devices.Items[0].ReportedAt != nil {
		t.Fatalf("unknown %+v", devices)
	}
	e.get(t, auditor, "/api/v1/software-catalog/"+tool.String()+"/devices?state=not_applicable", &devices)
	if devices.Total != 1 {
		t.Fatalf("not_applicable %+v", devices)
	}
	e.get(t, auditor, "/api/v1/software-catalog/"+editor.String()+"/devices?device_group_id="+uuid.NewString(), &devices)
	if devices.Total != 0 {
		t.Fatalf("a group without the device lists %+v", devices)
	}

	// PDK-716 fix round 1: another organization's group id as the filter of an own entry is an empty 200, no oracle.
	globexGroup := uuid.Must(uuid.NewV7())
	exec(`INSERT INTO device_group (id, organization_id, name) VALUES ($1, $2, 'Globex group')`, globexGroup, e.globex)
	exec(`INSERT INTO device_group_member (organization_id, device_group_id, device_id) VALUES ($1, $2, $3)`, e.globex, globexGroup, globexDev)
	r := e.do(call{method: "GET", path: "/api/v1/software-catalog/" + editor.String() + "/devices?device_group_id=" + globexGroup.String(), cookie: auditor})
	if r.status != http.StatusOK {
		t.Fatalf("foreign group filter: %d %s", r.status, r.body)
	}
	r.decode(t, &devices)
	if devices.Total != 0 || len(devices.Items) != 0 {
		t.Fatalf("foreign group filter lists %+v", devices)
	}

	// Another organization's device or entry is not found, in both directions.
	for _, c := range []struct {
		name   string
		cookie *http.Cookie
		path   string
	}{
		{"foreign device", auditor, "/api/v1/devices/" + globexDev.String() + "/managed-software"},
		{"foreign entry", auditor, "/api/v1/software-catalog/" + globexEntry.String() + "/devices"},
		{"unknown device", auditor, "/api/v1/devices/" + uuid.NewString() + "/managed-software"},
		{"acme device of globex", carol, "/api/v1/devices/" + dev.String() + "/managed-software"},
		{"acme entry of globex", carol, "/api/v1/software-catalog/" + editor.String() + "/devices"},
	} {
		r := e.do(call{method: "GET", path: c.path, cookie: c.cookie})
		if r.status != http.StatusNotFound || r.problemCode(t) != "not_found" {
			t.Errorf("%s: %d %s, want 404 not_found", c.name, r.status, r.body)
		}
	}
	// PDK-803: a user-scope row is listed next to the system row of the entry and selected by the scope filter.
	exec(`INSERT INTO device_software_status (device_id, organization_id, catalog_entry_id, package, intent, state, scope, reported_at)
		VALUES ($1, $2, $3, 'nano', 'available', 'installed', 'user', now())`, dev, e.acme, editor)
	e.get(t, auditor, "/api/v1/devices/"+dev.String()+"/managed-software?scope=user", &managed)
	if managed.Total != 1 || managed.Items[0].CatalogEntryId != editor || managed.Items[0].Scope != adminapi.SoftwareScopeUser ||
		managed.Items[0].Intent != adminapi.SoftwareIntentAvailable {
		t.Fatalf("scope=user %+v", managed)
	}
	e.get(t, auditor, "/api/v1/devices/"+dev.String()+"/managed-software?scope=system", &managed)
	if managed.Total != 3 || slices.ContainsFunc(managed.Items, func(m adminapi.DeviceManagedSoftware) bool { return m.Scope != adminapi.SoftwareScopeSystem }) {
		t.Fatalf("scope=system %+v", managed)
	}
	e.get(t, auditor, "/api/v1/software-catalog/"+editor.String()+"/devices", &devices)
	if devices.Total != 2 || devices.Items[0].Scope != adminapi.SoftwareScopeSystem || devices.Items[1].Scope != adminapi.SoftwareScopeUser {
		t.Fatalf("devices of an entry with two scopes %+v", devices)
	}
	e.get(t, auditor, "/api/v1/software-catalog/"+editor.String()+"/devices?scope=user", &devices)
	if devices.Total != 1 || devices.Items[0].Scope != adminapi.SoftwareScopeUser || devices.Items[0].DeviceId != dev {
		t.Fatalf("devices scope=user %+v", devices)
	}
	r = e.do(call{method: "GET", path: "/api/v1/devices/" + globexDev.String() + "/managed-software?scope=user", cookie: auditor})
	if r.status != http.StatusNotFound {
		t.Fatalf("foreign device with a scope filter: %d", r.status)
	}
	e.expectRejected(auditor, "/api/v1/devices/"+dev.String()+"/managed-software?scope=group", "invalid_request")
	e.expectRejected(auditor, "/api/v1/software-catalog/"+editor.String()+"/devices?scope=group", "invalid_request")
	e.expectRejected(auditor, "/api/v1/devices/"+dev.String()+"/managed-software?state=bogus", "invalid_request")
	e.expectRejected(auditor, "/api/v1/devices/"+dev.String()+"/managed-software?sort=hostname", "invalid_request")
	e.expectRejected(auditor, "/api/v1/software-catalog/"+editor.String()+"/devices?sort=name", "invalid_request")
	e.expectRejected(auditor, "/api/v1/software-catalog/"+editor.String()+"/devices?page=401&page_size=25", "page_out_of_range")
}
