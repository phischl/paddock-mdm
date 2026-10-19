package admin_test

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/transport/http/admin/adminapi"
)

// TestDeviceName (ADR 0041 decision 2): PUT /devices/{id}/name sets and clears the managed name, the list finds a
// device by it, and invalid names, a taken name, an auditor and a foreign device are refused.
func TestDeviceName(t *testing.T) {
	e := newEnv(t)
	alice := e.session(e.acme, principal.RoleOrgOperator)
	auditor := e.session(e.acme, principal.RoleOrgAuditor)
	carol := e.session(e.globex, principal.RoleOrgAdmin)
	dev := e.insertDevice(e.acme, "ubuntu-"+uuid.NewString()[:8], "active")
	other := e.insertDevice(e.acme, "ubuntu-"+uuid.NewString()[:8], "active")
	path := "/api/v1/devices/" + dev.String() + "/name"
	unique := "lap-" + uuid.NewString()[:8]

	set := e.do(call{method: "PUT", path: path, cookie: alice, body: map[string]any{"name": unique}})
	if set.status != http.StatusOK {
		t.Fatalf("set name: %d %s", set.status, set.body)
	}
	e.expectEvent(set, "device.name_changed:success:")
	var dd adminapi.DeviceDetail
	set.decode(t, &dd)
	if dd.Name == nil || *dd.Name != unique || dd.NameState != adminapi.DeviceDetailNameStatePending {
		t.Fatalf("detail name %v state %s", dd.Name, dd.NameState)
	}
	if found := e.list(alice, "/api/v1/devices", url.Values{"q": {unique[:9]}}); found.Total != 1 {
		t.Fatalf("q by name: %d devices", found.Total)
	}

	for _, bad := range []string{"A1", "a.b", "localhost"} {
		r := e.do(call{method: "PUT", path: path, cookie: alice, body: map[string]any{"name": bad}, skipReqCheck: true})
		if r.status != http.StatusBadRequest || r.problemCode(t) != "invalid_request" {
			t.Fatalf("%q: %d %s", bad, r.status, r.body)
		}
	}
	taken := e.do(call{method: "PUT", path: "/api/v1/devices/" + other.String() + "/name", cookie: alice, body: map[string]any{"name": unique}})
	if taken.status != http.StatusConflict || taken.problemCode(t) != "conflict" {
		t.Fatalf("taken: %d %s", taken.status, taken.body)
	}
	if r := e.do(call{method: "PUT", path: path, cookie: auditor, body: map[string]any{"name": "x"}}); r.status != http.StatusForbidden {
		t.Fatalf("auditor: %d %s", r.status, r.body)
	} else {
		e.expectEvent(r, "device.name_changed:denied:forbidden")
	}
	if r := e.do(call{method: "PUT", path: path, cookie: carol, body: map[string]any{"name": "x"}}); r.status != http.StatusNotFound ||
		r.problemCode(t) != "not_found" {
		t.Fatalf("foreign: %d %s", r.status, r.body)
	}

	cleared := e.do(call{method: "PUT", path: path, cookie: alice, body: map[string]any{"name": nil}})
	if cleared.status != http.StatusOK {
		t.Fatalf("clear: %d %s", cleared.status, cleared.body)
	}
	cleared.decode(t, &dd)
	if dd.Name != nil || dd.NameState != adminapi.DeviceDetailNameStateUnmanaged {
		t.Fatalf("cleared name %v state %s", dd.Name, dd.NameState)
	}
}
