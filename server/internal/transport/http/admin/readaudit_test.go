package admin_test

import (
	"context"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/platform/httpx"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/transport/http/admin"
)

// TestReadAccessRecording (plan M10 decision 20): with the organization's switches on, the audit log list records
// audit.searched before it lists and the software and vulnerability lists of a device record device.inventory_viewed,
// each once per window; a refused read (missing device, bad input) is recorded as failure; an operator's search is
// recorded as denied and refused; with the switches off no list read, refused or not, records anything.
func TestReadAccessRecording(t *testing.T) {
	e := newEnv(t)
	org := e.org("reads")
	dev := uuid.Must(uuid.NewV7())
	if _, err := e.super.Exec(context.Background(), "INSERT INTO device (id, organization_id, hostname, state) VALUES ($1, $2, 'ws-1', 'active')", dev, org); err != nil {
		t.Fatal(err)
	}
	count := func(code string) int {
		var n int
		if err := e.super.QueryRow(context.Background(), "SELECT count(*) FROM action WHERE organization_id = $1 AND code = $2", org, code).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	alice := e.session(org, principal.RoleOrgAdmin)
	reads := func() {
		t.Helper()
		for _, path := range []string{"/api/v1/audit-events", "/api/v1/audit-events?q=alice",
			"/api/v1/devices/" + dev.String() + "/software", "/api/v1/devices/" + dev.String() + "/vulnerabilities"} {
			if r := e.do(call{method: http.MethodGet, path: path, cookie: alice}); r.status != http.StatusOK {
				t.Fatalf("GET %s: %d %s", path, r.status, r.body)
			}
		}
	}

	reads()
	if s, v := count("audit.searched"), count("device.inventory_viewed"); s != 0 || v != 0 {
		t.Fatalf("switches off: %d searches, %d views recorded", s, v)
	}

	if _, err := e.super.Exec(context.Background(), `UPDATE organization_privacy_settings
		SET audit_search_recorded = true, inventory_view_recorded = true WHERE organization_id = $1`, org); err != nil {
		t.Fatal(err)
	}
	reads()
	reads()
	if s, v := count("audit.searched"), count("device.inventory_viewed"); s != 2 || v != 1 {
		t.Fatalf("switches on: %d searches, %d views recorded, want a search without and one with a search text and one view", s, v)
	}

	operator := e.session(org, principal.RoleOrgOperator)
	r := e.do(call{method: http.MethodGet, path: "/api/v1/audit-events", cookie: operator})
	if r.status != http.StatusForbidden {
		t.Fatalf("operator search: %d %s", r.status, r.body)
	}
	e.expectEvent(r, "audit.searched:denied:forbidden")

	missing := e.do(call{method: http.MethodGet, path: "/api/v1/devices/" + uuid.NewString() + "/software", cookie: alice})
	if missing.status != http.StatusNotFound {
		t.Fatalf("missing device: %d %s", missing.status, missing.body)
	}
	e.expectEvent(missing, "device.inventory_viewed:failure:not_found")
	for path, want := range map[string]string{
		"/api/v1/audit-events?page=101&page_size=100":                                 "audit.searched:failure:page_out_of_range",
		"/api/v1/audit-events?from=2099-01-01T00:00:00Z":                              "audit.searched:failure:invalid_request",
		"/api/v1/devices/" + dev.String() + "/vulnerabilities?page=101&page_size=100": "device.inventory_viewed:failure:page_out_of_range",
	} {
		r := e.do(call{method: http.MethodGet, path: path, cookie: alice})
		if r.status != http.StatusBadRequest {
			t.Fatalf("GET %s: %d %s", path, r.status, r.body)
		}
		e.expectEvent(r, want)
	}

	if _, err := e.super.Exec(context.Background(), `UPDATE organization_privacy_settings
		SET audit_search_recorded = false, inventory_view_recorded = false WHERE organization_id = $1`, org); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/api/v1/audit-events?page=101&page_size=100", "/api/v1/devices/" + uuid.NewString() + "/software"} {
		r := e.do(call{method: http.MethodGet, path: path, cookie: alice})
		if r.status != http.StatusBadRequest && r.status != http.StatusNotFound {
			t.Fatalf("switches off, GET %s: %d %s", path, r.status, r.body)
		}
		if ev := e.events(r.header.Get(httpx.HeaderRequestID)); len(ev) != 0 {
			t.Fatalf("switches off, GET %s recorded %v", path, ev)
		}
	}
}

// TestReadAccessRecordingOneRange (PDK-139): the recording and the list search the same range, so a from just after
// the recording's clock cannot be refused by the recording and served by the list. The handler's clock runs a minute
// ahead of the use cases' clocks; a from between both is served and recorded.
func TestReadAccessRecordingOneRange(t *testing.T) {
	e := newEnvWith(t, func(d *admin.Deps) { d.Now = func() time.Time { return time.Now().Add(time.Minute) } })
	org := e.org("onerange")
	if _, err := e.super.Exec(context.Background(), `UPDATE organization_privacy_settings
		SET audit_search_recorded = true WHERE organization_id = $1`, org); err != nil {
		t.Fatal(err)
	}
	from := time.Now().Add(10 * time.Second).UTC().Format(time.RFC3339Nano)
	r := e.do(call{method: http.MethodGet, path: "/api/v1/audit-events?from=" + url.QueryEscape(from), cookie: e.session(org, principal.RoleOrgAdmin)})
	if r.status != http.StatusOK {
		t.Fatalf("GET: %d %s", r.status, r.body)
	}
	e.expectEvent(r, "audit.searched:success:")
}
