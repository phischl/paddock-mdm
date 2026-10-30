package admin_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/platform/httpx"
	"github.com/phischl/paddock-mdm/server/internal/principal"
)

// TestReadAccessRecording (plan M10 decision 20): with the organization's switches on, the audit log list records
// audit.searched before it lists and the software and vulnerability lists of a device record device.inventory_viewed,
// each once per window; an operator's search is recorded as denied and refused; with the switches off no list read
// records anything.
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
	if s, v := count("audit.searched"), count("device.inventory_viewed"); s != 1 || v != 1 {
		t.Fatalf("switches on: %d searches, %d views recorded, want one each", s, v)
	}

	operator := e.session(org, principal.RoleOrgOperator)
	r := e.do(call{method: http.MethodGet, path: "/api/v1/audit-events", cookie: operator})
	if r.status != http.StatusForbidden {
		t.Fatalf("operator search: %d %s", r.status, r.body)
	}
	e.expectEvent(r, "audit.searched:denied:forbidden")

	missing := e.do(call{method: http.MethodGet, path: "/api/v1/devices/" + uuid.NewString() + "/software", cookie: alice})
	if missing.status != http.StatusNotFound || len(e.events(missing.header.Get(httpx.HeaderRequestID))) != 0 {
		t.Fatalf("missing device: %d, events %v", missing.status, e.events(missing.header.Get(httpx.HeaderRequestID)))
	}
}
