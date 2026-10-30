package admin_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/adapters/auditpg/auditstore"
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

// TestReadAccessRecordingSwitchUnknown (plan M10 amendment 2026-10-31, PDK-139 round 3): when the recording switch
// cannot be read, the read records nothing and fails, so no list is served unrecorded. The request's deadline has
// passed before the handler opens its transaction. The request bypasses the contract check of env.do: the contract
// documents no 500 response.
func TestReadAccessRecordingSwitchUnknown(t *testing.T) {
	e := newEnv(t)
	org := e.org("switchunknown")
	dev := uuid.Must(uuid.NewV7())
	if _, err := e.super.Exec(context.Background(), "INSERT INTO device (id, organization_id, hostname, state) VALUES ($1, $2, 'ws-1', 'active')", dev, org); err != nil {
		t.Fatal(err)
	}
	if _, err := e.super.Exec(context.Background(), `UPDATE organization_privacy_settings
		SET audit_search_recorded = true, inventory_view_recorded = true WHERE organization_id = $1`, org); err != nil {
		t.Fatal(err)
	}
	alice := e.session(org, principal.RoleOrgAdmin)
	expired, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	for _, path := range []string{"/api/v1/audit-events", "/api/v1/devices/" + dev.String() + "/software",
		"/api/v1/devices/" + dev.String() + "/vulnerabilities"} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(expired, http.MethodGet, "https://admin.test"+path, nil)
		req.AddCookie(alice)
		e.handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusInternalServerError || strings.Contains(rec.Body.String(), `"items"`) {
			t.Fatalf("GET %s with the switch unknown: %d %s", path, rec.Code, rec.Body)
		}
		if ev := e.events(rec.Header().Get(httpx.HeaderRequestID)); len(ev) != 0 {
			t.Fatalf("GET %s with the switch unknown recorded %v", path, ev)
		}
	}
}

// TestReadAccessRecordingMillisecondRange (PDK-139 round 3): a range finer than a millisecond is truncated once, so the
// recorded range and the listed range are the same. An event at T is listed by a search from T+0.4 ms to T+1.4 ms,
// whose recording names T and T+1 ms.
func TestReadAccessRecordingMillisecondRange(t *testing.T) {
	e := newEnv(t)
	org := e.org("msrange")
	if _, err := e.super.Exec(context.Background(), `UPDATE organization_privacy_settings
		SET audit_search_recorded = true WHERE organization_id = $1`, org); err != nil {
		t.Fatal(err)
	}
	at := time.Now().UTC().Add(-time.Hour).Truncate(time.Millisecond)
	err := e.writer.InWriter(context.Background(), func(ctx context.Context, q *auditstore.Queries) error {
		if err := q.EnsureAuditPartition(ctx, at); err != nil {
			return err
		}
		_, err := q.InsertAuditEvent(ctx, auditstore.InsertAuditEventParams{
			EventID: uuid.Must(uuid.NewV7()), OrganizationID: org, OccurredAt: at, RecordedAt: at, Code: "device_group.created",
			Outcome: "success", Source: "portal", Actor: []byte(`{"type":"admin","display":"alice","step_up":false}`),
			Params: []byte(`{}`), CorrelationID: "at-t", ObjectKey: "k",
		})
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	query := url.Values{
		"from": {at.Add(400 * time.Microsecond).Format(time.RFC3339Nano)},
		"to":   {at.Add(1400 * time.Microsecond).Format(time.RFC3339Nano)},
	}
	r := e.do(call{method: http.MethodGet, path: "/api/v1/audit-events?" + query.Encode(), cookie: e.session(org, principal.RoleOrgAdmin)})
	if r.status != http.StatusOK {
		t.Fatalf("GET: %d %s", r.status, r.body)
	}
	var listed struct {
		Items []struct {
			CorrelationID string `json:"correlation_id"`
		} `json:"items"`
	}
	if err := json.Unmarshal(r.body, &listed); err != nil {
		t.Fatal(err)
	}
	if len(listed.Items) != 1 || listed.Items[0].CorrelationID != "at-t" {
		t.Fatalf("listed %s, want the event at %s", r.body, at.Format(time.RFC3339Nano))
	}
	var from, to string
	if err := e.super.QueryRow(context.Background(), `SELECT params->>'from', params->>'to' FROM action
		WHERE correlation_id = $1 AND code = 'audit.searched'`, r.header.Get(httpx.HeaderRequestID)).Scan(&from, &to); err != nil {
		t.Fatal(err)
	}
	if from != at.Format(time.RFC3339Nano) || to != at.Add(time.Millisecond).Format(time.RFC3339Nano) {
		t.Fatalf("recorded %s to %s, want %s to %s", from, to, at.Format(time.RFC3339Nano), at.Add(time.Millisecond).Format(time.RFC3339Nano))
	}
}
