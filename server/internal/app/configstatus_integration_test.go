package app_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/pkg/protocol"
	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/problem"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/pgtest"
)

type statusRowT struct {
	Status  string
	Message string
	Changes []string
	Version int64
}

func statusRows(t *testing.T, h releaseHarness, device uuid.UUID) map[string]statusRowT {
	t.Helper()
	rows, err := h.super.Query(context.Background(),
		"SELECT resource_id, status, message, changes, bundle_version FROM device_resource_status WHERE device_id = $1", device)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	out := map[string]statusRowT{}
	for rows.Next() {
		var id string
		var r statusRowT
		if err := rows.Scan(&id, &r.Status, &r.Message, &r.Changes, &r.Version); err != nil {
			t.Fatal(err)
		}
		out[id] = r
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

func record(t *testing.T, h releaseHarness, org, device uuid.UUID, seq int64, typ string, at time.Time, data any) {
	t.Helper()
	raw, err := json.Marshal(data)
	if err != nil {
		t.Fatal(err)
	}
	if fresh, err := h.reports.RecordEvent(systemCtx(org), device, protocol.Event{EventSeq: seq, Type: typ, OccurredAt: at, Data: raw}); err != nil || !fresh {
		t.Fatalf("event %d: fresh %v, %v", seq, fresh, err)
	}
}

// TestConfigStatusIngest: bundle.applied with resources upserts one row per entry and deletes the rows of resources
// that left the bundle, an older report changes nothing, and the audit params carry the mode but never the resources
// (plan M11 decision 13).
func TestConfigStatusIngest(t *testing.T) {
	h := newReleaseHarness(t, true)
	org, device := h.device(t)
	at := time.Now().UTC().Truncate(time.Millisecond)
	record(t, h, org, device, 1, protocol.EventBundleApplied, at, map[string]any{
		"version": 7, "changed": 2, "mode": "report_only", "errors": []any{},
		"resources": []map[string]any{
			{"id": "file:/etc/a.conf", "status": "applied"},
			{"id": "unit:b.service", "status": "failed", "message": "unit not found"},
			{"id": "time", "status": "pending", "changes": []string{"set timezone to UTC"}},
			{"id": "sudo", "status": "bogus"},
		},
	})
	rows := statusRows(t, h, device)
	if len(rows) != 3 || rows["file:/etc/a.conf"].Status != "applied" || rows["unit:b.service"].Message != "unit not found" ||
		rows["time"].Status != "pending" || len(rows["time"].Changes) != 1 || rows["time"].Version != 7 {
		t.Fatalf("rows %+v", rows)
	}
	var mode string
	var changed, errorCount int
	if err := h.super.QueryRow(context.Background(), "SELECT mode, changed, error_count FROM device_bundle_report WHERE device_id = $1 AND version = 7", device).
		Scan(&mode, &changed, &errorCount); err != nil || mode != "report_only" || changed != 2 || errorCount != 0 {
		t.Fatalf("report %s %d %d (%v)", mode, changed, errorCount, err)
	}
	var params string
	if err := h.super.QueryRow(context.Background(), "SELECT params::text FROM action WHERE organization_id = $1 AND code = 'device.bundle_applied'", org).Scan(&params); err != nil ||
		!strings.Contains(params, `"mode"`) || strings.Contains(params, "resources") {
		t.Fatalf("audit params %s (%v)", params, err)
	}

	// A report one minute later drops what left the bundle.
	record(t, h, org, device, 2, protocol.EventBundleApplied, at.Add(time.Minute), map[string]any{
		"version": 8, "changed": 1, "mode": "enforce",
		"resources": []map[string]any{{"id": "file:/etc/a.conf", "status": "applied"}},
	})
	if rows = statusRows(t, h, device); len(rows) != 1 || rows["file:/etc/a.conf"].Version != 8 {
		t.Fatalf("after the second report: %+v", rows)
	}
	// An older report that arrives late neither overwrites, nor deletes, nor brings back a resource that left the bundle.
	record(t, h, org, device, 3, protocol.EventBundleApplied, at.Add(-time.Hour), map[string]any{
		"version": 6, "resources": []map[string]any{{"id": "unit:old.service", "status": "failed", "message": "old"}},
	})
	if rows = statusRows(t, h, device); len(rows) != 1 || rows["file:/etc/a.conf"].Version != 8 {
		t.Fatalf("after the late report: %+v", rows)
	}
	var lateOutcome string
	if err := h.super.QueryRow(context.Background(), "SELECT outcome FROM device_bundle_report WHERE device_id = $1 AND version = 6", device).Scan(&lateOutcome); err != nil || lateOutcome != "applied" {
		t.Fatalf("the late report of version 6 was not kept: %s (%v)", lateOutcome, err)
	}
	record(t, h, org, device, 4, protocol.EventBundleApplied, at.Add(-2*time.Hour), map[string]any{
		"version": 8, "mode": "report_only", "resources": []map[string]any{{"id": "file:/etc/a.conf", "status": "failed", "message": "late"}},
	})
	if rows = statusRows(t, h, device); rows["file:/etc/a.conf"].Status != "applied" {
		t.Fatalf("a late report overwrote a newer row: %+v", rows)
	}
	if err := h.super.QueryRow(context.Background(), "SELECT mode FROM device_bundle_report WHERE device_id = $1 AND version = 8", device).Scan(&mode); err != nil || mode != "enforce" {
		t.Fatalf("a late report overwrote the report of version 8: %s (%v)", mode, err)
	}
}

// TestConfigStatusIngestWithoutResources: an agent without per-resource outcomes upserts failed rows from its errors
// and deletes the device's other failed rows only (plan M11 decision 13).
func TestConfigStatusIngestWithoutResources(t *testing.T) {
	h := newReleaseHarness(t, true)
	org, device := h.device(t)
	at := time.Now().UTC().Truncate(time.Millisecond)
	record(t, h, org, device, 1, protocol.EventBundleApplied, at, map[string]any{
		"version": 1, "resources": []map[string]any{
			{"id": "file:/etc/ok.conf", "status": "applied"}, {"id": "unit:x.service", "status": "failed", "message": "x"},
		},
	})
	record(t, h, org, device, 2, protocol.EventBundleApplied, at.Add(time.Minute), map[string]any{
		"version": 2, "changed": 0, "errors": []map[string]string{{"id": "unit:y.service", "message": "y failed\x00"}},
	})
	rows := statusRows(t, h, device)
	if len(rows) != 2 || rows["file:/etc/ok.conf"].Status != "applied" || rows["unit:y.service"].Status != "failed" || rows["unit:y.service"].Message != "y failed" {
		t.Fatalf("rows %+v", rows)
	}
	var errorCount int
	if err := h.super.QueryRow(context.Background(), "SELECT error_count FROM device_bundle_report WHERE device_id = $1 AND version = 2", device).Scan(&errorCount); err != nil || errorCount != 1 {
		t.Fatalf("error_count %d (%v)", errorCount, err)
	}
}

// TestConfigStatusRejectedAndDrift: bundle.rejected records the outcome rejected with its reason and leaves the rows;
// config.drift_corrected sets drift_corrected.
func TestConfigStatusRejectedAndDrift(t *testing.T) {
	h := newReleaseHarness(t, true)
	org, device := h.device(t)
	at := time.Now().UTC().Truncate(time.Millisecond)
	record(t, h, org, device, 1, protocol.EventBundleApplied, at, map[string]any{
		"version": 3, "mode": "report_only", "resources": []map[string]any{{"id": "file:/etc/a.conf", "status": "applied"}, {"id": "time", "status": "applied"}},
	})
	record(t, h, org, device, 2, protocol.EventBundleRejected, at.Add(time.Minute), map[string]any{"version": 4, "reason": "signature"})
	var outcome, reason, mode string
	if err := h.super.QueryRow(context.Background(), "SELECT outcome, reason, mode FROM device_bundle_report WHERE device_id = $1 AND version = 4", device).Scan(&outcome, &reason, &mode); err != nil ||
		outcome != "rejected" || reason != "signature" || mode != "report_only" {
		t.Fatalf("rejected report %s %s %s (%v)", outcome, reason, mode, err)
	}
	if rows := statusRows(t, h, device); len(rows) != 2 || rows["time"].Status != "applied" {
		t.Fatalf("rows changed by a rejection: %+v", rows)
	}
	record(t, h, org, device, 3, protocol.EventConfigDriftCorrected, at.Add(2*time.Minute), map[string]any{"version": 3, "resource_ids": []string{"file:/etc/a.conf", "file:/etc/a.conf"}})
	rows := statusRows(t, h, device)
	if rows["file:/etc/a.conf"].Status != "drift_corrected" || rows["time"].Status != "applied" {
		t.Fatalf("rows %+v", rows)
	}

	// A drift correction that arrives after a newer report removed its resource does not bring the resource back.
	record(t, h, org, device, 4, protocol.EventBundleApplied, at.Add(4*time.Minute), map[string]any{
		"version": 5, "resources": []map[string]any{{"id": "time", "status": "applied"}},
	})
	record(t, h, org, device, 5, protocol.EventConfigDriftCorrected, at.Add(3*time.Minute), map[string]any{"version": 3, "resource_ids": []string{"file:/etc/a.conf", "time"}})
	if rows = statusRows(t, h, device); len(rows) != 1 || rows["time"].Status != "applied" || rows["time"].Version != 5 {
		t.Fatalf("after the late drift correction: %+v", rows)
	}

	// A device without an applied report has its rejection recorded as enforce, the agent's default mode.
	org2, fresh := h.device(t)
	record(t, h, org2, fresh, 1, protocol.EventBundleRejected, at, map[string]any{"version": 1, "reason": "signature"})
	if err := h.super.QueryRow(context.Background(), "SELECT mode FROM device_bundle_report WHERE device_id = $1 AND version = 1", fresh).Scan(&mode); err != nil || mode != "enforce" {
		t.Fatalf("rejection without an applied report: %s (%v)", mode, err)
	}
}

// TestConfigStatusIngestSerializesPerDevice: two ingest transactions of one device that run at the same time take
// turns, and the older report never brings back what the newer one removed (plan M11 decision 13, PDK-151 review 1).
func TestConfigStatusIngestSerializesPerDevice(t *testing.T) {
	h := newReleaseHarness(t, true)
	org, device := h.device(t)
	ctx := context.Background()
	at := time.Now().UTC().Truncate(time.Millisecond)
	record(t, h, org, device, 1, protocol.EventBundleApplied, at, map[string]any{
		"version": 1, "resources": []map[string]any{{"id": "file:/etc/a.conf", "status": "applied"}, {"id": "unit:old.service", "status": "applied"}},
	})

	hold, err := h.super.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = hold.Rollback(ctx) }()
	if _, err := hold.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended('config_status:' || $1::text, 0))", device); err != nil {
		t.Fatal(err)
	}
	waiting := func(want int) {
		t.Helper()
		deadline := time.Now().Add(10 * time.Second)
		for {
			var n int
			if err := hold.QueryRow(ctx, `SELECT count(*) FROM pg_locks l, (SELECT hashtextextended('config_status:' || $1::text, 0) AS k) h
				WHERE l.locktype = 'advisory' AND NOT l.granted AND l.objsubid = 1
				  AND l.classid::bigint = (h.k >> 32) & 4294967295 AND l.objid::bigint = h.k & 4294967295`, device).Scan(&n); err != nil {
				t.Fatal(err)
			}
			if n == want {
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("%d ingest transactions wait for the device lock, want %d", n, want)
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	send := func(seq int64, occurred time.Time, data map[string]any) <-chan error {
		done := make(chan error, 1)
		raw, err := json.Marshal(data)
		if err != nil {
			t.Fatal(err)
		}
		go func() {
			_, err := h.reports.RecordEvent(systemCtx(org), device, protocol.Event{EventSeq: seq, Type: protocol.EventBundleApplied, OccurredAt: occurred, Data: raw})
			done <- err
		}()
		return done
	}
	newer := send(2, at.Add(2*time.Minute), map[string]any{
		"version": 3, "resources": []map[string]any{{"id": "file:/etc/a.conf", "status": "applied"}},
	})
	waiting(1)
	older := send(3, at.Add(time.Minute), map[string]any{
		"version": 2, "resources": []map[string]any{{"id": "file:/etc/a.conf", "status": "failed"}, {"id": "unit:old.service", "status": "applied"}},
	})
	waiting(2)
	if err := hold.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	for _, done := range []<-chan error{newer, older} {
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
	if rows := statusRows(t, h, device); len(rows) != 1 || rows["file:/etc/a.conf"].Status != "applied" || rows["file:/etc/a.conf"].Version != 3 {
		t.Fatalf("after the concurrent reports: %+v", rows)
	}
}

// TestConfigStatusReads: the list use cases return the device's rows, its versions with and without a report, and the
// fleet counts over active devices; a foreign device is not_found and an auditor may read (plan M11 decision 14).
func TestConfigStatusReads(t *testing.T) {
	h := newReleaseHarness(t, true)
	env := pgtest.SharedPaddock(t)
	ctx := context.Background()
	pool, err := db.NewOrgPool(ctx, env.API, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	reads := app.NewConfigStatus(pool)
	org, device := h.device(t)
	otherOrg, otherDevice := h.device(t)
	retired := uuid.Must(uuid.NewV7())
	if _, err := h.super.Exec(ctx, "INSERT INTO device (id, organization_id, hostname, state) VALUES ($1, $2, 'gone', 'retired')", retired, org); err != nil {
		t.Fatal(err)
	}
	for _, v := range []int{1, 2} {
		if _, err := h.super.Exec(ctx, `INSERT INTO bundle (device_id, version, organization_id, content_sha256, envelope_sha256, object_key)
			VALUES ($1, $2, $3, '\x01', '\x02', 'k')`, device, v, org); err != nil {
			t.Fatal(err)
		}
	}
	at := time.Now().UTC().Truncate(time.Millisecond)
	record(t, h, org, device, 1, protocol.EventBundleApplied, at, map[string]any{
		"version": 1, "resources": []map[string]any{
			{"id": "file:/etc/a.conf", "status": "applied"}, {"id": "unit:b.service", "status": "failed", "message": "boom"}, {"id": "time", "status": "pending"},
		},
	})
	record(t, h, org, retired, 1, protocol.EventBundleApplied, at, map[string]any{
		"version": 1, "resources": []map[string]any{{"id": "unit:b.service", "status": "failed"}},
	})
	record(t, h, otherOrg, otherDevice, 1, protocol.EventBundleApplied, at, map[string]any{
		"version": 1, "resources": []map[string]any{{"id": "unit:foreign.service", "status": "failed"}},
	})
	account := func(role principal.Role, id uuid.UUID) context.Context {
		return principal.With(context.Background(), principal.Principal{Kind: principal.KindAdmin, Role: role, OrganizationID: id, ID: uuid.New(), Display: "t"})
	}
	auditor := account(principal.RoleOrgAuditor, org)
	page := app.ListPage{Sort: "resource_id", Limit: 10}

	res, err := reads.DeviceResources(auditor, device, app.ConfigStatusQuery{Page: page})
	if err != nil || res.Count != 3 || len(res.Items) != 3 || res.Items[0].ResourceID != "file:/etc/a.conf" {
		t.Fatalf("device resources %+v, %v", res, err)
	}
	failedOnly, err := reads.DeviceResources(auditor, device, app.ConfigStatusQuery{Page: page, Statuses: []string{"failed", "pending"}})
	if err != nil || failedOnly.Count != 2 {
		t.Fatalf("status filter %+v, %v", failedOnly, err)
	}
	if _, err := reads.DeviceResources(auditor, otherDevice, app.ConfigStatusQuery{Page: page}); !errors.Is(err, problem.NotFound) {
		t.Fatalf("foreign device = %v", err)
	}
	if _, err := reads.DeviceResources(context.Background(), device, app.ConfigStatusQuery{Page: page}); err == nil {
		t.Fatal("read without a principal")
	}

	bundles, err := reads.DeviceBundles(auditor, device, app.BundleQuery{Page: app.ListPage{Sort: "-version", Limit: 10}})
	if err != nil || bundles.Count != 2 || bundles.Items[0].Version != 2 || bundles.Items[0].ReportOutcome != nil ||
		bundles.Items[1].ReportOutcome == nil || *bundles.Items[1].ReportOutcome != "applied" {
		t.Fatalf("bundles %+v, %v", bundles, err)
	}
	none, err := reads.DeviceBundles(auditor, device, app.BundleQuery{Page: page, Outcomes: []string{"none"}})
	if err != nil || none.Count != 1 || none.Items[0].Version != 2 {
		t.Fatalf("outcome none %+v, %v", none, err)
	}

	fleet, err := reads.Fleet(auditor, app.ConfigStatusQuery{Page: app.ListPage{Sort: "-failed", Limit: 10}})
	if err != nil || fleet.Count != 3 {
		t.Fatalf("fleet %+v, %v", fleet, err)
	}
	for _, r := range fleet.Items {
		if r.ResourceID == "unit:foreign.service" {
			t.Fatal("the fleet view lists another organization's resource")
		}
		if r.ResourceID == "unit:b.service" && (r.Failed != 1 || r.LastFailureAt == nil) {
			t.Fatalf("a retired device counts: %+v", r)
		}
		if r.ResourceID == "file:/etc/a.conf" && (r.Applied != 1 || r.LastFailureAt != nil) {
			t.Fatalf("%+v", r)
		}
	}
	if fleet.Items[0].ResourceID != "unit:b.service" {
		t.Fatalf("default sort -failed: %+v", fleet.Items)
	}
}
