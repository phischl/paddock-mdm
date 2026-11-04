package app_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/pkg/command"
	"github.com/phischl/paddock-mdm/pkg/escrow"
	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/ingest"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/platform/httpx"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/problem"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/pgtest"
)

// fakeBundles is the escrow bucket of the diagnostics tests: objects by key, the prefixes deleted, and failing keys.
type fakeBundles struct {
	mu      sync.Mutex
	objects map[string][]byte
	deleted []string
	fail    error
	// afterDelete runs once after the next deletion, outside the lock: a step that races the retention round.
	afterDelete func()
}

func (f *fakeBundles) Size(_ context.Context, key string) (int64, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	b, ok := f.objects[key]
	return int64(len(b)), ok, f.fail
}

func (f *fakeBundles) SHA256(_ context.Context, key string) (string, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	b, ok := f.objects[key]
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), ok, f.fail
}

func (f *fakeBundles) DeleteAllVersions(_ context.Context, prefix string) (int, error) {
	f.mu.Lock()
	if f.fail != nil {
		f.mu.Unlock()
		return 0, f.fail
	}
	f.deleted = append(f.deleted, prefix)
	n := 0
	for k := range f.objects {
		if strings.HasPrefix(k, prefix) {
			delete(f.objects, k)
			n++
		}
	}
	after := f.afterDelete
	f.afterDelete = nil
	f.mu.Unlock()
	if after != nil {
		after()
	}
	return n, nil
}

type diagnosticsWorld struct {
	uninstallWorld
	diagnostics *app.Diagnostics // api
	worker      *app.Diagnostics // worker
	commands    *app.DeviceCommands
	retention   *app.Retention
	bundles     *fakeBundles
}

func newDiagnosticsWorld(t *testing.T) diagnosticsWorld {
	t.Helper()
	w := diagnosticsWorld{uninstallWorld: newUninstallWorld(t), bundles: &fakeBundles{objects: map[string][]byte{}}}
	env := pgtest.SharedPaddock(t)
	worker, err := db.NewOrgPool(context.Background(), env.Worker, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(worker.Close)
	platform, err := db.NewPlatformPool(context.Background(), env.Platform, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(platform.Close)
	runner := app.NewActionRunner(worker, platform, httpx.RequestID)
	w.diagnostics = app.NewDiagnostics(w.runner, w.api, nil, time.Second)
	w.worker = app.NewDiagnostics(runner, worker, w.bundles, time.Second)
	w.commands = app.NewDeviceCommands(runner, worker)
	w.retention = app.NewRetention(runner, worker, platform, &fakeInventoryAdmin{}, time.Second, 400).WithDiagnosticsObjects(w.bundles)
	// The database is shared: a stored bundle left behind would fail other packages' retention rounds, which run
	// without an escrow bucket.
	t.Cleanup(func() {
		_, _ = w.super.Exec(context.Background(), "DELETE FROM device_diagnostics WHERE organization_id = $1", w.org)
	})
	return w
}

func (w diagnosticsWorld) operator() context.Context {
	return w.as(w.org, principal.RoleOrgOperator, false)
}

// state is the state and failed_reason of a bundle.
func (w diagnosticsWorld) state(t *testing.T, id uuid.UUID) (state, reason string) {
	t.Helper()
	var r *string
	if err := w.super.QueryRow(context.Background(), "SELECT state, failed_reason FROM device_diagnostics WHERE id = $1", id).
		Scan(&state, &r); err != nil {
		t.Fatal(err)
	}
	if r != nil {
		reason = *r
	}
	return state, reason
}

// announce records the device's announcement of plain as the sealed object and uploads it to the fake bucket.
func (w diagnosticsWorld) announce(t *testing.T, id uuid.UUID, plain []byte) string {
	t.Helper()
	sum := sha256.Sum256(plain)
	key := escrow.DiagnosticsObjectKey(w.org.String(), w.device.String(), id.String())
	counted, err := w.worker.Announce(systemCtx(w.org), ingest.DiagnosticsAnnounced{DiagnosticsID: id, DeviceID: w.device,
		OrganizationID: w.org, ObjectKey: key, SHA256: hex.EncodeToString(sum[:]), Size: int64(len(plain)),
		Nonce: make([]byte, 12), WrappedDEK: []byte{1, 2, 3}, ReceivedAt: time.Now()})
	if err != nil || !counted {
		t.Fatalf("announce: %v %v", counted, err)
	}
	w.bundles.mu.Lock()
	w.bundles.objects[key] = plain
	w.bundles.mu.Unlock()
	return key
}

func (w diagnosticsWorld) result(t *testing.T, id uuid.UUID, status, result string) {
	t.Helper()
	if err := w.commands.Finish(systemCtx(w.org), ingest.CommandResult{DeviceID: w.device, OrganizationID: w.org, CommandID: id,
		Status: status, Result: json.RawMessage(result), ReceivedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
}

// backdate moves the upload report of a bundle into the past, past the verification delay.
func (w diagnosticsWorld) backdate(t *testing.T, id uuid.UUID, ago time.Duration) {
	t.Helper()
	w.exec(t, "UPDATE device_diagnostics SET uploaded_at = now() - $2::interval WHERE id = $1", id, ago.String())
}

const uploaded = `{"uploaded": true, "files": 41, "bytes": 1834221, "truncated_entries": ["journal:himmelblaud"], "notified_sessions": 1}`

// TestDiagnosticsRequest (plan M12 decision 4): an operator asks an active device for a bundle with a reason; the
// bundle's ID is the collect_status command's, which carries request_id and reason; the request is audited with
// request_id, reason, command_id and hostname. An auditor is denied, a second request while one is pending, a retired
// device and a reason outside 2–500 characters are refused, a device of another organization is not found.
func TestDiagnosticsRequest(t *testing.T) {
	w := newDiagnosticsWorld(t)
	ctx := context.Background()

	if _, err := w.diagnostics.Request(w.as(w.org, principal.RoleOrgAuditor, true), w.device, "slow logins"); !errors.Is(err, problem.Forbidden) {
		t.Fatalf("auditor: %v", err)
	}
	if _, outcome := w.event(t, "device.diagnostics_requested"); outcome != "denied" {
		t.Fatalf("auditor's attempt recorded as %s", outcome)
	}
	if n := w.count(t, "SELECT count(*) FROM device_diagnostics WHERE device_id = $1", w.device); n != 0 {
		t.Fatalf("the auditor's request left %d bundles", n)
	}
	for _, reason := range []string{"x", strings.Repeat("r", 501)} {
		if _, err := w.diagnostics.Request(w.operator(), w.device, reason); !errors.Is(err, problem.InvalidRequestUnprocessed) {
			t.Fatalf("reason of %d characters: %v", len(reason), err)
		}
	}

	row, err := w.diagnostics.Request(w.operator(), w.device, "slow logins")
	if err != nil {
		t.Fatal(err)
	}
	if row.State != app.DiagnosticsRequested || row.Reason != "slow logins" || row.RequestedBy != "alice" || row.DeviceID != w.device {
		t.Fatalf("row %+v", row)
	}
	var typ string
	var params []byte
	if err := w.super.QueryRow(ctx, "SELECT type, params FROM device_command WHERE id = $1", row.ID).Scan(&typ, &params); err != nil {
		t.Fatalf("command with the bundle's ID: %v", err)
	}
	var p command.CollectStatusParams
	if err := json.Unmarshal(params, &p); err != nil || typ != command.TypeCollectStatus || p.RequestID != row.ID.String() || p.Reason != "slow logins" {
		t.Fatalf("command %s %s", typ, params)
	}
	ev, outcome := w.event(t, "device.diagnostics_requested")
	if outcome != "success" || ev["request_id"] != row.ID.String() || ev["command_id"] != row.ID.String() ||
		ev["reason"] != "slow logins" || ev["hostname"] != w.hostname {
		t.Fatalf("event %s %v", outcome, ev)
	}

	if _, err := w.diagnostics.Request(w.as(w.org, principal.RoleOrgAdmin, false), w.device, "again"); !errors.Is(err, problem.InvalidState) {
		t.Fatalf("second request while one is pending: %v", err)
	}

	retired, _ := w.newDevice(t, w.org, "retired")
	if _, err := w.diagnostics.Request(w.operator(), retired, "slow logins"); !errors.Is(err, problem.InvalidState) {
		t.Fatalf("retired device: %v", err)
	}

	otherOrg := newHarness(t).org
	foreign, _ := w.newDevice(t, otherOrg, "active")
	if _, err := w.diagnostics.Request(w.operator(), foreign, "slow logins"); !errors.Is(err, problem.NotFound) {
		t.Fatalf("another organization's device: %v", err)
	}
	if n := w.count(t, "SELECT count(*) FROM device_diagnostics WHERE device_id = $1", foreign); n != 0 {
		t.Fatalf("a bundle was requested for another organization's device")
	}

	// A bundle that ended no longer blocks the next request.
	w.result(t, row.ID, "failed", `{"uploaded": false, "reason": "collect_failed"}`)
	if _, err := w.diagnostics.Request(w.operator(), w.device, "second try"); err != nil {
		t.Fatalf("request after a failed collection: %v", err)
	}
}

// TestDiagnosticsLifecycle (plan M12 decisions 5 and 6): the announcement records the object once, the result moves
// the bundle to uploaded, and the worker's round marks it stored once size and SHA-256 match, with expires_at seven
// retention days later and device.diagnostics_collected recorded exactly once with the hash and without content.
func TestDiagnosticsLifecycle(t *testing.T) {
	w := newDiagnosticsWorld(t)
	ctx := context.Background()
	row, err := w.diagnostics.Request(w.operator(), w.device, "slow logins")
	if err != nil {
		t.Fatal(err)
	}
	plain := []byte("sealed diagnostics bundle")
	w.announce(t, row.ID, plain)
	if counted, err := w.worker.Announce(systemCtx(w.org), ingest.DiagnosticsAnnounced{DiagnosticsID: row.ID, DeviceID: w.device,
		OrganizationID: w.org, ObjectKey: "other", SHA256: strings.Repeat("0", 64), Size: 1}); err != nil || counted {
		t.Fatalf("a second announcement counted: %v %v", counted, err)
	}
	if counted, err := w.worker.Announce(systemCtx(w.org), ingest.DiagnosticsAnnounced{DiagnosticsID: row.ID,
		DeviceID: uuid.Must(uuid.NewV7()), OrganizationID: w.org, ObjectKey: "other", SHA256: strings.Repeat("0", 64), Size: 1}); err != nil || counted {
		t.Fatalf("another device's announcement counted: %v %v", counted, err)
	}

	w.result(t, row.ID, "succeeded", uploaded)
	if state, _ := w.state(t, row.ID); state != app.DiagnosticsUploaded {
		t.Fatalf("after the result: %s", state)
	}
	if err := w.worker.Verify(systemCtx(w.org)); err != nil {
		t.Fatal(err)
	}
	if state, _ := w.state(t, row.ID); state != app.DiagnosticsUploaded {
		t.Fatalf("verified within the delay: %s", state)
	}
	w.backdate(t, row.ID, time.Minute)
	for range 2 {
		if err := w.worker.Verify(systemCtx(w.org)); err != nil {
			t.Fatal(err)
		}
	}
	var state, sum string
	var files, sessions int
	var truncated []string
	var stored, expires time.Time
	if err := w.super.QueryRow(ctx, `SELECT state, sha256, files, notified_sessions, truncated_entries, stored_at, expires_at
		FROM device_diagnostics WHERE id = $1`, row.ID).Scan(&state, &sum, &files, &sessions, &truncated, &stored, &expires); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(plain)
	if state != app.DiagnosticsStored || sum != hex.EncodeToString(digest[:]) || files != 41 || sessions != 1 ||
		len(truncated) != 1 || truncated[0] != "journal:himmelblaud" || !expires.Equal(stored.Add(app.DiagnosticsRetentionDays*time.Second)) {
		t.Fatalf("stored row %s %s %d %d %v %v %v", state, sum, files, sessions, truncated, stored, expires)
	}
	if n := w.count(t, "SELECT count(*) FROM outbox WHERE organization_id = $1 AND payload->>'code' = 'device.diagnostics_collected'", w.org); n != 1 {
		t.Fatalf("%d collected events, want 1", n)
	}
	ev, outcome := w.event(t, "device.diagnostics_collected")
	if outcome != "success" || ev["request_id"] != row.ID.String() || ev["sha256"] != sum || ev["bytes"] != float64(len(plain)) ||
		ev["files"] != float64(41) || ev["notified_sessions"] != float64(1) {
		t.Fatalf("event %s %v", outcome, ev)
	}
	var actor string
	if err := w.super.QueryRow(ctx, `SELECT payload->'actor'->>'type' FROM outbox WHERE organization_id = $1
		AND payload->>'code' = 'device.diagnostics_collected'`, w.org).Scan(&actor); err != nil || actor != "device" {
		t.Fatalf("actor %q %v", actor, err)
	}
	// A repeated result changes nothing.
	w.result(t, row.ID, "succeeded", uploaded)
	if state, _ := w.state(t, row.ID); state != app.DiagnosticsStored {
		t.Fatalf("after a repeated result: %s", state)
	}
}

// TestDiagnosticsVerifyFailures (plan M12 decision 5): a bundle whose object has another size or hash fails with
// size_mismatch or sha256_mismatch, one whose object did not arrive within the upload window fails with missing, one
// still within the window waits; each failure records device.diagnostics_collected as failure once.
func TestDiagnosticsVerifyFailures(t *testing.T) {
	for _, tc := range []struct {
		name    string
		tamper  func(w diagnosticsWorld, key string)
		ago     time.Duration
		want    string
		pending bool
	}{
		{name: "size", tamper: func(w diagnosticsWorld, key string) { w.bundles.objects[key] = []byte("short") }, ago: time.Minute,
			want: app.DiagnosticsSizeMismatch},
		{name: "hash", tamper: func(w diagnosticsWorld, key string) { w.bundles.objects[key] = []byte("SEALED diagnostics bundle") },
			ago: time.Minute, want: app.DiagnosticsSHA256Mismatch},
		{name: "missing", tamper: func(w diagnosticsWorld, key string) { delete(w.bundles.objects, key) }, ago: 20 * time.Minute,
			want: app.DiagnosticsMissing},
		{name: "not yet", tamper: func(w diagnosticsWorld, key string) { delete(w.bundles.objects, key) }, ago: time.Minute,
			want: app.DiagnosticsUploaded, pending: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := newDiagnosticsWorld(t)
			row, err := w.diagnostics.Request(w.operator(), w.device, "slow logins")
			if err != nil {
				t.Fatal(err)
			}
			key := w.announce(t, row.ID, []byte("sealed diagnostics bundle"))
			tc.tamper(w, key)
			w.result(t, row.ID, "succeeded", uploaded)
			w.backdate(t, row.ID, tc.ago)
			for range 2 {
				if err := w.worker.Verify(systemCtx(w.org)); err != nil {
					t.Fatal(err)
				}
			}
			state, reason := w.state(t, row.ID)
			if tc.pending {
				if state != tc.want {
					t.Fatalf("state %s, want %s", state, tc.want)
				}
				return
			}
			if state != app.DiagnosticsFailed || reason != tc.want {
				t.Fatalf("state %s %s, want failed %s", state, reason, tc.want)
			}
			if n := w.count(t, "SELECT count(*) FROM outbox WHERE organization_id = $1 AND payload->>'code' = 'device.diagnostics_collected'", w.org); n != 1 {
				t.Fatalf("%d collected events, want 1", n)
			}
			if ev, outcome := w.event(t, "device.diagnostics_collected"); outcome != "failure" || ev["reason"] != tc.want {
				t.Fatalf("event %s %v", outcome, ev)
			}
		})
	}
}

// TestDiagnosticsVerifyWithoutAnnouncement: a bundle reported uploaded whose announcement never arrived fails as
// missing after the upload window.
func TestDiagnosticsVerifyWithoutAnnouncement(t *testing.T) {
	w := newDiagnosticsWorld(t)
	row, err := w.diagnostics.Request(w.operator(), w.device, "slow logins")
	if err != nil {
		t.Fatal(err)
	}
	w.result(t, row.ID, "succeeded", uploaded)
	w.backdate(t, row.ID, 20*time.Minute)
	if err := w.worker.Verify(systemCtx(w.org)); err != nil {
		t.Fatal(err)
	}
	if state, reason := w.state(t, row.ID); state != app.DiagnosticsFailed || reason != app.DiagnosticsMissing {
		t.Fatalf("state %s %s", state, reason)
	}
}

// TestDiagnosticsRefusedResult (plan M12 decision 5): a result without an upload fails the bundle with the device's
// reason, an unknown reason as unknown, and records device.diagnostics_collected as failure once.
func TestDiagnosticsRefusedResult(t *testing.T) {
	w := newDiagnosticsWorld(t)
	row, err := w.diagnostics.Request(w.operator(), w.device, "slow logins")
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		w.result(t, row.ID, "failed", `{"uploaded": false, "notified_sessions": 0, "reason": "upload_failed"}`)
	}
	if state, reason := w.state(t, row.ID); state != app.DiagnosticsFailed || reason != command.CollectStatusUploadFailed {
		t.Fatalf("state %s %s", state, reason)
	}
	if n := w.count(t, "SELECT count(*) FROM outbox WHERE organization_id = $1 AND payload->>'code' = 'device.diagnostics_collected'", w.org); n != 1 {
		t.Fatalf("%d collected events, want 1", n)
	}
	if ev, outcome := w.event(t, "device.diagnostics_collected"); outcome != "failure" || ev["reason"] != "upload_failed" {
		t.Fatalf("event %s %v", outcome, ev)
	}

	second, err := w.diagnostics.Request(w.operator(), w.device, "slow logins")
	if err != nil {
		t.Fatal(err)
	}
	w.result(t, second.ID, "failed", `{"uploaded": false, "reason": "rm -rf /"}`)
	if state, reason := w.state(t, second.ID); state != app.DiagnosticsFailed || reason != "unknown" {
		t.Fatalf("state %s %s", state, reason)
	}
}

// TestDiagnosticsCommandExpiry: a bundle whose collect_status command expired unanswered expires with it.
func TestDiagnosticsCommandExpiry(t *testing.T) {
	w := newDiagnosticsWorld(t)
	row, err := w.diagnostics.Request(w.operator(), w.device, "slow logins")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.commands.Expire(systemCtx(w.org), time.Now().Add(2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if state, _ := w.state(t, row.ID); state != app.DiagnosticsExpired {
		t.Fatalf("state %s", state)
	}
}

// TestRetentionPurgeDiagnostics (ADR 0048 decision 5, plan M12 decision 7): a stored bundle past expires_at is
// expired by the retention round, its object deleted and its object key, nonce and wrapped key cleared, recorded as
// one retention.purged (store device_diagnostics); a bundle within its retention stays; a second round records nothing.
func TestRetentionPurgeDiagnostics(t *testing.T) {
	w := newDiagnosticsWorld(t)
	ctx := context.Background()
	stored := func(expires time.Time) (uuid.UUID, string) {
		t.Helper()
		id := uuid.Must(uuid.NewV7())
		key := escrow.DiagnosticsObjectKey(w.org.String(), w.device.String(), id.String())
		w.exec(t, `INSERT INTO device_diagnostics (id, organization_id, device_id, requested_by, reason, state, object_key, size,
			sha256, nonce, wrapped_dek, stored_at, expires_at) VALUES ($1, $2, $3, 'alice', 'slow logins', 'stored', $4, 5,
			$5, '\x00', '\x01', $6::timestamptz - interval '7 seconds', $6)`, id, w.org, w.device, key, strings.Repeat("a", 64), expires)
		w.bundles.objects[key] = []byte("bundle")
		return id, key
	}
	now := time.Now()
	old, oldKey := stored(now.Add(-time.Minute))
	young, youngKey := stored(now.Add(time.Hour))

	if _, err := w.retention.PurgeDiagnostics(systemCtx(w.org), now); err != nil {
		t.Fatal(err)
	}
	var state string
	var key *string
	var nonce, dek []byte
	if err := w.super.QueryRow(ctx, "SELECT state, object_key, nonce, wrapped_dek FROM device_diagnostics WHERE id = $1", old).
		Scan(&state, &key, &nonce, &dek); err != nil {
		t.Fatal(err)
	}
	if state != app.DiagnosticsExpired || key != nil || nonce != nil || dek != nil {
		t.Fatalf("expired bundle %s %v %v %v", state, key, nonce, dek)
	}
	if _, ok := w.bundles.objects[oldKey]; ok || len(w.bundles.deleted) != 1 || w.bundles.deleted[0] != oldKey {
		t.Fatalf("deleted %v", w.bundles.deleted)
	}
	if s, _ := w.state(t, young); s != app.DiagnosticsStored {
		t.Fatalf("young bundle %s", s)
	}
	if _, ok := w.bundles.objects[youngKey]; !ok {
		t.Fatal("young bundle's object deleted")
	}
	var params map[string]any
	var raw []byte
	var outcome string
	if err := w.super.QueryRow(ctx, `SELECT payload->'params', payload->>'outcome' FROM outbox WHERE organization_id = $1
		AND payload->>'code' = 'retention.purged'`, w.org).Scan(&raw, &outcome); err != nil {
		t.Fatal(err)
	}
	_ = json.Unmarshal(raw, &params)
	if outcome != "success" || params["store"] != app.StoreDeviceDiagnostics || params["deleted"] != float64(1) {
		t.Fatalf("retention.purged %s %v", outcome, params)
	}
	if n, err := w.retention.PurgeDiagnostics(systemCtx(w.org), now); err != nil || n != 0 {
		t.Fatalf("second round: %d %v", n, err)
	}
	if n := w.count(t, "SELECT count(*) FROM outbox WHERE organization_id = $1 AND payload->>'code' = 'retention.purged'", w.org); n != 1 {
		t.Fatalf("%d retention.purged events, want 1", n)
	}

	// An object that cannot be deleted keeps its bundle stored for the next round, and the pass fails.
	w.bundles.fail = errors.New("object store down")
	if _, err := w.retention.PurgeDiagnostics(systemCtx(w.org), now.Add(2*time.Hour)); err == nil {
		t.Fatal("a failed deletion passed")
	}
	if s, _ := w.state(t, young); s != app.DiagnosticsStored {
		t.Fatalf("bundle whose object deletion failed: %s", s)
	}
}

// TestRetentionPurgeDiagnosticsWithoutBucket: a worker without the escrow bucket fails the pass instead of expiring
// a bundle whose object it cannot delete.
func TestRetentionPurgeDiagnosticsWithoutBucket(t *testing.T) {
	w := newDiagnosticsWorld(t)
	env := pgtest.SharedPaddock(t)
	worker, err := db.NewOrgPool(context.Background(), env.Worker, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(worker.Close)
	retention := app.NewRetention(app.NewActionRunner(worker, nil, httpx.RequestID), worker, nil, &fakeInventoryAdmin{}, time.Second, 400)
	id := uuid.Must(uuid.NewV7())
	w.exec(t, `INSERT INTO device_diagnostics (id, organization_id, device_id, requested_by, reason, state, object_key,
		stored_at, expires_at) VALUES ($1, $2, $3, 'alice', 'slow logins', 'stored', 'k', now() - interval '1 hour', now() - interval '1 minute')`,
		id, w.org, w.device)
	if _, err := retention.PurgeDiagnostics(systemCtx(w.org), time.Now()); err == nil {
		t.Fatal("expired without a bucket")
	}
	if s, _ := w.state(t, id); s != app.DiagnosticsStored {
		t.Fatalf("state %s", s)
	}
}

// keyMaterial reports whether a bundle still holds an object key, nonce or wrapped key, and its expires_at.
func (w diagnosticsWorld) keyMaterial(t *testing.T, id uuid.UUID) (held bool, expires *time.Time) {
	t.Helper()
	if err := w.super.QueryRow(context.Background(), `SELECT object_key IS NOT NULL OR nonce IS NOT NULL OR wrapped_dek IS NOT NULL,
		expires_at FROM device_diagnostics WHERE id = $1`, id).Scan(&held, &expires); err != nil {
		t.Fatal(err)
	}
	return held, expires
}

// put uploads data as the object of a bundle to the fake bucket, as a presigned PUT does.
func (w diagnosticsWorld) put(id uuid.UUID, data []byte) string {
	key := escrow.DiagnosticsObjectKey(w.org.String(), w.device.String(), id.String())
	w.bundles.mu.Lock()
	defer w.bundles.mu.Unlock()
	w.bundles.objects[key] = data
	return key
}

// TestRetentionPurgeEndedDiagnostics (ADR 0048 decision 5, review PDK-747 findings 1 and 2): a bundle that ends
// without being stored loses its key material at once, and the retention round deletes its object by the derived key
// once the upload window ended — a mismatching upload, an upload followed by a failed result, an upload whose command
// expired before the result, and an announcement that arrives after the bundle ended and was cleaned.
func TestRetentionPurgeEndedDiagnostics(t *testing.T) {
	plain := []byte("sealed diagnostics bundle")
	for _, tc := range []struct {
		name string
		// end ends the bundle and returns its object key and the time it ended.
		end func(t *testing.T, w diagnosticsWorld, id uuid.UUID) (string, time.Time)
	}{
		{name: "sha256 mismatch", end: func(t *testing.T, w diagnosticsWorld, id uuid.UUID) (string, time.Time) {
			key := w.announce(t, id, plain)
			w.put(id, []byte("SEALED diagnostics bundle"))
			w.result(t, id, "succeeded", uploaded)
			w.backdate(t, id, time.Minute)
			if err := w.worker.Verify(systemCtx(w.org)); err != nil {
				t.Fatal(err)
			}
			if state, reason := w.state(t, id); state != app.DiagnosticsFailed || reason != app.DiagnosticsSHA256Mismatch {
				t.Fatalf("state %s %s", state, reason)
			}
			return key, time.Now()
		}},
		{name: "upload then failed result", end: func(t *testing.T, w diagnosticsWorld, id uuid.UUID) (string, time.Time) {
			key := w.announce(t, id, plain)
			w.result(t, id, "failed", `{"uploaded": false, "reason": "upload_failed"}`)
			if state, _ := w.state(t, id); state != app.DiagnosticsFailed {
				t.Fatalf("state %s", state)
			}
			return key, time.Now()
		}},
		{name: "upload then command expired", end: func(t *testing.T, w diagnosticsWorld, id uuid.UUID) (string, time.Time) {
			key := w.announce(t, id, plain)
			at := time.Now().Add(2 * time.Hour)
			if _, err := w.commands.Expire(systemCtx(w.org), at); err != nil {
				t.Fatal(err)
			}
			if state, _ := w.state(t, id); state != app.DiagnosticsExpired {
				t.Fatalf("state %s", state)
			}
			return key, at
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := newDiagnosticsWorld(t)
			row, err := w.diagnostics.Request(w.operator(), w.device, "slow logins")
			if err != nil {
				t.Fatal(err)
			}
			key, at := tc.end(t, w, row.ID)
			held, expires := w.keyMaterial(t, row.ID)
			if held || expires == nil {
				t.Fatalf("ended bundle: key material %v, expires_at %v", held, expires)
			}
			if _, err := w.retention.PurgeDiagnostics(systemCtx(w.org), at); err != nil {
				t.Fatal(err)
			}
			if _, ok := w.bundles.objects[key]; !ok {
				t.Fatal("object deleted within the upload window")
			}
			if n, err := w.retention.PurgeDiagnostics(systemCtx(w.org), at.Add(app.DiagnosticsUploadWindow+time.Minute)); err != nil || n != 1 {
				t.Fatalf("purge: %d %v", n, err)
			}
			if _, ok := w.bundles.objects[key]; ok {
				t.Fatal("object of the ended bundle kept")
			}
			if _, expires := w.keyMaterial(t, row.ID); expires != nil {
				t.Fatalf("expires_at %v after the deletion", expires)
			}
			if n, err := w.retention.PurgeDiagnostics(systemCtx(w.org), at.Add(app.DiagnosticsUploadWindow+time.Minute)); err != nil || n != 0 {
				t.Fatalf("second round: %d %v", n, err)
			}
		})
	}

	t.Run("announcement after the end", func(t *testing.T) {
		w := newDiagnosticsWorld(t)
		row, err := w.diagnostics.Request(w.operator(), w.device, "slow logins")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.commands.Expire(systemCtx(w.org), time.Now().Add(time.Hour+time.Minute)); err != nil {
			t.Fatal(err)
		}
		later := time.Now().Add(time.Hour + app.DiagnosticsUploadWindow + 2*time.Minute)
		if _, err := w.retention.PurgeDiagnostics(systemCtx(w.org), later); err != nil {
			t.Fatal(err)
		}
		if _, expires := w.keyMaterial(t, row.ID); expires != nil {
			t.Fatalf("expires_at %v after the first deletion", expires)
		}
		sum := sha256.Sum256(plain)
		key := escrow.DiagnosticsObjectKey(w.org.String(), w.device.String(), row.ID.String())
		counted, err := w.worker.Announce(systemCtx(w.org), ingest.DiagnosticsAnnounced{DiagnosticsID: row.ID, DeviceID: w.device,
			OrganizationID: w.org, ObjectKey: key, SHA256: hex.EncodeToString(sum[:]), Size: int64(len(plain)),
			Nonce: make([]byte, 12), WrappedDEK: []byte{1, 2, 3}, ReceivedAt: time.Now()})
		if err != nil || counted {
			t.Fatalf("late announcement: %v %v", counted, err)
		}
		if held, expires := w.keyMaterial(t, row.ID); held || expires == nil {
			t.Fatalf("late announcement: key material %v, expires_at %v", held, expires)
		}
		w.put(row.ID, plain)
		if _, err := w.retention.PurgeDiagnostics(systemCtx(w.org), later); err != nil {
			t.Fatal(err)
		}
		if _, ok := w.bundles.objects[key]; ok {
			t.Fatal("object of a late announcement kept")
		}
	})
}

// TestDiagnosticsFailedResultWindowFromProcessing (review 2 PDK-747 finding A): a failed result processed long after
// the gateway received it, after an announcement whose presigned PUT is still valid, keeps the object due from the
// processing time on, not from the receipt, so the retention round cannot delete before the PUT lands.
func TestDiagnosticsFailedResultWindowFromProcessing(t *testing.T) {
	w := newDiagnosticsWorld(t)
	row, err := w.diagnostics.Request(w.operator(), w.device, "slow logins")
	if err != nil {
		t.Fatal(err)
	}
	key := w.announce(t, row.ID, []byte("sealed diagnostics bundle"))
	received := time.Now().Add(-20 * time.Minute)
	processed := time.Now()
	if err := w.commands.Finish(systemCtx(w.org), ingest.CommandResult{DeviceID: w.device, OrganizationID: w.org,
		CommandID: row.ID, Status: "failed", Result: json.RawMessage(`{"uploaded": false, "reason": "upload_failed"}`),
		ReceivedAt: received}); err != nil {
		t.Fatal(err)
	}
	if state, _ := w.state(t, row.ID); state != app.DiagnosticsFailed {
		t.Fatalf("state %s", state)
	}
	if _, expires := w.keyMaterial(t, row.ID); expires == nil || expires.Before(processed.Add(app.DiagnosticsUploadWindow)) {
		t.Fatalf("expires_at %v before processing + upload window %v", expires, processed.Add(app.DiagnosticsUploadWindow))
	}
	if _, err := w.retention.PurgeDiagnostics(systemCtx(w.org), received.Add(app.DiagnosticsUploadWindow+time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, ok := w.bundles.objects[key]; !ok {
		t.Fatal("object deleted within the window of the presigned PUT")
	}
}

// TestRetentionPurgeKeepsRearmedDiagnostics (review 2 PDK-747 finding B): an announcement that re-arms an ended bundle
// while the retention round deletes its object keeps the bundle due, so the next round deletes the object its PUT left.
func TestRetentionPurgeKeepsRearmedDiagnostics(t *testing.T) {
	plain := []byte("sealed diagnostics bundle")
	w := newDiagnosticsWorld(t)
	row, err := w.diagnostics.Request(w.operator(), w.device, "slow logins")
	if err != nil {
		t.Fatal(err)
	}
	w.result(t, row.ID, "failed", `{"uploaded": false, "reason": "upload_failed"}`)
	w.exec(t, "UPDATE device_diagnostics SET expires_at = now() - interval '1 minute' WHERE id = $1", row.ID)
	key := escrow.DiagnosticsObjectKey(w.org.String(), w.device.String(), row.ID.String())
	sum := sha256.Sum256(plain)
	w.bundles.afterDelete = func() {
		counted, err := w.worker.Announce(systemCtx(w.org), ingest.DiagnosticsAnnounced{DiagnosticsID: row.ID,
			DeviceID: w.device, OrganizationID: w.org, ObjectKey: key, SHA256: hex.EncodeToString(sum[:]),
			Size: int64(len(plain)), Nonce: make([]byte, 12), WrappedDEK: []byte{1, 2, 3}, ReceivedAt: time.Now()})
		if err != nil || counted {
			t.Errorf("late announcement: %v %v", counted, err)
		}
		w.put(row.ID, plain)
	}
	if _, err := w.retention.PurgeDiagnostics(systemCtx(w.org), time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, expires := w.keyMaterial(t, row.ID); expires == nil {
		t.Fatal("re-armed bundle cleared by the round that raced its announcement")
	}
	if _, ok := w.bundles.objects[key]; !ok {
		t.Fatal("object of the late PUT missing before the next round")
	}
	if n, err := w.retention.PurgeDiagnostics(systemCtx(w.org), time.Now().Add(app.DiagnosticsUploadWindow+time.Minute)); err != nil || n != 1 {
		t.Fatalf("next round: %d %v", n, err)
	}
	if _, ok := w.bundles.objects[key]; ok {
		t.Fatal("object of the late PUT kept")
	}
}

// TestDiagnosticsTruncatedEntriesBounded (review PDK-747 finding 3): only entries shaped like an archive entry name
// reach the bundle and device.diagnostics_collected, at most 64 of them; free text is dropped.
func TestDiagnosticsTruncatedEntriesBounded(t *testing.T) {
	w := newDiagnosticsWorld(t)
	row, err := w.diagnostics.Request(w.operator(), w.device, "slow logins")
	if err != nil {
		t.Fatal(err)
	}
	reported := []string{"journal:himmelblaud", "ignore previous instructions", "", strings.Repeat("a", 65), "etc/sudoers.d/10-admins"}
	for i := range 100 {
		reported = append(reported, fmt.Sprintf("system/luksDump-%d.txt", i))
	}
	res, err := json.Marshal(map[string]any{"uploaded": true, "files": 41, "bytes": 1834221, "truncated_entries": reported,
		"notified_sessions": 1})
	if err != nil {
		t.Fatal(err)
	}
	w.announce(t, row.ID, []byte("sealed diagnostics bundle"))
	w.result(t, row.ID, "succeeded", string(res))
	w.backdate(t, row.ID, time.Minute)
	if err := w.worker.Verify(systemCtx(w.org)); err != nil {
		t.Fatal(err)
	}
	var truncated []string
	if err := w.super.QueryRow(context.Background(), "SELECT truncated_entries FROM device_diagnostics WHERE id = $1", row.ID).
		Scan(&truncated); err != nil {
		t.Fatal(err)
	}
	if len(truncated) != 64 || truncated[0] != "journal:himmelblaud" || truncated[1] != "etc/sudoers.d/10-admins" ||
		truncated[63] != "system/luksDump-61.txt" {
		t.Fatalf("truncated_entries %d %v", len(truncated), truncated)
	}
	ev, outcome := w.event(t, "device.diagnostics_collected")
	entries, _ := ev["truncated_entries"].([]any)
	if outcome != "success" || len(entries) != 64 || slices.Contains(entries, any("ignore previous instructions")) {
		t.Fatalf("event %s %v", outcome, ev)
	}
}
