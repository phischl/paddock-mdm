package worker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/phischl/paddock-mdm/pkg/command"
	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/devicecache"
	"github.com/phischl/paddock-mdm/server/internal/platform/httpx"
)

func reconcileWrites(kind string) float64 {
	return testutil.ToFloat64(metricReconcileWrites.WithLabelValues(kind))
}

// TestCacheSyncReconcileWritesOnlyChanges (plan M17 amendment s points 4.1 and 4.3, PDK-1088 AC4): a second reconcile
// of 5 000 unchanged live keys writes nothing, as paddock_device_cache_reconcile_writes_total{kind="device_key"} shows;
// a key whose device changed state is written again.
func TestCacheSyncReconcileWritesOnlyChanges(t *testing.T) {
	const devices = 5000
	f := newFixture(t)
	ctx := context.Background()
	t.Cleanup(func() {
		for _, table := range []string{"device_status", "device_identity_key", "device"} {
			if _, err := f.super.Exec(ctx, "DELETE FROM "+table+" WHERE organization_id = $1", f.org); err != nil {
				t.Errorf("remove the seeded %s rows: %v", table, err)
			}
		}
	})
	if _, err := f.super.Exec(ctx, `
		WITH d AS (
			INSERT INTO device (id, organization_id, hostname, state)
			SELECT gen_random_uuid(), $1, 'w-' || i, 'active' FROM generate_series(1, $2::int) i RETURNING id, hostname)
		INSERT INTO device_identity_key (key_id, organization_id, device_id, public_key, key_protection, status)
		SELECT 'k-' || hostname, $1, id, '\x01', 'file', 'active' FROM d`, f.org, devices); err != nil {
		t.Fatal(err)
	}
	s := NewCacheSync(f.pool, f.cache)
	before := reconcileWrites(reconcileWritesDeviceKey)
	if err := s.Reconcile(ctx, f.org); err != nil {
		t.Fatal(err)
	}
	first := reconcileWrites(reconcileWritesDeviceKey) - before
	if first != 2*devices { // seq: and dk: of every device
		t.Fatalf("first reconcile wrote %v keys, want %d", first, 2*devices)
	}
	if err := s.Reconcile(ctx, f.org); err != nil {
		t.Fatal(err)
	}
	if second := reconcileWrites(reconcileWritesDeviceKey) - before - first; second != 0 {
		t.Fatalf("second reconcile of unchanged keys wrote %v keys, want 0", second)
	}
	if _, err := f.super.Exec(ctx, "UPDATE device SET state = 'quarantined' WHERE organization_id = $1 AND hostname = 'w-7'", f.org); err != nil {
		t.Fatal(err)
	}
	mark := reconcileWrites(reconcileWritesDeviceKey)
	if err := s.Reconcile(ctx, f.org); err != nil {
		t.Fatal(err)
	}
	if n := reconcileWrites(reconcileWritesDeviceKey) - mark; n != 1 {
		t.Fatalf("reconcile after one state change wrote %v keys, want 1", n)
	}
	if k, ok, err := f.cache.DeviceKey(ctx, "k-w-7"); err != nil || !ok || k.Status != "quarantined" {
		t.Fatalf("changed key: %+v %v %v", k, ok, err)
	}
}

// deletingSyncer deletes one offboarded record while the restore syncs its page, as a removal report that arrives
// meanwhile does.
type deletingSyncer struct {
	inner  app.OffboardedDeviceSyncer
	delete func()
}

func (d *deletingSyncer) SyncOffboardedDevices(ctx context.Context, devices []devicecache.OffboardedDevice) (int, error) {
	n, err := d.inner.SyncOffboardedDevices(ctx, devices)
	if d.delete != nil {
		d.delete()
		d.delete = nil
	}
	return n, err
}

// TestOffboardedRestorePages (plan M17 amendment s point 4.2, PDK-1088 AC3): Restore reads 2 500 records in pages of
// 1 000 and writes nothing on its second run; the keys of a record deleted while its page was synced are deleted.
func TestOffboardedRestorePages(t *testing.T) {
	const records = 2500
	f := newFixture(t)
	platform := platformPool(t)
	runner := app.NewActionRunner(f.pool, platform, httpx.RequestID)
	ctx := context.Background()
	cmd := uuid.Must(uuid.NewV7())
	cmds, err := json.Marshal([]map[string]any{{"command_id": cmd,
		"envelope": offboardedEnvelope(t, cmd, uuid.New(), f.org, command.TypeUninstall, `{"mode":"leave"}`)}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.super.Exec(ctx, `INSERT INTO offboarded_device (device_id, organization_id, keys, command_envelopes)
		SELECT gen_random_uuid(), $1, jsonb_build_array(jsonb_build_object('key_id', 'r-' || i, 'public_key', 'AQ==')), $2::jsonb
		FROM generate_series(1, $3::int) i`, f.org, cmds, records); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = f.super.Exec(ctx, "DELETE FROM offboarded_device WHERE organization_id = $1", f.org) })
	var total int
	if err := f.super.QueryRow(ctx, "SELECT count(*) FROM offboarded_device").Scan(&total); err != nil {
		t.Fatal(err)
	}
	pages := total/1000 + 1 // the last page is shorter than 1 000 or empty
	// The first record of the first page goes while that page is synced; the second is kept.
	var gone uuid.UUID
	var goneKey, keptKey string
	if err := f.super.QueryRow(ctx, `SELECT (array_agg(device_id ORDER BY device_id))[1],
		(array_agg(keys -> 0 ->> 'key_id' ORDER BY device_id))[1], (array_agg(keys -> 0 ->> 'key_id' ORDER BY device_id))[2]
		FROM offboarded_device WHERE organization_id = $1`, f.org).Scan(&gone, &goneKey, &keptKey); err != nil {
		t.Fatal(err)
	}
	syncer := &deletingSyncer{inner: devicecache.NewSyncer(f.cache), delete: func() {
		if _, err := f.super.Exec(ctx, "DELETE FROM offboarded_device WHERE device_id = $1", gone); err != nil {
			t.Error(err)
		}
	}}
	o := app.NewOffboardedDevices(runner, platform, f.cache).WithCacheSync(syncer)
	first, err := o.Restore(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if first.Pages != pages || first.Devices != total-1 || first.Written < 3*records {
		t.Fatalf("first restore %+v, want %d pages, %d devices, at least %d keys written", first, pages, total-1, 3*records)
	}
	if _, ok, err := f.cache.DeviceKey(ctx, goneKey); ok || err != nil {
		t.Fatalf("dk: of the record deleted meanwhile: %v %v", ok, err)
	}
	if cmds, err := f.cache.Commands(ctx, gone, time.Now()); err != nil || len(cmds) != 0 {
		t.Fatalf("cmd: of the record deleted meanwhile: %v %v", cmds, err)
	}
	if k, ok, err := f.cache.DeviceKey(ctx, keptKey); err != nil || !ok || k.Status != devicecache.KeyOffboarded {
		t.Fatalf("dk: of a kept record: %+v %v %v", k, ok, err)
	}
	second, err := o.Restore(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if second.Pages != pages || second.Devices != total-1 || second.Written != 0 {
		t.Fatalf("second restore %+v, want %d pages, %d devices, 0 keys written", second, pages, total-1)
	}
}

// countingRestorer counts Restore calls and fails while err is set.
type countingRestorer struct {
	calls int
	err   error
}

func (c *countingRestorer) Restore(context.Context) (app.OffboardedRestore, error) {
	c.calls++
	return app.OffboardedRestore{}, c.err
}

// TestReconcileAllRestoresEveryInterval (plan M17 amendment s point 4.2, PDK-1088 AC3): ReconcileAll restores the
// offboarded devices at its first run and then at most once per OffboardedRestoreInterval; a failed restore is
// retried by the next reconcile.
func TestReconcileAllRestoresEveryInterval(t *testing.T) {
	f := newFixture(t)
	now := time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)
	restorer := &countingRestorer{}
	s := NewCacheSync(f.pool, f.cache).WithOffboardedDevices(restorer)
	s.now = func() time.Time { return now }
	ctx := context.Background()
	run := func(advance time.Duration, want int) {
		t.Helper()
		now = now.Add(advance)
		_ = s.ReconcileAll(ctx)
		if restorer.calls != want {
			t.Fatalf("after +%s: %d restores, want %d", advance, restorer.calls, want)
		}
	}
	run(0, 1)
	run(ReconcileInterval, 1)
	run(OffboardedRestoreInterval-2*ReconcileInterval, 1)
	run(ReconcileInterval, 2)
	restorer.err = errors.New("platform pool down")
	run(OffboardedRestoreInterval, 3)
	run(ReconcileInterval, 4)
	restorer.err = nil
	run(ReconcileInterval, 5)
	run(ReconcileInterval, 5)
}

// TestCacheSyncQuietForDeletingOrganizations (plan M17 amendment s point 6.2, PDK-1088 AC5): 100 change notifications
// of an organization that is deleting log one Info line and no WARN, and ReconcileAll skips the organization without a
// WARN.
func TestCacheSyncQuietForDeletingOrganizations(t *testing.T) {
	f := newFixture(t)
	dev := f.device(t, "active")
	f.markDeleted(t)
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(previous) })
	s := NewCacheSync(f.pool, f.cache)
	ctx := context.Background()
	for range 100 {
		s.applyChange(ctx, "device:"+f.org.String()+":"+dev.String())
	}
	out := logs.String()
	if n := strings.Count(out, "device cache changes of a deleting organization are skipped"); n != 1 {
		t.Fatalf("%d Info lines for 100 refused notifications, want 1:\n%s", n, out)
	}
	if strings.Contains(out, "level=WARN") {
		t.Fatalf("refused notifications logged a WARN:\n%s", out)
	}
	logs.Reset()
	_ = s.ReconcileAll(ctx)
	for _, line := range strings.Split(logs.String(), "\n") {
		if strings.Contains(line, "level=WARN") && strings.Contains(line, f.org.String()) {
			t.Fatalf("ReconcileAll logged a WARN for the deleting organization: %s", line)
		}
	}
}
