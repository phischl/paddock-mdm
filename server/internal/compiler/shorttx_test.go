package compiler_test

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/phischl/paddock-mdm/server/internal/compiler"
	"github.com/phischl/paddock-mdm/server/internal/domain/statechange"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/pgtest"
)

// pauseOnce makes the first snapshot read of c wait until the returned release is called and closes read when it is
// reached; later reads pass.
func pauseOnce(c *compiler.Compiler) (read <-chan struct{}, release func()) {
	reached, resume := make(chan struct{}), make(chan struct{})
	var done atomic.Bool
	c.SetAfterRead(func() {
		if done.CompareAndSwap(false, true) {
			close(reached)
			<-resume
		}
	})
	return reached, func() { close(resume) }
}

func (w *world) bundleVersions(dev uuid.UUID) []int64 {
	w.t.Helper()
	rows, err := w.super.Query(context.Background(), "SELECT version FROM bundle WHERE device_id = $1 ORDER BY version", dev)
	if err != nil {
		w.t.Fatal(err)
	}
	versions, err := pgx.CollectRows(rows, pgx.RowTo[int64])
	if err != nil {
		w.t.Fatal(err)
	}
	return versions
}

// TestStaleConcurrentCommitIsRecompiled: compile B reads before a change, compile A after it, and B commits first. A's
// guarded write finds the device moved on and skips it; A then compiles the device again from a new snapshot, so the
// device ends with A's newer inputs instead of B's older bundle (plan M17 amendment r point 7: no lost update).
func TestStaleConcurrentCommitIsRecompiled(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	d := w.device("active", w.g1)
	w.mustCompile(statechange.ScopeDevice, d)
	compA := w.comp
	w.restart(func(*compiler.Config) {})
	compB := w.comp
	events := []statechange.Event{{OrganizationID: w.org, Scope: statechange.ScopeDevice, ID: d}}

	w.exec("INSERT INTO managed_unit (id, organization_id, unit, enabled, active) VALUES ($1, $2, 'chrony.service', true, true)",
		uuid.Must(uuid.NewV7()), w.org)
	bRead, bRelease := pauseOnce(compB)
	bDone := make(chan error, 1)
	go func() { bDone <- compB.Compile(ctx, events) }()
	<-bRead

	w.exec("INSERT INTO managed_file (id, organization_id, device_group_id, path, mode, content) VALUES ($1, $2, $3, '/etc/motd', '0644', 'hello')",
		uuid.Must(uuid.NewV7()), w.org, w.g1)
	aRead, aRelease := pauseOnce(compA)
	aDone := make(chan error, 1)
	go func() { aDone <- compA.Compile(ctx, events) }()
	<-aRead

	bRelease()
	if err := <-bDone; err != nil {
		aRelease()
		if err := <-aDone; err != nil {
			t.Logf("the newer compile, ended after the failure: %v", err)
		}
		t.Fatalf("the stale compile: %v", err)
	}
	if got := resourceIDs(w.fetch(d)); w.version(d) != 2 || got != "time,unit:chrony.service" {
		aRelease()
		if err := <-aDone; err != nil {
			t.Logf("the newer compile, ended after the failure: %v", err)
		}
		t.Fatalf("after the stale compile: v%d %s", w.version(d), got)
	}

	aRelease()
	if err := <-aDone; err != nil {
		t.Fatalf("the newer compile: %v", err)
	}
	b := w.fetch(d)
	if got := resourceIDs(b); got != "file:/etc/motd,time,unit:chrony.service" || b.BundleVersion != 3 {
		t.Fatalf("lost update: v%d %s, want v3 with the file and the unit", b.BundleVersion, got)
	}
	if got := w.bundleVersions(d); len(got) != 3 || got[0] != 1 || got[1] != 2 || got[2] != 3 {
		t.Fatalf("bundle versions %v, want [1 2 3]", got)
	}
}

// TestPersistentConflictFailsTheCompile: a device that moves on after every snapshot read is never written by this
// compile; after MaxConflictRounds reads the compile fails, so the consumer requeues its batch and the device is
// compiled later (plan M17 amendment r point 7).
func TestPersistentConflictFailsTheCompile(t *testing.T) {
	w := newWorld(t)
	d := w.device("active")
	w.mustCompile(statechange.ScopeDevice, d)
	w.exec("INSERT INTO managed_unit (id, organization_id, unit, enabled, active) VALUES ($1, $2, 'chrony.service', true, true)",
		uuid.Must(uuid.NewV7()), w.org)
	var reads atomic.Int32
	w.comp.SetAfterRead(func() {
		reads.Add(1)
		w.exec("UPDATE device SET bundle_seq = bundle_seq + 1 WHERE id = $1", d)
	})
	err := w.compile(statechange.ScopeDevice, d)
	if err == nil || !strings.Contains(err.Error(), "bundle_seq changed concurrently") {
		t.Fatalf("compile error %v, want the conflict", err)
	}
	if n := reads.Load(); n != compiler.MaxConflictRounds {
		t.Fatalf("%d snapshot reads, want %d", n, compiler.MaxConflictRounds)
	}
	if got := w.bundleVersions(d); len(got) != 1 {
		t.Fatalf("bundle versions %v: a conflicting write was applied", got)
	}

	w.comp.SetAfterRead(nil)
	w.mustCompile(statechange.ScopeDevice, d)
	if b := w.fetch(d); b.BundleVersion != 5 || resourceIDs(b) != "time,unit:chrony.service" {
		t.Fatalf("the later compile: v%d %s, want v5 with the unit", b.BundleVersion, resourceIDs(b))
	}
}

// TestGuardedPlatformWriteSkipsAMovedDevice: the platform inputs a compile saw are recorded only while the device's
// bundle_seq is still the one the compile left; a device moved on keeps what its newer writer records.
func TestGuardedPlatformWriteSkipsAMovedDevice(t *testing.T) {
	w := newWorld(t)
	d := w.device("active")
	w.exec("INSERT INTO device_status (device_id, organization_id, agent_version) VALUES ($1, $2, '1.0.0')", d, w.org)
	w.mustCompile(statechange.ScopeDevice, d)
	w.exec("UPDATE device_status SET agent_version = '2.0.0' WHERE device_id = $1", d)
	w.comp.SetAfterRead(func() { w.exec("UPDATE device SET bundle_seq = bundle_seq + 1 WHERE id = $1", d) })
	w.mustCompile(statechange.ScopeDevice, d)
	var got string
	if err := w.super.QueryRow(context.Background(), "SELECT compiled_agent_version FROM device WHERE id = $1", d).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != "1.0.0" {
		t.Fatalf("compiled_agent_version %q written over a moved bundle_seq, want 1.0.0", got)
	}
}

// TestWritesInBatchesRecordEveryDevice: the compile results are written in transactions of the batch size, and every
// device is recorded across the batch boundaries, the last partial batch included.
func TestWritesInBatchesRecordEveryDevice(t *testing.T) {
	w := newWorld(t)
	w.comp.SetWriteBatch(2)
	var devices []uuid.UUID
	for range 5 {
		d := w.device("active")
		w.exec("INSERT INTO device_status (device_id, organization_id, agent_version) VALUES ($1, $2, '1.0.0')", d, w.org)
		devices = append(devices, d)
	}
	w.mustCompile(statechange.ScopeOrg, w.org)
	for _, d := range devices {
		var agent string
		var checked *time.Time
		if err := w.super.QueryRow(context.Background(), "SELECT compiled_agent_version, denial_lock_checked_at FROM device WHERE id = $1",
			d).Scan(&agent, &checked); err != nil {
			t.Fatal(err)
		}
		if w.version(d) != 1 || agent != "1.0.0" || checked == nil {
			t.Fatalf("device %s: v%d, compiled agent %q, denial lock checked %v", d, w.version(d), agent, checked)
		}
	}
}

// TestSnapshotReadOf70000Devices: the snapshot read of a whole-organization compile of 70 000 active schema 2 devices,
// each in a group and with a bundle, stays within the 10 s target (plan M17 amendment r points 1 and 7). It runs on
// its own database, so the seeded organization never reaches the other tests' reconcile.
func TestSnapshotReadOf70000Devices(t *testing.T) {
	if testing.Short() {
		t.Skip("seeds 70 000 devices")
	}
	const devices = 70000
	ctx := context.Background()
	env := pgtest.StartPaddock(t)
	pool, err := db.NewOrgPool(ctx, env.Compiler, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	super, err := pgx.Connect(ctx, env.Super)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = super.Close(ctx) })
	org, group := uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())
	for _, stmt := range []struct {
		sql  string
		args []any
	}{
		{"INSERT INTO organization (id, slug, name, status) VALUES ($1, 'scale', 'Scale', 'active')", []any{org}},
		{"INSERT INTO device_group (id, organization_id, name) VALUES ($2, $1, 'all')", []any{org, group}},
		{"INSERT INTO device (id, organization_id, hostname, state, bundle_seq) SELECT gen_random_uuid(), $1, 'h' || i, 'active', 1 " +
			"FROM generate_series(1, $2::int) i", []any{org, devices}},
		{"INSERT INTO device_status (device_id, organization_id, schema_versions, agent_version) SELECT id, $1, '{1,2}', '1.0.0' " +
			"FROM device WHERE organization_id = $1", []any{org}},
		{"INSERT INTO device_group_member (organization_id, device_group_id, device_id) SELECT $1, $2, id FROM device " +
			"WHERE organization_id = $1", []any{org, group}},
		{"INSERT INTO bundle (device_id, version, organization_id, content_sha256, envelope_sha256, object_key) " +
			"SELECT id, 1, $1, sha256(id::text::bytea), sha256(id::text::bytea), 'k' FROM device WHERE organization_id = $1", []any{org}},
		{"ANALYZE", nil},
	} {
		if _, err := super.Exec(ctx, stmt.sql, stmt.args...); err != nil {
			t.Fatalf("%s: %v", stmt.sql, err)
		}
	}
	comp := compiler.New(pool, nil, nil, nil, compiler.Config{})
	start := time.Now()
	n, err := comp.ReadInputs(ctx, org, []statechange.Event{{OrganizationID: org, Scope: statechange.ScopeOrg, ID: org}})
	elapsed := time.Since(start)
	if err != nil {
		t.Fatal(err)
	}
	if n != devices {
		t.Fatalf("read %d devices, want %d", n, devices)
	}
	t.Logf("snapshot read of %d devices: %s", n, elapsed)
	if elapsed > 10*time.Second {
		t.Fatalf("snapshot read of %d devices took %s, over the 10 s target", n, elapsed)
	}
}

// TestStalledUploadRollsBackTheCommit: a bundle upload that stalls is given up after UploadTimeout, so the commit
// transaction, which holds the device's row lock, rolls back within the 10 s target instead of running on; bundle_seq
// is unchanged and the next compile reuses that version (plan M17 amendment r points 1 and 7).
func TestStalledUploadRollsBackTheCommit(t *testing.T) {
	w := newWorld(t)
	d := w.device("active")
	w.mustCompile(statechange.ScopeDevice, d)
	w.exec("INSERT INTO managed_unit (id, organization_id, unit, enabled, active) VALUES ($1, $2, 'chrony.service', true, true)",
		uuid.Must(uuid.NewV7()), w.org)
	w.store.stall.Store(true)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	start := time.Now()
	go func() {
		done <- w.comp.Compile(ctx, []statechange.Event{{OrganizationID: w.org, Scope: statechange.ScopeDevice, ID: d}})
	}()
	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("compile error %v, want the upload timeout", err)
		}
	case <-time.After(15 * time.Second):
		// Ending the compile releases its connection, so the pool's cleanup does not wait on it.
		cancel()
		if err := <-done; err != nil {
			t.Logf("the cancelled compile: %v", err)
		}
		t.Fatal("the stalled upload held the commit transaction beyond the upload timeout")
	}
	if elapsed := time.Since(start); elapsed > 10*time.Second {
		t.Fatalf("the commit with a stalled upload took %s, over the 10 s target", elapsed)
	}
	if v := w.version(d); v != 1 {
		t.Fatalf("bundle_seq %d after the rolled back commit, want 1", v)
	}
	if got := w.bundleVersions(d); len(got) != 1 {
		t.Fatalf("bundle versions %v after the rolled back commit", got)
	}

	w.store.stall.Store(false)
	w.mustCompile(statechange.ScopeDevice, d)
	if b := w.fetch(d); b.BundleVersion != 2 || resourceIDs(b) != "time,unit:chrony.service" {
		t.Fatalf("the next compile: v%d %s, want v2 with the unit", b.BundleVersion, resourceIDs(b))
	}
}

// TestWarningsWrittenInBatchesReachEveryDevice: the compile warnings are recorded in transactions of the batch size,
// and a device in the last, partial batch gets its warning too.
func TestWarningsWrittenInBatchesReachEveryDevice(t *testing.T) {
	w := newWorld(t)
	w.comp.SetWriteBatch(2)
	flathub := w.flathub(loadSoftwareKey(t, "ed25519.asc"))
	w.assign(w.flatpakEntry("GIMP", flathub, "org.gimp.GIMP"), nil, "required", "latest", nil)
	w.assign(w.entry("Flatpak", nil, [4]string{"ubuntu", "*", "*", "flatpak"}), nil, "forbid", "latest", nil)
	var devices []uuid.UUID
	for range 5 {
		d := w.v2Device("{1,2}", w.g1)
		w.ubuntu(d, "amd64")
		devices = append(devices, d)
	}
	w.mustCompile(statechange.ScopeOrg, w.org)
	for _, d := range devices {
		if got := w.warnings(d); len(got) != 1 || got[0].code != compiler.WarningFlatpakForbidden {
			t.Fatalf("device %s: warnings %+v, want flatpak_forbidden", d, got)
		}
	}
}
