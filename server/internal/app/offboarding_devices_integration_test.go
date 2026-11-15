package app_test

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/phischl/paddock-mdm/pkg/command"
	"github.com/phischl/paddock-mdm/pkg/dsse"
	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/devicecache"
	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
	"github.com/phischl/paddock-mdm/server/internal/domain/offboarding"
	"github.com/phischl/paddock-mdm/server/internal/domain/organization"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/pgtest"
)

// offboardedRow is a record of offboarded_device.
type offboardedRow struct {
	command  uuid.UUID
	envelope []byte
	keys     []map[string]any
}

func (w *offboardWorld) offboardedRows(t *testing.T) map[uuid.UUID]offboardedRow {
	t.Helper()
	rows, err := w.super.Query(context.Background(),
		"SELECT device_id, command_id, command_envelope, keys FROM offboarded_device WHERE organization_id = $1", w.org)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	out := map[uuid.UUID]offboardedRow{}
	for rows.Next() {
		var id uuid.UUID
		var r offboardedRow
		var keys []byte
		if err := rows.Scan(&id, &r.command, &r.envelope, &keys); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(keys, &r.keys); err != nil {
			t.Fatal(err)
		}
		out[id] = r
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// uninstallCommand is the device's current uninstall command and its status.
func (w *offboardWorld) uninstallCommand(t *testing.T, device uuid.UUID) (uuid.UUID, string) {
	t.Helper()
	var id uuid.UUID
	var status string
	if err := w.super.QueryRow(context.Background(), `SELECT c.id, c.status FROM device d JOIN device_command c ON c.id = d.uninstall_command_id
		WHERE d.id = $1`, device).Scan(&id, &status); err != nil {
		t.Fatalf("uninstall command of %s: %v", device, err)
	}
	return id, status
}

func decodeCommand(t *testing.T, env []byte) command.Command {
	t.Helper()
	_, payload, err := dsse.Decode(env)
	if err != nil {
		t.Fatal(err)
	}
	var c command.Command
	if err := json.Unmarshal(payload, &c); err != nil {
		t.Fatal(err)
	}
	return c
}

// TestOffboardingHandsDevicesOver (plan M17 decision 15, amendment e point 10, PDK-1016): the step devices records
// every device that has not reported its removal and is neither retired nor rejected in offboarded_device. A device
// whose offboarding uninstall is pending or delivered keeps that command; a device enrolled during the grace period, one
// the request skipped for an open Lock, one whose command failed (conversion_pending), expired or lapsed while pending,
// a quarantined and a pending device each get a fresh leave, also with the Lock open. The cache receives each device's
// active keys and the signed uninstall; the completion event carries uninstalls_reissued. The deletion then finishes
// without any failure although no device reported (main's requirement: waiting devices never hold the deletion).
func TestOffboardingHandsDevicesOver(t *testing.T) {
	w := newOffboardWorld(t)
	job := w.job()
	ctx := context.Background()
	delivered, _ := w.newDevice(t, w.org, "active")
	locked, _ := w.newDevice(t, w.org, "active")
	failed, _ := w.newDevice(t, w.org, "active")
	expired, _ := w.newDevice(t, w.org, "active")
	lapsed, _ := w.newDevice(t, w.org, "active")
	quarantined, _ := w.newDevice(t, w.org, "quarantined")
	pending, _ := w.newDevice(t, w.org, "pending")
	retired, _ := w.newDevice(t, w.org, "retired")
	rejected, _ := w.newDevice(t, w.org, "rejected")
	reported, _ := w.newDevice(t, w.org, "active")
	w.exec(t, `INSERT INTO revocation_request (id, organization_id, device_id, action, status, requested_by)
		VALUES ($1, $2, $3, 'lock', 'issued', $4)`, uuid.Must(uuid.NewV7()), w.org, locked, uuid.Must(uuid.NewV7()))
	w.exec(t, `INSERT INTO device_identity_key (key_id, organization_id, device_id, public_key, key_protection, status)
		VALUES ('k-active-'||$3::text, $1, $2, '\x01', 'file', 'active'), ('k-revoked-'||$3::text, $1, $2, '\x02', 'file', 'revoked'),
		('k-quarantined-'||$3::text, $1, $4, '\x03', 'file', 'active')`, w.org, delivered, delivered.String(), quarantined)
	t.Cleanup(func() { w.exec(t, "DELETE FROM offboarded_device WHERE organization_id = $1", w.org) })

	if _, err := w.devOrgs.RequestDeletion(w.root(true), w.org, w.input(0)); err != nil {
		t.Fatal(err)
	}
	keptPending, _ := w.uninstallCommand(t, w.device)
	keptDelivered, _ := w.uninstallCommand(t, delivered)
	w.exec(t, "UPDATE device_command SET status = 'delivered', delivered_at = now() WHERE id = $1", keptDelivered)
	oldFailed, _ := w.uninstallCommand(t, failed)
	w.exec(t, `UPDATE device_command SET status = 'failed', finished_at = now(), result = '{"error":"conversion_pending"}'
		WHERE id = $1`, oldFailed)
	oldExpired, _ := w.uninstallCommand(t, expired)
	w.exec(t, "UPDATE device_command SET status = 'expired', finished_at = now() WHERE id = $1", oldExpired)
	oldLapsed, _ := w.uninstallCommand(t, lapsed)
	w.exec(t, "UPDATE device_command SET issued_at = now() - interval '2 days', expires_at = now() - interval '1 second' WHERE id = $1", oldLapsed)
	w.exec(t, "UPDATE device SET uninstalled_at = now() WHERE id = $1", reported)
	graceEnrolled, _ := w.newDevice(t, w.org, "active")
	w.publishOutbox(t)
	if started, err := job.StartDue(ctx); err != nil || !slices.Contains(started, w.org) {
		t.Fatalf("StartDue = %v, %v", started, err)
	}
	w.advanceTo(t, job, offboarding.StepOutbox)

	handed := []uuid.UUID{w.device, delivered, locked, failed, expired, lapsed, quarantined, pending, graceEnrolled}
	rows := w.offboardedRows(t)
	if len(rows) != len(handed) {
		t.Fatalf("%d offboarded devices, want %d: %v", len(rows), len(handed), rows)
	}
	for _, id := range []uuid.UUID{retired, rejected, reported} {
		if _, ok := rows[id]; ok {
			t.Fatalf("device %s was handed over", id)
		}
	}
	if rows[w.device].command != keptPending || rows[delivered].command != keptDelivered {
		t.Fatal("a pending or delivered offboarding uninstall was replaced")
	}
	for _, id := range handed {
		row, ok := rows[id]
		if !ok {
			t.Fatalf("device %s has no record", id)
		}
		cur, status := w.uninstallCommand(t, id)
		c := decodeCommand(t, row.envelope)
		if cur != row.command || c.CommandID != row.command.String() || c.DeviceID != id.String() || c.Type != command.TypeUninstall {
			t.Fatalf("device %s: record %s, current %s (%s), envelope %+v", id, row.command, cur, status, c)
		}
		var p command.UninstallParams
		if err := json.Unmarshal(c.Params, &p); err != nil || p.Mode != command.UninstallLeave {
			t.Fatalf("device %s: params %s", id, c.Params)
		}
		if w.count(t, "SELECT count(*) FROM device WHERE id = $1 AND uninstall_reason = 'organization_offboarding'", id) != 1 {
			t.Fatalf("device %s: the uninstall is not marked as the organization's", id)
		}
		cached := w.cache.offboarded[id]
		if cached.CommandID != row.command || string(cached.Command.Envelope) != string(row.envelope) || cached.OrganizationID != w.org {
			t.Fatalf("device %s: cached %+v", id, cached)
		}
		if id == w.device || id == delivered {
			continue
		}
		if !slices.Contains([]uuid.UUID{oldFailed, oldExpired, oldLapsed}, row.command) && status != "pending" {
			t.Fatalf("device %s: fresh command in status %s", id, status)
		}
		if slices.Contains([]uuid.UUID{oldFailed, oldExpired, oldLapsed}, row.command) {
			t.Fatalf("device %s kept its unusable command", id)
		}
		if d := time.Until(c.ExpiresAt) - organization.OffboardedDeviceRetention; d > time.Minute || d < -time.Minute {
			t.Fatalf("device %s: fresh command expires at %s", id, c.ExpiresAt)
		}
	}
	if keys := w.cache.offboarded[delivered].Keys; len(keys) != 1 || keys[0].KeyID != "k-active-"+delivered.String() ||
		len(rows[delivered].keys) != 1 || rows[delivered].keys[0]["key_id"] != "k-active-"+delivered.String() {
		t.Fatalf("keys of the delivered device: cached %+v, recorded %v; want the active key only", keys, rows[delivered].keys)
	}
	if keys := w.cache.offboarded[quarantined].Keys; len(keys) != 1 {
		t.Fatalf("keys of the quarantined device: %+v", keys)
	}
	var stepEvent *audit.Event
	for _, ev := range w.stepEvents(t, audit.CodeOrganizationDeletionStepCompleted) {
		if ev.Params["step"] == offboarding.StepDevices {
			stepEvent = &ev
		}
	}
	if stepEvent == nil || stepEvent.Params["count"] != float64(len(handed)) || stepEvent.Params["uninstalls_reissued"] != float64(7) {
		t.Fatalf("devices step event %+v", stepEvent)
	}

	w.advanceTo(t, job, "")
	if status, _, code := w.state(t); status != organization.StatusDeleted || code != "" {
		t.Fatalf("after the deletion: %s with %q", status, code)
	}
	if n := len(w.stepEvents(t, audit.CodeOrganizationDeletionStepFailed)); n != 0 {
		t.Fatalf("%d failure events although only devices were waiting", n)
	}
	deleted := w.stepEvents(t, audit.CodeOrganizationDeleted)
	if len(deleted) != 1 || deleted[0].Params["devices_offboarded"] != float64(len(handed)) {
		t.Fatalf("organization.deleted %+v", deleted)
	}
	if got := w.offboardedRows(t); len(got) != len(handed) {
		t.Fatalf("%d records after the tombstone, want %d", len(got), len(handed))
	}
	for _, d := range w.cache.devices {
		if !d.Offboarded && slices.Contains(handed, d.ID) {
			t.Fatalf("the valkey step deleted the keys of offboarded device %s", d.ID)
		}
	}
}

// TestOffboardingDevicesRepeatable: a step that fails after its transaction (here: signing) keeps the commands it
// issued; the repeated step re-signs them, records every device once and reissues nothing again.
func TestOffboardingDevicesRepeatable(t *testing.T) {
	w := newOffboardWorld(t)
	t.Cleanup(func() { w.exec(t, "DELETE FROM offboarded_device WHERE organization_id = $1", w.org) })
	w.signer = fakeCommandSigner{err: errors.New("openbao sealed")}
	failing := w.job()
	w.signer = fakeCommandSigner{}
	job := w.job()
	w.requestDueWithDevices(t, job)
	enrolled, _ := w.newDevice(t, w.org, "active")
	w.advanceTo(t, job, offboarding.StepDevices)
	var oe *app.OffboardingError
	for {
		_, err := failing.Advance(context.Background(), w.org)
		if errors.Is(err, app.ErrOffboardingWaiting) {
			w.passCutoff(t)
			continue
		}
		if !errors.As(err, &oe) || oe.Code != offboarding.ErrorSigningUnavailable {
			t.Fatalf("Advance with a failing signer: %v", err)
		}
		break
	}
	if n := len(w.offboardedRows(t)); n != 0 {
		t.Fatalf("%d records after a failed signing", n)
	}
	issued, _ := w.uninstallCommand(t, enrolled)
	w.advanceTo(t, job, offboarding.StepOutbox)
	rows := w.offboardedRows(t)
	if len(rows) != 2 || rows[enrolled].command != issued {
		t.Fatalf("records %v; want both devices, the enrolled one with %s", rows, issued)
	}
	for _, ev := range w.stepEvents(t, audit.CodeOrganizationDeletionStepCompleted) {
		if ev.Params["step"] == offboarding.StepDevices && (ev.Params["count"] != float64(2) || ev.Params["uninstalls_reissued"] != float64(0)) {
			t.Fatalf("devices step event %+v", ev)
		}
	}
}

// TestOffboardingDevicesWaitForOlderTransactions (amendment e point 10 on the gate of amendment j): a transaction that
// entered the organization before the deletion started and inserts a device later keeps the step devices waiting until
// it ends; the device it inserted gets a record.
func TestOffboardingDevicesWaitForOlderTransactions(t *testing.T) {
	w := newOffboardWorld(t)
	job := w.job()
	t.Cleanup(func() { w.exec(t, "DELETE FROM offboarded_device WHERE organization_id = $1", w.org) })
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, pgtest.SharedPaddock(t).Worker)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close(ctx) })
	straggler, err := conn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := straggler.Exec(ctx, "SELECT set_config('paddock.org_id', $1, true)", w.org.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := straggler.Exec(ctx, "SELECT count(*) FROM device"); err != nil {
		t.Fatal(err)
	}
	w.requestDue(t, job)
	w.advanceTo(t, job, offboarding.StepDevices)
	for range 3 {
		if _, err := job.Advance(ctx, w.org); !errors.Is(err, app.ErrOffboardingWaiting) {
			t.Fatalf("Advance with an older transaction open: %v", err)
		}
		w.passCutoff(t)
	}
	late := uuid.Must(uuid.NewV7())
	if _, err := straggler.Exec(ctx, "INSERT INTO device (id, organization_id, hostname, state) VALUES ($1, $2, 'late', 'active')",
		late, w.org); err != nil {
		t.Fatal(err)
	}
	if err := straggler.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	w.advanceTo(t, job, offboarding.StepOutbox)
	if _, ok := w.offboardedRows(t)[late]; !ok {
		t.Fatal("the device of the older transaction has no record")
	}
}

// fakeOffboardedCache records the keys the purge deletes.
type fakeOffboardedCache struct {
	mu      sync.Mutex
	deleted map[uuid.UUID][]string
}

func (f *fakeOffboardedCache) PutOffboardedDevice(context.Context, devicecache.OffboardedDevice, int64) error {
	return nil
}

func (f *fakeOffboardedCache) DeleteOffboardedDevice(_ context.Context, device uuid.UUID, keyIDs []string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.deleted[device] = keyIDs
	return nil
}

// TestOffboardedDevicesPurge (plan M17 decision 15, amendment l point 3): a record older than 365 days is deleted with
// its kept keys and one retention.purged (store offboarded_device) in the platform pseudo-organization; a younger
// record stays. A round without expired records records nothing.
func TestOffboardedDevicesPurge(t *testing.T) {
	w := newOffboardWorld(t)
	cache := &fakeOffboardedCache{deleted: map[uuid.UUID][]string{}}
	o := app.NewOffboardedDevices(w.runner, w.platform, cache)
	old, young := uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())
	now := time.Now()
	w.exec(t, `INSERT INTO offboarded_device (device_id, organization_id, keys, command_id, command_envelope, offboarded_at)
		VALUES ($1, $3, '[{"key_id":"k-old","public_key":"AQ=="}]', $4, '\x00', $5), ($2, $3, '[]', $4, '\x00', $6)`,
		old, young, w.org, uuid.Must(uuid.NewV7()), now.Add(-organization.OffboardedDeviceRetention-time.Hour),
		now.Add(-organization.OffboardedDeviceRetention+time.Hour))
	t.Cleanup(func() { w.exec(t, "DELETE FROM offboarded_device WHERE organization_id = $1", w.org) })
	sys := principal.With(context.Background(), principal.Principal{Kind: principal.KindSystem})
	events := func() []map[string]any {
		rows, err := w.super.Query(context.Background(), `SELECT payload -> 'params' FROM outbox WHERE organization_id = $1
			AND payload ->> 'code' = 'retention.purged' AND payload -> 'params' ->> 'store' = 'offboarded_device' ORDER BY id`,
			audit.PlatformOrganizationID)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		var out []map[string]any
		for rows.Next() {
			var p map[string]any
			if err := rows.Scan(&p); err != nil {
				t.Fatal(err)
			}
			out = append(out, p)
		}
		return out
	}
	before := len(events())
	if _, err := o.Purge(context.Background(), now); err == nil {
		t.Fatal("Purge without a system principal succeeded")
	}
	n, err := o.Purge(sys, now)
	if err != nil || n != 1 {
		t.Fatalf("Purge = %d, %v; want 1", n, err)
	}
	if w.count(t, "SELECT count(*) FROM offboarded_device WHERE device_id = $1", old) != 0 ||
		w.count(t, "SELECT count(*) FROM offboarded_device WHERE device_id = $1", young) != 1 {
		t.Fatal("the purge deleted the wrong records")
	}
	if !slices.Equal(cache.deleted[old], []string{"k-old"}) || len(cache.deleted) != 1 {
		t.Fatalf("keys deleted %v", cache.deleted)
	}
	got := events()
	if len(got) != before+1 || got[len(got)-1]["deleted"] != float64(1) {
		t.Fatalf("retention.purged events %v", got[before:])
	}
	if n, err := o.Purge(sys, now); err != nil || n != 0 || len(events()) != before+1 {
		t.Fatalf("second purge = %d, %v, events %d", n, err, len(events())-before)
	}
}

// TestOffboardReissueUninstallsDefiner (migration 00135): the worker's function refuses an organization that is not
// being deleted, and for a deleting organization it changes only that organization's devices.
func TestOffboardReissueUninstallsDefiner(t *testing.T) {
	w := newOffboardWorld(t)
	params := pgstore.OffboardReissueUninstallsParams{Params: []byte(`{"mode":"leave"}`), IssuedAt: time.Now().Truncate(time.Second),
		ExpiresAt: time.Now().Add(time.Hour)}
	call := func(org uuid.UUID) (n int64, err error) {
		err = w.worker.InOrgOffboarding(offboardingTestContext(org), func(ctx context.Context, q *pgstore.Queries) error {
			n, err = q.OffboardReissueUninstalls(ctx, params)
			return err
		})
		return n, err
	}
	if _, err := call(w.org); err == nil || !strings.Contains(err.Error(), "42501") {
		t.Fatalf("an active organization: %v, want insufficient_privilege", err)
	}
	for _, org := range []uuid.UUID{w.org, w.other} {
		w.exec(t, "UPDATE organization SET status = 'deleting' WHERE id = $1", org)
		t.Cleanup(func() { w.exec(t, "UPDATE organization SET status = 'active' WHERE id = $1", org) })
	}
	if n, err := call(w.org); err != nil || n != 1 {
		t.Fatalf("own organization: %d, %v; want 1", n, err)
	}
	if n, err := call(w.org); err != nil || n != 0 {
		t.Fatalf("again: %d, %v; want 0, the fresh command is kept", n, err)
	}
	if n := w.count(t, "SELECT count(*) FROM device_command WHERE device_id = $1", w.otherDevice); n != 0 {
		t.Fatalf("the other organization's device got %d commands", n)
	}
}
