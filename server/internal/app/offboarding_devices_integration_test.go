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

// offboardedRow is a record of offboarded_device: its uninstall and disarm by command ID, with their envelopes.
type offboardedRow struct {
	uninstall, disarm uuid.UUID
	envelopes         map[uuid.UUID][]byte
	keys              []map[string]any
}

func (w *offboardWorld) offboardedRows(t *testing.T) map[uuid.UUID]offboardedRow {
	t.Helper()
	rows, err := w.super.Query(context.Background(),
		"SELECT device_id, command_envelopes, keys FROM offboarded_device WHERE organization_id = $1", w.org)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	out := map[uuid.UUID]offboardedRow{}
	for rows.Next() {
		var id uuid.UUID
		var cmds, keys []byte
		if err := rows.Scan(&id, &cmds, &keys); err != nil {
			t.Fatal(err)
		}
		r := offboardedRow{envelopes: map[uuid.UUID][]byte{}}
		var stored []struct {
			CommandID uuid.UUID `json:"command_id"`
			Envelope  []byte    `json:"envelope"`
		}
		if err := json.Unmarshal(cmds, &stored); err != nil {
			t.Fatal(err)
		}
		for _, c := range stored {
			r.envelopes[c.CommandID] = c.Envelope
			switch decodeCommand(t, c.Envelope).Type {
			case command.TypeUninstall:
				r.uninstall = c.CommandID
			case command.TypeDeleteSelfLock:
				r.disarm = c.CommandID
			}
		}
		if len(stored) != 2 || r.uninstall == uuid.Nil || r.disarm == uuid.Nil {
			t.Fatalf("device %s: commands %s, want one uninstall and one disarm", id, cmds)
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

// adminUninstall gives device an administrator's own open uninstall with params, status and 7 days left, as the
// deletion request finds it (amendment e point 8).
func (w *offboardWorld) adminUninstall(t *testing.T, device uuid.UUID, params, status string) uuid.UUID {
	t.Helper()
	id := uuid.Must(uuid.NewV7())
	w.exec(t, `INSERT INTO device_command (id, organization_id, device_id, type, params, status, issued_at, expires_at, issued_by)
		VALUES ($1, $2, $3, 'uninstall', $4::jsonb, $5, date_trunc('second', now()), date_trunc('second', now()) + interval '7 days', $6)`,
		id, w.org, device, params, status, uuid.Must(uuid.NewV7()))
	w.exec(t, `UPDATE device SET uninstall_requested_at = now(), uninstall_mode = $2::jsonb ->> 'mode', uninstall_command_id = $3
		WHERE id = $1`, device, params, id)
	return id
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

// expiresInRetention fails unless the command expires about OffboardedDeviceRetention from now.
func expiresInRetention(t *testing.T, what string, c command.Command) {
	t.Helper()
	if d := time.Until(c.ExpiresAt) - organization.OffboardedDeviceRetention; d > time.Minute || d < -time.Minute {
		t.Fatalf("%s expires at %s", what, c.ExpiresAt)
	}
}

// devicesStepEvent is the completion event of the step devices.
func (w *offboardWorld) devicesStepEvent(t *testing.T) audit.Event {
	t.Helper()
	for _, ev := range w.stepEvents(t, audit.CodeOrganizationDeletionStepCompleted) {
		if ev.Params["step"] == offboarding.StepDevices {
			return ev
		}
	}
	t.Fatal("no completion event of the step devices")
	return audit.Event{}
}

// TestOffboardingHandsDevicesOver (plan M17 decision 15, amendments e point 10, m point 2 and n, PDK-1016): the step
// devices records every device that has not reported its removal and is neither retired nor rejected in
// offboarded_device, each with the disarm of its dead man's switch (delete_self_lock, valid for the retention) and an
// uninstall. A device whose offboarding uninstall is pending or delivered keeps that command, as does a delivered
// administrator reset; an administrator's pending reset with 7 days left is cancelled, dropped from the cache and
// replaced by a reset valid for the retention, while one that has already lapsed gets a fresh leave (review 2 finding
// 1); a device enrolled during the grace period, one the request skipped for an open Lock, one whose command
// failed (conversion_pending), expired or lapsed while pending, a quarantined device each get a fresh
// leave, also with the Lock open. A device still pending approval is skipped (PDK-1061, amendment m point 1): no
// command, no record and no cached key, and organization.deleted counts it in devices_pending_dropped. The cache receives each device's active keys and both signed commands; the
// completion event carries uninstalls_reissued and disarms_issued. The deletion then finishes without any failure
// although no device reported (main's requirement: waiting devices never hold the deletion).
func TestOffboardingHandsDevicesOver(t *testing.T) {
	w := newOffboardWorld(t)
	job := w.job()
	ctx := context.Background()
	delivered, _ := w.newDevice(t, w.org, "active")
	locked, _ := w.newDevice(t, w.org, "active")
	failed, _ := w.newDevice(t, w.org, "active")
	expired, _ := w.newDevice(t, w.org, "active")
	lapsed, _ := w.newDevice(t, w.org, "active")
	reset, _ := w.newDevice(t, w.org, "active")
	resetDelivered, _ := w.newDevice(t, w.org, "active")
	resetLapsed, _ := w.newDevice(t, w.org, "active")
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
	resetParams := `{"mode":"reset","clear_tpm":true}`
	oldReset := w.adminUninstall(t, reset, resetParams, "pending")
	keptReset := w.adminUninstall(t, resetDelivered, resetParams, "delivered")
	oldResetLapsed := w.adminUninstall(t, resetLapsed, resetParams, "pending")
	w.exec(t, "UPDATE device_command SET issued_at = now() - interval '8 days', expires_at = now() - interval '1 second' WHERE id = $1",
		oldResetLapsed)
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

	handed := []uuid.UUID{w.device, delivered, locked, failed, expired, lapsed, reset, resetDelivered, resetLapsed, quarantined,
		graceEnrolled}
	rows := w.offboardedRows(t)
	if len(rows) != len(handed) {
		t.Fatalf("%d offboarded devices, want %d: %v", len(rows), len(handed), rows)
	}
	for _, id := range []uuid.UUID{pending, retired, rejected, reported} {
		if _, ok := rows[id]; ok {
			t.Fatalf("device %s was handed over", id)
		}
	}
	kept := map[uuid.UUID]uuid.UUID{w.device: keptPending, delivered: keptDelivered, resetDelivered: keptReset}
	for id, cmd := range kept {
		if rows[id].uninstall != cmd {
			t.Fatalf("device %s: the kept uninstall %s was replaced by %s", id, cmd, rows[id].uninstall)
		}
	}
	unusable := []uuid.UUID{oldFailed, oldExpired, oldLapsed, oldReset, oldResetLapsed}
	for _, id := range handed {
		row, ok := rows[id]
		if !ok {
			t.Fatalf("device %s has no record", id)
		}
		cur, status := w.uninstallCommand(t, id)
		c := decodeCommand(t, row.envelopes[row.uninstall])
		if cur != row.uninstall || c.CommandID != row.uninstall.String() || c.DeviceID != id.String() || c.Type != command.TypeUninstall {
			t.Fatalf("device %s: record %s, current %s (%s), envelope %+v", id, row.uninstall, cur, status, c)
		}
		disarm := decodeCommand(t, row.envelopes[row.disarm])
		if disarm.Type != command.TypeDeleteSelfLock || disarm.DeviceID != id.String() || string(disarm.Params) != "{}" {
			t.Fatalf("device %s: disarm %+v", id, disarm)
		}
		expiresInRetention(t, "disarm of "+id.String(), disarm)
		var p command.UninstallParams
		if err := json.Unmarshal(c.Params, &p); err != nil {
			t.Fatalf("device %s: params %s", id, c.Params)
		}
		cached := w.cache.offboarded[id]
		if cached.OrganizationID != w.org || len(cached.Commands) != 2 {
			t.Fatalf("device %s: cached %+v", id, cached)
		}
		for _, cc := range cached.Commands {
			if string(cc.Command.Envelope) != string(row.envelopes[cc.ID]) {
				t.Fatalf("device %s: cached command %s differs from the record", id, cc.ID)
			}
		}
		if slices.Contains(unusable, row.uninstall) {
			t.Fatalf("device %s kept its unusable command", id)
		}
		switch {
		case id == reset:
			if p.Mode != command.UninstallReset || !p.ClearTPM || status != "pending" {
				t.Fatalf("the replaced reset: %s %+v", status, p)
			}
			expiresInRetention(t, "the replaced reset", c)
		case id == resetDelivered:
			if p.Mode != command.UninstallReset || status != "delivered" {
				t.Fatalf("the delivered reset: %s %+v", status, p)
			}
		case kept[id] != uuid.Nil:
			if p.Mode != command.UninstallLeave ||
				w.count(t, "SELECT count(*) FROM device WHERE id = $1 AND uninstall_reason = 'organization_offboarding'", id) != 1 {
				t.Fatalf("device %s: kept params %s or reason lost", id, c.Params)
			}
		default:
			if p.Mode != command.UninstallLeave || status != "pending" ||
				w.count(t, "SELECT count(*) FROM device WHERE id = $1 AND uninstall_reason = 'organization_offboarding'", id) != 1 {
				t.Fatalf("device %s: fresh command %s %+v", id, status, p)
			}
			expiresInRetention(t, "fresh uninstall of "+id.String(), c)
		}
	}
	var oldStatus string
	if err := w.super.QueryRow(ctx, "SELECT status FROM device_command WHERE id = $1", oldReset).Scan(&oldStatus); err != nil || oldStatus != "cancelled" {
		t.Fatalf("the replaced reset is %q (%v), want cancelled", oldStatus, err)
	}
	if !slices.Contains(w.cache.dropped, oldReset) || slices.Contains(w.cache.dropped, keptReset) {
		t.Fatalf("commands dropped from the cache %v; want the replaced reset %s only among the kept ones", w.cache.dropped, oldReset)
	}
	if keys := w.cache.offboarded[delivered].Keys; len(keys) != 1 || keys[0].KeyID != "k-active-"+delivered.String() ||
		len(rows[delivered].keys) != 1 || rows[delivered].keys[0]["key_id"] != "k-active-"+delivered.String() {
		t.Fatalf("keys of the delivered device: cached %+v, recorded %v; want the active key only", keys, rows[delivered].keys)
	}
	if keys := w.cache.offboarded[quarantined].Keys; len(keys) != 1 {
		t.Fatalf("keys of the quarantined device: %+v", keys)
	}
	ev := w.devicesStepEvent(t)
	if ev.Params["count"] != float64(len(handed)) || ev.Params["uninstalls_reissued"] != float64(8) ||
		ev.Params["disarms_issued"] != float64(len(handed)) {
		t.Fatalf("devices step event %+v", ev.Params)
	}

	if n := w.count(t, "SELECT count(*) FROM device_command WHERE device_id = $1", pending); n != 0 {
		t.Fatalf("the pending device got %d commands", n)
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
	if deleted[0].Params["devices_pending_dropped"] != float64(1) {
		t.Fatalf("organization.deleted %+v, want devices_pending_dropped 1", deleted[0].Params)
	}
	if _, ok := w.cache.offboarded[pending]; ok {
		t.Fatal("the pending device was cached as offboarded")
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

// TestOffboardingDevicesRepeatable (review 1 minor 3): a step that fails after its transaction (here: signing) keeps
// the commands it issued; the repeated step re-signs them, records every device once and issues nothing again, and the
// completion event counts what all attempts issued.
func TestOffboardingDevicesRepeatable(t *testing.T) {
	w := newOffboardWorld(t)
	t.Cleanup(func() { w.exec(t, "DELETE FROM offboarded_device WHERE organization_id = $1", w.org) })
	w.signer = fakeCommandSigner{err: errors.New("openbao sealed")}
	failing := w.job()
	w.signer = fakeCommandSigner{}
	job := w.job()
	w.requestDueWithDevices(t, job)
	enrolled, _ := w.newDevice(t, w.org, "active")
	pending, _ := w.newDevice(t, w.org, "pending")
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
	if n := w.count(t, "SELECT count(*) FROM offboarded_device WHERE organization_id = $1", w.org); n != 0 {
		t.Fatalf("%d records after a failed signing", n)
	}
	issued, _ := w.uninstallCommand(t, enrolled)
	w.advanceTo(t, job, offboarding.StepOutbox)
	rows := w.offboardedRows(t)
	if len(rows) != 2 || rows[enrolled].uninstall != issued {
		t.Fatalf("records %v; want both devices, the enrolled one with %s", rows, issued)
	}
	if n := w.count(t, `SELECT count(*) FROM device_command WHERE organization_id = $1 AND type = 'delete_self_lock'`, w.org); n != 2 {
		t.Fatalf("%d disarms after the repeated step, want one per device", n)
	}
	if _, ok := rows[pending]; ok {
		t.Fatal("the pending device was handed over")
	}
	// Both attempts of the step counted the pending device; the stored count is the latest value, not their sum.
	if n := w.count(t, `SELECT (offboarding_counts ->> 'devices.pending_dropped')::bigint FROM organization WHERE id = $1`, w.org); n != 1 {
		t.Fatalf("devices.pending_dropped = %d after two attempts of the step, want 1", n)
	}
	ev := w.devicesStepEvent(t)
	if ev.Params["count"] != float64(2) || ev.Params["uninstalls_reissued"] != float64(1) || ev.Params["disarms_issued"] != float64(2) {
		t.Fatalf("devices step event %+v; want the first attempt's uninstall and disarms counted", ev.Params)
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
	w.exec(t, `INSERT INTO offboarded_device (device_id, organization_id, keys, command_envelopes, offboarded_at)
		VALUES ($1, $3, '[{"key_id":"k-old","public_key":"AQ=="}]', '[]', $4), ($2, $3, '[]', '[]', $5)`,
		old, young, w.org, now.Add(-organization.OffboardedDeviceRetention-time.Hour),
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

// TestOffboardReissueUninstallsDefiner (migration 00135, review 1 minor 4): the worker's function refuses an
// organization that is not being deleted; it takes no params from its caller, so the worker can issue only a leave, and
// a caller passing params of its own finds no such function. For a deleting organization it changes only that
// organization's devices, and a second call issues nothing more.
func TestOffboardReissueUninstallsDefiner(t *testing.T) {
	w := newOffboardWorld(t)
	call := func(org uuid.UUID) (n int64, err error) {
		err = w.worker.InOrgOffboarding(offboardingTestContext(org), func(ctx context.Context, q *pgstore.Queries) error {
			n, err = q.OffboardReissueUninstalls(ctx)
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
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, pgtest.SharedPaddock(t).Worker)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close(ctx) })
	tx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, "SELECT set_config('paddock.org_id', $1, true)", w.org.String()); err != nil {
		t.Fatal(err)
	}
	_, err = tx.Exec(ctx, `SELECT paddock_offboard_reissue_uninstalls('{"mode":"reset"}'::jsonb, now(), now() + interval '1 year')`)
	if err == nil || !strings.Contains(err.Error(), "42883") {
		t.Fatalf("a call with params of its own: %v, want undefined_function", err)
	}
	_ = tx.Rollback(ctx)
	if n, err := call(w.org); err != nil || n != 1 {
		t.Fatalf("own organization: %d, %v; want 1", n, err)
	}
	var params string
	if err := w.super.QueryRow(ctx, `SELECT c.params::text FROM device d JOIN device_command c ON c.id = d.uninstall_command_id
		WHERE d.id = $1`, w.device).Scan(&params); err != nil || params != `{"mode": "leave"}` {
		t.Fatalf("params of the fresh uninstall: %s %v", params, err)
	}
	if n, err := call(w.org); err != nil || n != 0 {
		t.Fatalf("again: %d, %v; want 0, the fresh command is kept", n, err)
	}
	if n := w.count(t, "SELECT count(*) FROM device_command WHERE device_id = $1 AND type = 'delete_self_lock'", w.device); n != 1 {
		t.Fatalf("%d disarms after two calls, want 1", n)
	}
	if n := w.count(t, "SELECT count(*) FROM device_command WHERE device_id = $1", w.otherDevice); n != 0 {
		t.Fatalf("the other organization's device got %d commands", n)
	}
}
