package app_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/problem"
)

// indexPeriod is the audit index retention of newRetentionWorld: 400 days counted in seconds.
const indexPeriod = 400 * time.Second

// orgWithDevice creates an organization with one active device.
func (w retentionWorld) orgWithDevice(t *testing.T) (org, dev uuid.UUID) {
	t.Helper()
	org, dev = uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())
	w.exec(t, "INSERT INTO organization (id, slug, name, status) VALUES ($1, $2, 'R', 'active')", org, "r"+org.String()[24:])
	w.exec(t, "INSERT INTO device (id, organization_id, hostname, state) VALUES ($1, $2, 'cp', 'active')", dev, org)
	return org, dev
}

func (w retentionWorld) exec(t *testing.T, sql string, args ...any) {
	t.Helper()
	if _, err := w.super.Exec(context.Background(), sql, args...); err != nil {
		t.Fatal(err)
	}
}

// command inserts a command of dev in status that finished at finished (nil for an unfinished one).
func (w retentionWorld) command(t *testing.T, org, dev uuid.UUID, status string, finished *time.Time) uuid.UUID {
	t.Helper()
	id := uuid.Must(uuid.NewV7())
	issued := time.Now().Add(-1000 * time.Second)
	if finished != nil {
		issued = finished.Add(-time.Second)
	}
	w.exec(t, `INSERT INTO device_command (id, organization_id, device_id, type, status, issued_at, expires_at, finished_at)
		VALUES ($1, $2, $3, 'run_bundle', $4, $5::timestamptz, $5::timestamptz + interval '1 day', $6)`, id, org, dev, status, issued, finished)
	return id
}

func (w retentionWorld) exists(t *testing.T, table string, id uuid.UUID) bool {
	t.Helper()
	return countRows(t, w.super, "SELECT count(*) FROM "+table+" WHERE id = $1", id) == 1
}

// purged returns the outcome and deleted rows of org's retention.purged events of store, oldest first.
func (w retentionWorld) purged(t *testing.T, org uuid.UUID, store string) []purgedEvent {
	t.Helper()
	rows, err := w.super.Query(context.Background(), `
		SELECT outcome, params->>'store', params->>'cutoff', (params->>'deleted')::bigint
		  FROM action WHERE organization_id = $1 AND code = 'retention.purged' AND params->>'store' = $2
		 ORDER BY started_at`, org, store)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []purgedEvent
	for rows.Next() {
		var e purgedEvent
		if err := rows.Scan(&e.outcome, &e.store, &e.cutoff, &e.deleted); err != nil {
			t.Fatal(err)
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

func at(t time.Time) *time.Time { return &t }

// assertOneSuccess checks that org has exactly one successful retention.purged event of store with deleted rows and
// the cutoff now − indexPeriod.
func (w retentionWorld) assertOneSuccess(t *testing.T, org uuid.UUID, store string, deleted int64, now time.Time) {
	t.Helper()
	events := w.purged(t, org, store)
	if len(events) != 1 {
		t.Fatalf("%d retention.purged events of %s, want 1", len(events), store)
	}
	ev := events[0]
	cutoff, err := time.Parse(time.RFC3339, ev.cutoff)
	if ev.outcome != "success" || ev.deleted != deleted || err != nil || cutoff.Sub(now.Add(-indexPeriod)).Abs() > time.Millisecond {
		t.Fatalf("event %+v (cutoff %v), want success with deleted %d and cutoff now − %v", ev, err, deleted, indexPeriod)
	}
}

// TestRetentionPurgeDeviceCommands (ADR 0032 amendments 2026-10-18 and 2026-10-31): commands that finished, in every
// final status, more than the index retention ago go with one retention.purged event; younger finished and unfinished
// commands stay; a second pass records nothing.
func TestRetentionPurgeDeviceCommands(t *testing.T) {
	w := newRetentionWorld(t)
	now := time.Now().UTC()
	old := now.Add(-indexPeriod - time.Minute)
	org, dev := w.orgWithDevice(t)
	var expired []uuid.UUID
	for _, status := range []string{"succeeded", "failed", "expired", "cancelled"} {
		expired = append(expired, w.command(t, org, dev, status, at(old)))
	}
	young := w.command(t, org, dev, "succeeded", at(now.Add(-indexPeriod+time.Minute)))
	pending := w.command(t, org, dev, "pending", nil)
	delivered := w.command(t, org, dev, "delivered", nil)

	n, err := w.retention.PurgeDeviceCommands(systemCtx(org), now)
	if err != nil || n != 4 {
		t.Fatalf("purged %d (%v), want 4", n, err)
	}
	for _, id := range expired {
		if w.exists(t, "device_command", id) {
			t.Fatalf("finished command %s older than the period is still there", id)
		}
	}
	for name, id := range map[string]uuid.UUID{"younger": young, "pending": pending, "delivered": delivered} {
		if !w.exists(t, "device_command", id) {
			t.Fatalf("%s command was deleted", name)
		}
	}
	w.assertOneSuccess(t, org, app.StoreDeviceCommand, 4, now)

	if n, err := w.retention.PurgeDeviceCommands(systemCtx(org), now); err != nil || n != 0 {
		t.Fatalf("second pass purged %d (%v), want 0", n, err)
	}
	if events := w.purged(t, org, app.StoreDeviceCommand); len(events) != 1 {
		t.Fatalf("%d events after a pass without expired rows, want 1", len(events))
	}
}

// TestRetentionPurgeDeviceCommandsReferencedByConversion (ADR 0032 amendment 2026-10-31): a finished command a disk
// conversion still references as its command stays.
func TestRetentionPurgeDeviceCommandsReferencedByConversion(t *testing.T) {
	w := newRetentionWorld(t)
	now := time.Now().UTC()
	org, dev := w.orgWithDevice(t)
	cmd := w.command(t, org, dev, "succeeded", at(now.Add(-indexPeriod-time.Minute)))
	w.exec(t, `INSERT INTO device_disk_conversion (id, organization_id, device_id, command_id, reason, phase)
		VALUES ($1, $2, $3, $4, 'r', 'completed')`, uuid.Must(uuid.NewV7()), org, dev, cmd)

	if n, err := w.retention.PurgeDeviceCommands(systemCtx(org), now); err != nil || n != 0 {
		t.Fatalf("purged %d (%v), want 0", n, err)
	}
	if !w.exists(t, "device_command", cmd) {
		t.Fatal("the conversion's command was deleted")
	}
	if events := w.purged(t, org, app.StoreDeviceCommand); len(events) != 0 {
		t.Fatalf("events %+v, want none", events)
	}
}

// TestRetentionPurgeDeviceCommandsReferencedByAbort (ADR 0032 amendment 2026-10-31): a finished command a disk
// conversion still references as its abort command stays; the conversion's own command, also expired, stays as well.
func TestRetentionPurgeDeviceCommandsReferencedByAbort(t *testing.T) {
	w := newRetentionWorld(t)
	now := time.Now().UTC()
	org, dev := w.orgWithDevice(t)
	old := at(now.Add(-indexPeriod - time.Minute))
	cmd := w.command(t, org, dev, "failed", old)
	abort := w.command(t, org, dev, "succeeded", old)
	unrelated := w.command(t, org, dev, "succeeded", old)
	w.exec(t, `INSERT INTO device_disk_conversion (id, organization_id, device_id, command_id, abort_command_id, reason, phase)
		VALUES ($1, $2, $3, $4, $5, 'r', 'cancelled')`, uuid.Must(uuid.NewV7()), org, dev, cmd, abort)

	if n, err := w.retention.PurgeDeviceCommands(systemCtx(org), now); err != nil || n != 1 {
		t.Fatalf("purged %d (%v), want only the unreferenced command", n, err)
	}
	if !w.exists(t, "device_command", abort) || !w.exists(t, "device_command", cmd) || w.exists(t, "device_command", unrelated) {
		t.Fatal("want the abort and the conversion command kept and the unreferenced one deleted")
	}
	w.assertOneSuccess(t, org, app.StoreDeviceCommand, 1, now)
}

// TestRetentionPurgeDeviceCommandsReferencedByUninstall (ADR 0032 amendment 2026-10-31): a finished command a device
// still names as its uninstall command stays.
func TestRetentionPurgeDeviceCommandsReferencedByUninstall(t *testing.T) {
	w := newRetentionWorld(t)
	now := time.Now().UTC()
	org, dev := w.orgWithDevice(t)
	cmd := w.command(t, org, dev, "cancelled", at(now.Add(-indexPeriod-time.Minute)))
	w.exec(t, "UPDATE device SET uninstall_command_id = $1 WHERE id = $2", cmd, dev)

	if n, err := w.retention.PurgeDeviceCommands(systemCtx(org), now); err != nil || n != 0 {
		t.Fatalf("purged %d (%v), want 0", n, err)
	}
	if !w.exists(t, "device_command", cmd) {
		t.Fatal("the uninstall command was deleted")
	}
}

// TestRetentionPurgeDeviceAlerts (ADR 0032 amendment 2026-10-18): alerts cleared more than the index retention ago go
// with one retention.purged event; younger cleared alerts and open alerts, however old, stay.
func TestRetentionPurgeDeviceAlerts(t *testing.T) {
	w := newRetentionWorld(t)
	now := time.Now().UTC()
	org, dev := w.orgWithDevice(t)
	_, other := w.orgWithDevice(t)
	alert := func(device uuid.UUID, raised time.Time, cleared *time.Time) uuid.UUID {
		id := uuid.Must(uuid.NewV7())
		w.exec(t, `INSERT INTO device_alert (id, organization_id, device_id, kind, raised_at, cleared_at)
			SELECT $1, organization_id, id, 'stale_warning', $3, $4 FROM device WHERE id = $2`, id, device, raised, cleared)
		return id
	}
	long := now.Add(-2 * indexPeriod)
	expired := alert(dev, long, at(now.Add(-indexPeriod-time.Minute)))
	young := alert(dev, long, at(now.Add(-indexPeriod+time.Minute)))
	open := alert(other, long, nil)

	n, err := w.retention.PurgeDeviceAlerts(systemCtx(org), now)
	if err != nil || n != 1 {
		t.Fatalf("purged %d (%v), want 1", n, err)
	}
	if w.exists(t, "device_alert", expired) || !w.exists(t, "device_alert", young) {
		t.Fatal("want the expired alert deleted and the younger one kept")
	}
	w.assertOneSuccess(t, org, app.StoreDeviceAlert, 1, now)

	openOrg := uuid.Nil
	if err := w.super.QueryRow(context.Background(), "SELECT organization_id FROM device WHERE id = $1", other).Scan(&openOrg); err != nil {
		t.Fatal(err)
	}
	if n, err := w.retention.PurgeDeviceAlerts(systemCtx(openOrg), now); err != nil || n != 0 {
		t.Fatalf("open alert: purged %d (%v), want 0", n, err)
	}
	if !w.exists(t, "device_alert", open) {
		t.Fatal("an open alert was deleted")
	}
}

// TestRetentionPurgeEventGaps (ADR 0032 amendment 2026-10-31): gaps filled more than the index retention ago go with
// one retention.purged event; younger filled gaps and unfilled gaps, however old, stay.
func TestRetentionPurgeEventGaps(t *testing.T) {
	w := newRetentionWorld(t)
	now := time.Now().UTC()
	org, dev := w.orgWithDevice(t)
	long := now.Add(-2 * indexPeriod)
	gap := func(from int64, filled *time.Time) uuid.UUID {
		id := uuid.Must(uuid.NewV7())
		w.exec(t, `INSERT INTO device_event_gap (id, organization_id, device_id, from_seq, to_seq, first_seen_at,
			first_seen_last_seq, reported_at, filled_at) VALUES ($1, $2, $3, $4::bigint, $4::bigint + 5, $5, $4::bigint + 10, $5, $6)`,
			id, org, dev, from, long, filled)
		return id
	}
	expired := gap(1, at(now.Add(-indexPeriod-time.Minute)))
	young := gap(100, at(now.Add(-indexPeriod+time.Minute)))
	unfilled := gap(200, nil)

	n, err := w.retention.PurgeEventGaps(systemCtx(org), now)
	if err != nil || n != 1 {
		t.Fatalf("purged %d (%v), want 1", n, err)
	}
	if w.exists(t, "device_event_gap", expired) || !w.exists(t, "device_event_gap", young) || !w.exists(t, "device_event_gap", unfilled) {
		t.Fatal("want the expired gap deleted and the younger and the unfilled gap kept")
	}
	w.assertOneSuccess(t, org, app.StoreDeviceEventGap, 1, now)
}

// TestRetentionPurgeControlPlaneIsolation: a pass deletes only the context's organization's rows and records its event
// there; another organization's expired rows and events stay untouched.
func TestRetentionPurgeControlPlaneIsolation(t *testing.T) {
	w := newRetentionWorld(t)
	now := time.Now().UTC()
	old := now.Add(-indexPeriod - time.Minute)
	orgA, devA := w.orgWithDevice(t)
	orgB, devB := w.orgWithDevice(t)
	cmdA, cmdB := w.command(t, orgA, devA, "succeeded", &old), w.command(t, orgB, devB, "succeeded", &old)
	alertB, gapB := uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())
	w.exec(t, `INSERT INTO device_alert (id, organization_id, device_id, kind, raised_at, cleared_at)
		VALUES ($1, $2, $3, 'stale_warning', $4, $4)`, alertB, orgB, devB, old)
	w.exec(t, `INSERT INTO device_event_gap (id, organization_id, device_id, from_seq, to_seq, first_seen_at,
		first_seen_last_seq, filled_at) VALUES ($1, $2, $3, 1, 2, $4, 3, $4)`, gapB, orgB, devB, old)

	ctx := systemCtx(orgA)
	for name, purge := range map[string]func(context.Context, time.Time) (int64, error){
		app.StoreDeviceCommand: w.retention.PurgeDeviceCommands, app.StoreDeviceAlert: w.retention.PurgeDeviceAlerts,
		app.StoreDeviceEventGap: w.retention.PurgeEventGaps,
	} {
		if _, err := purge(ctx, now); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
	if w.exists(t, "device_command", cmdA) {
		t.Fatal("organization A's expired command is still there")
	}
	if !w.exists(t, "device_command", cmdB) || !w.exists(t, "device_alert", alertB) || !w.exists(t, "device_event_gap", gapB) {
		t.Fatal("organization B's rows were deleted by organization A's pass")
	}
	for _, store := range []string{app.StoreDeviceCommand, app.StoreDeviceAlert, app.StoreDeviceEventGap} {
		if events := w.purged(t, orgB, store); len(events) != 0 {
			t.Fatalf("organization B has events %+v of %s", events, store)
		}
	}
}

// TestRetentionPurgeControlPlaneSystemOnly: only the worker's system principal may purge these stores.
func TestRetentionPurgeControlPlaneSystemOnly(t *testing.T) {
	w := newRetentionWorld(t)
	now := time.Now().UTC()
	org, dev := w.orgWithDevice(t)
	cmd := w.command(t, org, dev, "succeeded", at(now.Add(-indexPeriod-time.Minute)))
	admin := principal.With(context.Background(), principal.Principal{Kind: principal.KindAdmin, ID: uuid.Must(uuid.NewV7()),
		Role: principal.RoleOrgAdmin, OrganizationID: org})
	for name, purge := range map[string]func(context.Context, time.Time) (int64, error){
		app.StoreDeviceCommand: w.retention.PurgeDeviceCommands, app.StoreDeviceAlert: w.retention.PurgeDeviceAlerts,
		app.StoreDeviceEventGap: w.retention.PurgeEventGaps,
	} {
		if _, err := purge(admin, now); !errors.Is(err, problem.Unauthenticated) {
			t.Fatalf("%s by an admin: %v, want unauthenticated", name, err)
		}
	}
	if !w.exists(t, "device_command", cmd) {
		t.Fatal("an admin's purge deleted a command")
	}
}
