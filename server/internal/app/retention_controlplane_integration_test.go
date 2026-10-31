package app_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/problem"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/pgtest"
)

// indexPeriod is the audit index retention of newRetentionWorld: 400 days counted in seconds.
const indexPeriod = 400 * time.Second

// indexNow is the injected clock of the passes kept by the audit index: mid-month, so the index still shows the whole
// month containing now − indexPeriod, and the cutoff is indexFloor, that month's start (ADR 0032 amendment 2026-10-31).
var (
	indexNow   = time.Date(2026, 3, 15, 12, 0, 0, 0, time.UTC)
	indexFloor = time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
)

// orgWithDevice creates an organization with one active device.
func (w retentionWorld) orgWithDevice(t *testing.T) (org, dev uuid.UUID) {
	t.Helper()
	org = uuid.Must(uuid.NewV7())
	w.exec(t, "INSERT INTO organization (id, slug, name, status) VALUES ($1, $2, 'R', 'active')", org, "r"+org.String()[24:])
	return org, w.device(t, org)
}

// device creates another active device of org.
func (w retentionWorld) device(t *testing.T, org uuid.UUID) uuid.UUID {
	t.Helper()
	dev := uuid.Must(uuid.NewV7())
	w.exec(t, "INSERT INTO device (id, organization_id, hostname, state) VALUES ($1, $2, 'cp', 'active')", dev, org)
	return dev
}

// alert inserts an alert of dev raised a day before indexFloor and cleared at cleared (nil for an open one).
func (w retentionWorld) alert(t *testing.T, dev uuid.UUID, cleared *time.Time) uuid.UUID {
	t.Helper()
	id := uuid.Must(uuid.NewV7())
	w.exec(t, `INSERT INTO device_alert (id, organization_id, device_id, kind, raised_at, cleared_at)
		SELECT $1, organization_id, id, 'stale_warning', $3, $4 FROM device WHERE id = $2`, id, dev, indexFloor.Add(-24*time.Hour), cleared)
	return id
}

// gap inserts an event gap of dev from from, first seen a day before indexFloor and filled at filled (nil for an
// unfilled one).
func (w retentionWorld) gap(t *testing.T, org, dev uuid.UUID, from int64, filled *time.Time) uuid.UUID {
	t.Helper()
	id := uuid.Must(uuid.NewV7())
	w.exec(t, `INSERT INTO device_event_gap (id, organization_id, device_id, from_seq, to_seq, first_seen_at,
		first_seen_last_seq, reported_at, filled_at) VALUES ($1, $2, $3, $4::bigint, $4::bigint + 5, $5, $4::bigint + 10, $5, $6)`,
		id, org, dev, from, indexFloor.Add(-24*time.Hour), filled)
	return id
}

// action inserts an action of org started at started, in status started (finished nil) or finished at finished, with
// the action trigger off: the times lie in the past (migration 00084).
func (w retentionWorld) action(t *testing.T, org uuid.UUID, started time.Time, finished *time.Time) uuid.UUID {
	t.Helper()
	id := uuid.Must(uuid.NewV7())
	status, outcome := "started", (*string)(nil)
	if finished != nil {
		ok := "success"
		status, outcome = "finished", &ok
	}
	if err := pgtest.ExecUntriggered(context.Background(), w.super, `INSERT INTO action (id, organization_id, code, status, outcome, actor,
		correlation_id, started_at, finished_at)
		VALUES ($1, $2, 'test.retention', $3, $4, '{"kind":"system"}', 'retention-test', $5, $6)`, id, org, status, outcome, started, finished); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = w.super.Exec(context.Background(), "DELETE FROM action WHERE id = $1", id) })
	return id
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
		SELECT outcome, params->>'store', params->>'cutoff', (params->>'deleted')::bigint, coalesce(params->>'index_days', '')
		  FROM action WHERE organization_id = $1 AND code = 'retention.purged' AND params->>'store' = $2
		 ORDER BY started_at`, org, store)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []purgedEvent
	for rows.Next() {
		var e purgedEvent
		if err := rows.Scan(&e.outcome, &e.store, &e.cutoff, &e.deleted, &e.indexDays); err != nil {
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

// assertOneSuccess checks that org has exactly one successful retention.purged event of store with deleted rows, the
// cutoff want and the world's index retention of 400 days.
func (w retentionWorld) assertOneSuccess(t *testing.T, org uuid.UUID, store string, deleted int64, want time.Time) {
	t.Helper()
	events := w.purged(t, org, store)
	if len(events) != 1 {
		t.Fatalf("%d retention.purged events of %s, want 1", len(events), store)
	}
	ev := events[0]
	cutoff, err := time.Parse(time.RFC3339, ev.cutoff)
	if ev.outcome != "success" || ev.deleted != deleted || err != nil || !cutoff.Equal(want) || ev.indexDays != "400" {
		t.Fatalf("event %+v (cutoff %v), want success with deleted %d, cutoff %v and index_days 400", ev, err, deleted, want)
	}
}

// TestRetentionPurgeDeviceCommands (ADR 0032 amendments 2026-10-18 and 2026-10-31): commands that finished, in every
// final status, more than the index retention ago go with one retention.purged event; younger finished and unfinished
// commands stay; a second pass records nothing.
func TestRetentionPurgeDeviceCommands(t *testing.T) {
	w := newRetentionWorld(t)
	now := indexNow
	old := indexFloor.Add(-time.Minute)
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
	w.assertOneSuccess(t, org, app.StoreDeviceCommand, 4, indexFloor)

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
	now := indexNow
	org, dev := w.orgWithDevice(t)
	cmd := w.command(t, org, dev, "succeeded", at(indexFloor.Add(-time.Minute)))
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
	now := indexNow
	org, dev := w.orgWithDevice(t)
	old := at(indexFloor.Add(-time.Minute))
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
	w.assertOneSuccess(t, org, app.StoreDeviceCommand, 1, indexFloor)
}

// TestRetentionPurgeDeviceCommandsReferencedByUninstall (ADR 0032 amendment 2026-10-31): a finished command a device
// still names as its uninstall command stays, while an unreferenced expired command of the same organization goes.
func TestRetentionPurgeDeviceCommandsReferencedByUninstall(t *testing.T) {
	w := newRetentionWorld(t)
	now := indexNow
	org, dev := w.orgWithDevice(t)
	old := at(indexFloor.Add(-time.Minute))
	cmd := w.command(t, org, dev, "cancelled", old)
	unrelated := w.command(t, org, dev, "cancelled", old)
	w.exec(t, "UPDATE device SET uninstall_command_id = $1 WHERE id = $2", cmd, dev)

	if n, err := w.retention.PurgeDeviceCommands(systemCtx(org), now); err != nil || n != 1 {
		t.Fatalf("purged %d (%v), want only the unreferenced command", n, err)
	}
	if !w.exists(t, "device_command", cmd) || w.exists(t, "device_command", unrelated) {
		t.Fatal("want the uninstall command kept and the unreferenced one deleted")
	}
	w.assertOneSuccess(t, org, app.StoreDeviceCommand, 1, indexFloor)
}

// TestRetentionPurgeDeviceAlerts (ADR 0032 amendment 2026-10-18): alerts cleared more than the index retention ago go
// with one retention.purged event; younger cleared alerts and open alerts, however old, stay. The open alert is on a
// second device of the same organization, as a device has at most one open alert.
func TestRetentionPurgeDeviceAlerts(t *testing.T) {
	w := newRetentionWorld(t)
	now := indexNow
	org, dev := w.orgWithDevice(t)
	expired := w.alert(t, dev, at(indexFloor.Add(-time.Minute)))
	young := w.alert(t, dev, at(now.Add(-indexPeriod+time.Minute)))
	open := w.alert(t, w.device(t, org), nil)

	n, err := w.retention.PurgeDeviceAlerts(systemCtx(org), now)
	if err != nil || n != 1 {
		t.Fatalf("purged %d (%v), want 1", n, err)
	}
	if w.exists(t, "device_alert", expired) || !w.exists(t, "device_alert", young) || !w.exists(t, "device_alert", open) {
		t.Fatal("want the expired alert deleted and the younger and the open one kept")
	}
	w.assertOneSuccess(t, org, app.StoreDeviceAlert, 1, indexFloor)
}

// TestRetentionPurgeEventGaps (ADR 0032 amendment 2026-10-31): gaps filled more than the index retention ago go with
// one retention.purged event; younger filled gaps and unfilled gaps, however old, stay.
func TestRetentionPurgeEventGaps(t *testing.T) {
	w := newRetentionWorld(t)
	now := indexNow
	org, dev := w.orgWithDevice(t)
	expired := w.gap(t, org, dev, 1, at(indexFloor.Add(-time.Minute)))
	young := w.gap(t, org, dev, 100, at(now.Add(-indexPeriod+time.Minute)))
	unfilled := w.gap(t, org, dev, 200, nil)

	n, err := w.retention.PurgeEventGaps(systemCtx(org), now)
	if err != nil || n != 1 {
		t.Fatalf("purged %d (%v), want 1", n, err)
	}
	if w.exists(t, "device_event_gap", expired) || !w.exists(t, "device_event_gap", young) || !w.exists(t, "device_event_gap", unfilled) {
		t.Fatal("want the expired gap deleted and the younger and the unfilled gap kept")
	}
	w.assertOneSuccess(t, org, app.StoreDeviceEventGap, 1, indexFloor)
}

// TestRetentionPurgeActions (ADR 0032 amendment 2026-10-31): actions that finished before the index cutoff go with one
// retention.purged event of store action; younger finished actions and started ones, however old, stay; a second pass
// records nothing.
func TestRetentionPurgeActions(t *testing.T) {
	w := newRetentionWorld(t)
	now := indexNow
	org, _ := w.orgWithDevice(t)
	long := indexFloor.Add(-24 * time.Hour)
	expired := w.action(t, org, long, at(indexFloor.Add(-time.Minute)))
	young := w.action(t, org, long, at(now.Add(-indexPeriod+time.Minute)))
	started := w.action(t, org, long, nil)
	// Migration 00084 ties finished_at to the status, so a started action cannot carry the expired finish time that only
	// the status guard would otherwise keep out.
	expectRefused(t, w.super, "UPDATE action SET finished_at = $1 WHERE id = $2", indexFloor.Add(-time.Minute), started)

	n, err := w.retention.PurgeActions(systemCtx(org), now)
	if err != nil || n != 1 {
		t.Fatalf("purged %d (%v), want 1", n, err)
	}
	if w.exists(t, "action", expired) || !w.exists(t, "action", young) || !w.exists(t, "action", started) {
		t.Fatal("want the expired action deleted and the younger and the started one kept")
	}
	w.assertOneSuccess(t, org, app.StoreAction, 1, indexFloor)

	if n, err := w.retention.PurgeActions(systemCtx(org), now); err != nil || n != 0 {
		t.Fatalf("second pass purged %d (%v), want 0", n, err)
	}
	if events := w.purged(t, org, app.StoreAction); len(events) != 1 {
		t.Fatalf("%d events after a pass without expired rows, want 1", len(events))
	}
}

// TestRetentionPurgePlatformActions (ADR 0032 amendment 2026-10-31): the platform pass deletes the platform
// pseudo-organization's expired finished actions through the platform pool and records its event there; started
// platform actions and an organization's expired actions stay. Its clock lies in 2020, before every other row of the
// shared database, because the platform pool sees every organization's actions.
func TestRetentionPurgePlatformActions(t *testing.T) {
	w := newRetentionWorld(t)
	now, floor := time.Date(2020, 6, 15, 12, 0, 0, 0, time.UTC), time.Date(2020, 6, 1, 0, 0, 0, 0, time.UTC)
	org, _ := w.orgWithDevice(t)
	long := floor.Add(-24 * time.Hour)
	expired := w.action(t, uuid.Nil, long, at(floor.Add(-time.Minute)))
	inMonth := w.action(t, uuid.Nil, long, at(floor.Add(time.Minute)))
	started := w.action(t, uuid.Nil, long, nil)
	expectRefused(t, w.super, "UPDATE action SET finished_at = $1 WHERE id = $2", floor.Add(-time.Minute), started)
	other := w.action(t, org, long, at(floor.Add(-time.Minute)))
	t.Cleanup(func() {
		_, _ = w.super.Exec(context.Background(), `DELETE FROM action WHERE organization_id = $1 AND code = 'retention.purged'
			AND params->>'store' = $2 AND params->>'cutoff' = $3`, uuid.Nil, app.StoreAction, floor.Format(time.RFC3339))
	})

	n, err := w.retention.PurgePlatformActions(systemCtx(uuid.Nil), now)
	if err != nil || n != 1 {
		t.Fatalf("purged %d (%v), want 1", n, err)
	}
	if w.exists(t, "action", expired) || !w.exists(t, "action", inMonth) || !w.exists(t, "action", started) || !w.exists(t, "action", other) {
		t.Fatal("want the expired platform action deleted and the one inside the index month, the started one and the organization's kept")
	}
	var events []purgedEvent
	for _, e := range w.purged(t, uuid.Nil, app.StoreAction) {
		if e.cutoff == floor.Format(time.RFC3339) {
			events = append(events, e)
		}
	}
	if len(events) != 1 || events[0].outcome != "success" || events[0].deleted != 1 || events[0].indexDays != "400" {
		t.Fatalf("platform events %+v, want one success with deleted 1 and index_days 400", events)
	}
}

// TestRetentionActionDeleteLimitedByDatabase (ADR 0032 amendment 2026-10-31): the database, not only the use case's
// queries, limits who deletes which action. The platform role, which the internet-facing API holds too, deletes neither
// an organization's action nor a started platform action; the worker deletes no started action. A finished platform
// action and a finished organization action show that the deletes themselves are allowed.
func TestRetentionActionDeleteLimitedByDatabase(t *testing.T) {
	w := newRetentionWorld(t)
	env := pgtest.SharedPaddock(t)
	org, _ := w.orgWithDevice(t)
	long := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	orgFinished := w.action(t, org, long, at(long.Add(time.Minute)))
	orgStarted := w.action(t, org, long, nil)
	platformFinished := w.action(t, uuid.Nil, long, at(long.Add(time.Minute)))
	platformStarted := w.action(t, uuid.Nil, long, nil)

	for _, c := range []struct {
		name   string
		url    string
		orgCtx *uuid.UUID
		id     uuid.UUID
		want   int64
	}{
		{"platform, organization's finished action", env.Platform, nil, orgFinished, 0},
		{"platform, started platform action", env.Platform, nil, platformStarted, 0},
		{"worker, started action", env.Worker, &org, orgStarted, 0},
		{"platform, finished platform action", env.Platform, nil, platformFinished, 1},
		{"worker, finished action", env.Worker, &org, orgFinished, 1},
	} {
		if n := affected(t, c.url, c.orgCtx, "DELETE FROM action WHERE id = $1", c.id); n != c.want {
			t.Errorf("%s: deleted %d rows, want %d", c.name, n, c.want)
		}
	}
	if !w.exists(t, "action", orgStarted) || !w.exists(t, "action", platformStarted) {
		t.Fatal("want both started actions kept")
	}
}

// affected runs sql with args in one committed transaction of the role behind url, with paddock.org_id set to orgCtx
// when given, and returns the rows it affected.
func affected(t *testing.T, url string, orgCtx *uuid.UUID, sql string, args ...any) int64 {
	t.Helper()
	n, err := tryAffected(t, url, orgCtx, sql, args...)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// tryAffected is affected that returns the statement's error instead of failing the test.
func tryAffected(t *testing.T, url string, orgCtx *uuid.UUID, sql string, args ...any) (int64, error) {
	t.Helper()
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close(ctx) }()
	return inTx(t, conn, "", orgCtx, sql, args...)
}

// inTx runs sql with args in one committed transaction on conn, as role when given (SET LOCAL ROLE) and with
// paddock.org_id set to orgCtx when given, and returns the rows it affected or the statement's error.
func inTx(t *testing.T, conn *pgx.Conn, role string, orgCtx *uuid.UUID, sql string, args ...any) (int64, error) {
	t.Helper()
	ctx := context.Background()
	tx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if role != "" {
		if _, err := tx.Exec(ctx, "SET LOCAL ROLE "+pgx.Identifier{role}.Sanitize()); err != nil {
			t.Fatal(err)
		}
	}
	if orgCtx != nil {
		if _, err := tx.Exec(ctx, "SELECT set_config('paddock.org_id', $1, true)", orgCtx.String()); err != nil {
			t.Fatal(err)
		}
	}
	tag, err := tx.Exec(ctx, sql, args...)
	if err != nil {
		return 0, err
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	return tag.RowsAffected(), nil
}

// expectRefused runs sql on conn and fails t unless the database refuses it with check_violation.
func expectRefused(t *testing.T, conn *pgx.Conn, sql string, args ...any) {
	t.Helper()
	_, err := conn.Exec(context.Background(), sql, args...)
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "23514" {
		t.Errorf("%s: got %v, want check_violation", sql, err)
	}
}

// TestRetentionActionFinishedImmutable (ADR 0032 amendment 2026-10-31, migration 00082): no runtime role with UPDATE
// on action changes a finished action, so none can rewrite its params and outcome or move an organization's finished
// action into the platform pseudo-organization, where the platform role could delete it. Finishing a started action,
// as FinishAction and the outbox reaper do, keeps working for every role.
func TestRetentionActionFinishedImmutable(t *testing.T) {
	w := newRetentionWorld(t)
	env := pgtest.SharedPaddock(t)
	org, _ := w.orgWithDevice(t)
	long := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	const rewrite = `UPDATE action SET params = '{"rewritten":true}', outcome = 'failure' WHERE id = $1`
	const finish = `UPDATE action SET status = 'finished', outcome = 'success', finished_at = now() WHERE id = $1`

	for _, r := range []struct {
		role   string
		url    string
		orgCtx *uuid.UUID
	}{
		{"paddock_api", env.API, &org},
		{"paddock_platform", env.Platform, nil},
		{"paddock_relay", env.Relay, nil},
		{"paddock_worker", env.Worker, &org},
		{"paddock_compiler", env.Compiler, &org},
		{"paddock_revocation", env.Revocation, &org},
	} {
		t.Run(r.role, func(t *testing.T) {
			finished := w.action(t, org, long, at(long.Add(time.Minute)))
			if n := affected(t, r.url, r.orgCtx, rewrite, finished); n != 0 {
				t.Errorf("rewrote %d finished actions, want 0", n)
			}
			if n := affected(t, r.url, r.orgCtx, "UPDATE action SET status = 'started', outcome = NULL WHERE id = $1", finished); n != 0 {
				t.Errorf("reopened %d finished actions, want 0", n)
			}
			if got := countRows(t, w.super, `SELECT count(*) FROM action WHERE id = $1 AND organization_id = $2
				AND status = 'finished' AND outcome = 'success' AND params = '{}'`, finished, org); got != 1 {
				t.Error("want the finished action unchanged")
			}
			started := w.action(t, org, long, nil)
			if n := affected(t, r.url, r.orgCtx, finish, started); n != 1 {
				t.Errorf("finished %d started actions, want 1", n)
			}
		})
	}

	t.Run("moved into the platform pseudo-organization, then deleted", func(t *testing.T) {
		finished := w.action(t, org, long, at(long.Add(time.Minute)))
		for _, url := range []string{env.Platform, env.Relay} {
			if n := affected(t, url, nil, "UPDATE action SET organization_id = $2 WHERE id = $1", finished, uuid.Nil); n != 0 {
				t.Errorf("moved %d finished actions, want 0", n)
			}
		}
		if n := affected(t, env.Platform, nil, "DELETE FROM action WHERE id = $1", finished); n != 0 {
			t.Errorf("deleted %d actions, want 0", n)
		}
		if countRows(t, w.super, "SELECT count(*) FROM action WHERE id = $1 AND organization_id = $2", finished, org) != 1 {
			t.Fatal("want the organization's finished action kept in its organization")
		}
	})
}

// TestRetentionActionOrganizationImmutable (ADR 0032 amendment 2026-10-31, migrations 00083 and 00084): neither the
// platform role nor the relay role moves an organization's started action into another organization or the platform
// pseudo-organization, where it could be finished and deleted outside the organization's audit trail. A started
// platform action moves into an organization only while it is finished; moving it without finishing is refused, so the
// reaper never writes its event into an organization the use case did not finish it in.
func TestRetentionActionOrganizationImmutable(t *testing.T) {
	w := newRetentionWorld(t)
	env := pgtest.SharedPaddock(t)
	org, _ := w.orgWithDevice(t)
	other, _ := w.orgWithDevice(t)
	long := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	const move = "UPDATE action SET organization_id = $2 WHERE id = $1"
	const moveAndFinish = `UPDATE action SET organization_id = $2, status = 'finished', outcome = 'success',
		finished_at = now() WHERE id = $1`

	for _, r := range []struct {
		role string
		url  string
	}{
		{"paddock_platform", env.Platform},
		{"paddock_relay", env.Relay},
	} {
		for _, target := range []struct {
			name string
			id   uuid.UUID
		}{
			{"another organization", other},
			{"platform pseudo-organization", uuid.Nil},
		} {
			for _, sql := range []string{move, moveAndFinish} {
				started := w.action(t, org, long, nil)
				_, err := tryAffected(t, r.url, nil, sql, started, target.id)
				var pgErr *pgconn.PgError
				if !errors.As(err, &pgErr) || pgErr.Code != "23514" {
					t.Errorf("%s, into %s: got %v, want check_violation", r.role, target.name, err)
				}
				if countRows(t, w.super, "SELECT count(*) FROM action WHERE id = $1 AND organization_id = $2 AND status = 'started'",
					started, org) != 1 {
					t.Errorf("%s, into %s: want the started action kept in its organization", r.role, target.name)
				}
			}
		}
	}

	t.Run("a platform action moves into an organization only on finishing", func(t *testing.T) {
		for _, url := range []string{env.Platform, env.Relay} {
			started := w.action(t, uuid.Nil, long, nil)
			_, err := tryAffected(t, url, nil, move, started, org)
			var pgErr *pgconn.PgError
			if !errors.As(err, &pgErr) || pgErr.Code != "23514" {
				t.Errorf("moved a started platform action without finishing it: got %v, want check_violation", err)
			}
			if countRows(t, w.super, "SELECT count(*) FROM action WHERE id = $1 AND organization_id = $2 AND status = 'started'",
				started, uuid.Nil) != 1 {
				t.Error("want the started action kept in the platform pseudo-organization")
			}
			if n := affected(t, url, nil, moveAndFinish, started, org); n != 1 {
				t.Fatalf("finished %d pseudo-organization actions in the organization, want 1", n)
			}
			if countRows(t, w.super, "SELECT count(*) FROM action WHERE id = $1 AND organization_id = $2 AND status = 'finished'",
				started, org) != 1 {
				t.Fatal("want the action finished in the organization")
			}
		}
	})
}

// TestRetentionActionFinishTimeFromDatabase (ADR 0032 amendment 2026-10-31, migration 00084): a role that finishes a
// started organization action, or inserts a finished one, cannot backdate its finish time, so a retention round right
// afterwards keeps the row. The stored finish time is the written one, floored at the database's time and capped at five
// minutes after it: an application clock ahead of the database keeps its time, one behind it gets the database's.
func TestRetentionActionFinishTimeFromDatabase(t *testing.T) {
	w := newRetentionWorld(t)
	env := pgtest.SharedPaddock(t)
	org, _ := w.orgWithDevice(t)
	long := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	const finish = "UPDATE action SET status = 'finished', outcome = 'success', finished_at = $2 WHERE id = $1"
	const insert = `INSERT INTO action (id, organization_id, code, status, outcome, actor, correlation_id, started_at, finished_at)
		VALUES ($1, $3, 'test.retention', 'finished', 'success', '{"kind":"system"}', 'retention-test', clock_timestamp(), $2)`
	dbNow := func() time.Time {
		t.Helper()
		var at time.Time
		if err := w.super.QueryRow(context.Background(), "SELECT clock_timestamp()").Scan(&at); err != nil {
			t.Fatal(err)
		}
		return at
	}
	const window = 5 * time.Minute
	cases := []struct {
		name string
		// written returns the finish time the statement writes, given the database's time just before.
		written func(dbBefore time.Time) *time.Time
		// stored checks the stored finish time against the written one and the database's time around the statement.
		stored func(got time.Time, written *time.Time, before, after time.Time) bool
	}{
		{"backdated", func(time.Time) *time.Time { return at(time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)) },
			func(got time.Time, _ *time.Time, before, after time.Time) bool {
				return !got.Before(before) && !got.After(after)
			}},
		{"missing", func(time.Time) *time.Time { return nil },
			func(got time.Time, _ *time.Time, before, after time.Time) bool {
				return !got.Before(before) && !got.After(after)
			}},
		{"application clock behind", func(b time.Time) *time.Time { return at(b.Add(-time.Second)) },
			func(got time.Time, _ *time.Time, before, after time.Time) bool {
				return !got.Before(before) && !got.After(after)
			}},
		{"application clock ahead", func(b time.Time) *time.Time { return at(b.Add(2 * time.Minute)) },
			func(got time.Time, written *time.Time, _, _ time.Time) bool {
				d := got.Sub(*written)
				return d > -time.Millisecond && d < time.Millisecond
			}},
		{"application clock ahead beyond the cap", func(b time.Time) *time.Time { return at(b.Add(time.Hour)) },
			func(got time.Time, _ *time.Time, before, after time.Time) bool {
				return !got.Before(before.Add(window)) && !got.After(after.Add(window))
			}},
	}
	check := func(t *testing.T, id uuid.UUID, written *time.Time, before, after time.Time, ok func(time.Time, *time.Time, time.Time, time.Time) bool) {
		t.Helper()
		var finished time.Time
		if err := w.super.QueryRow(context.Background(), "SELECT finished_at FROM action WHERE id = $1", id).Scan(&finished); err != nil {
			t.Fatal(err)
		}
		if !ok(finished, written, before, after) {
			t.Fatalf("finished_at %s for written %v, database time %s to %s", finished, written, before, after)
		}
	}

	for _, r := range []struct {
		role string
		url  string
	}{
		{"paddock_platform", env.Platform},
		{"paddock_relay", env.Relay},
	} {
		for _, c := range cases {
			t.Run("finish/"+r.role+"/"+c.name, func(t *testing.T) {
				started := w.action(t, org, long, nil)
				before := dbNow()
				written := c.written(before)
				if n := affected(t, r.url, nil, finish, started, written); n != 1 {
					t.Fatalf("finished %d started actions, want 1", n)
				}
				check(t, started, written, before, dbNow(), c.stored)
			})
		}
	}
	for _, r := range []struct {
		role   string
		url    string
		orgCtx *uuid.UUID
	}{
		{"paddock_platform", env.Platform, nil},
		{"paddock_api", env.API, &org},
	} {
		for _, c := range cases {
			t.Run("insert/"+r.role+"/"+c.name, func(t *testing.T) {
				id := uuid.Must(uuid.NewV7())
				t.Cleanup(func() { _, _ = w.super.Exec(context.Background(), "DELETE FROM action WHERE id = $1", id) })
				before := dbNow()
				written := c.written(before)
				if n := affected(t, r.url, r.orgCtx, insert, id, written, org); n != 1 {
					t.Fatalf("inserted %d finished actions, want 1", n)
				}
				check(t, id, written, before, dbNow(), c.stored)
			})
		}
	}

	t.Run("retention round after a backdated finish", func(t *testing.T) {
		started := w.action(t, org, long, nil)
		if n := affected(t, env.Platform, nil, finish, started, time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)); n != 1 {
			t.Fatalf("finished %d started actions, want 1", n)
		}
		if n, err := w.retention.PurgeActions(systemCtx(org), time.Now()); err != nil || n != 0 {
			t.Fatalf("retention round purged %d (%v), want 0", n, err)
		}
		if !w.exists(t, "action", started) {
			t.Fatal("want the just finished action kept by the retention round")
		}
	})
}

// TestRetentionActionStartedUnchangeable (ADR 0032 amendment 2026-10-31, migration 00084): a started action changes
// only by finishing. Neither the platform role nor the relay role rewrites a started action's target, params, error code
// or finish time, which the outbox reaper would copy into the event it writes, nor reopens it by writing started again.
func TestRetentionActionStartedUnchangeable(t *testing.T) {
	w := newRetentionWorld(t)
	env := pgtest.SharedPaddock(t)
	org, _ := w.orgWithDevice(t)
	long := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, set := range []string{
		`target = '{"type":"organization","id":"rewritten"}'`,
		`params = '{"rewritten":true}'`,
		"error_code = 'rewritten'",
		"finished_at = clock_timestamp()",
		"status = 'started'",
	} {
		for _, r := range []struct {
			role string
			url  string
		}{
			{"paddock_platform", env.Platform},
			{"paddock_relay", env.Relay},
		} {
			started := w.action(t, org, long, nil)
			_, err := tryAffected(t, r.url, nil, "UPDATE action SET "+set+" WHERE id = $1", started)
			var pgErr *pgconn.PgError
			if !errors.As(err, &pgErr) || pgErr.Code != "23514" {
				t.Errorf("%s, %s: got %v, want check_violation", r.role, set, err)
			}
			if countRows(t, w.super, `SELECT count(*) FROM action WHERE id = $1 AND status = 'started' AND target IS NULL
				AND params = '{}' AND error_code IS NULL AND finished_at IS NULL`, started) != 1 {
				t.Errorf("%s, %s: want the started action unchanged", r.role, set)
			}
		}
	}
}

// TestRetentionActionInsertBounded (ADR 0032 amendment 2026-10-31, migration 00084): a started action is inserted
// without a finish time and with a start time within five minutes of the database's, so no role inserts an action the
// outbox reaper would take for a stuck one or one that carries a finish time; and the schema ties the finish time to the
// status even with the trigger off.
func TestRetentionActionInsertBounded(t *testing.T) {
	w := newRetentionWorld(t)
	env := pgtest.SharedPaddock(t)
	org, _ := w.orgWithDevice(t)
	const insert = `INSERT INTO action (id, organization_id, code, status, actor, correlation_id, started_at, finished_at)
		VALUES ($1, $2, 'test.retention', 'started', '{"kind":"system"}', 'retention-test', clock_timestamp() + $3::interval, $4)`
	for _, r := range []struct {
		role   string
		url    string
		orgCtx *uuid.UUID
	}{
		{"paddock_platform", env.Platform, nil},
		{"paddock_api", env.API, &org},
	} {
		for _, c := range []struct {
			name     string
			offset   string
			finished *time.Time
			accepted bool
		}{
			{"current", "0 seconds", nil, true},
			{"four minutes old", "-4 minutes", nil, true},
			{"four minutes ahead", "4 minutes", nil, true},
			{"six minutes old", "-6 minutes", nil, false},
			{"six minutes ahead", "6 minutes", nil, false},
			{"with a finish time", "0 seconds", at(time.Now()), false},
		} {
			t.Run(r.role+"/"+c.name, func(t *testing.T) {
				id := uuid.Must(uuid.NewV7())
				t.Cleanup(func() { _, _ = w.super.Exec(context.Background(), "DELETE FROM action WHERE id = $1", id) })
				n, err := tryAffected(t, r.url, r.orgCtx, insert, id, org, c.offset, c.finished)
				if c.accepted {
					if err != nil || n != 1 {
						t.Fatalf("inserted %d (%v), want 1", n, err)
					}
					return
				}
				var pgErr *pgconn.PgError
				if !errors.As(err, &pgErr) || pgErr.Code != "23514" {
					t.Fatalf("got %v, want check_violation", err)
				}
			})
		}
	}

	t.Run("finish time tied to the status", func(t *testing.T) {
		long := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
		for _, c := range []struct {
			status, outcome string
			finished        *time.Time
		}{
			{"started", "", at(long)},
			{"finished", "success", nil},
		} {
			id := uuid.Must(uuid.NewV7())
			t.Cleanup(func() { _, _ = w.super.Exec(context.Background(), "DELETE FROM action WHERE id = $1", id) })
			var outcome *string
			if c.outcome != "" {
				outcome = &c.outcome
			}
			err := pgtest.ExecUntriggered(context.Background(), w.super, `INSERT INTO action (id, organization_id, code, status,
				outcome, actor, correlation_id, started_at, finished_at)
				VALUES ($1, $2, 'test.retention', $3, $4, '{"kind":"system"}', 'retention-test', $5, $6)`,
				id, org, c.status, outcome, long, c.finished)
			var pgErr *pgconn.PgError
			if !errors.As(err, &pgErr) || pgErr.Code != "23514" || pgErr.ConstraintName != "action_finished_at_status" {
				t.Errorf("%s with finish time %v: got %v, want action_finished_at_status", c.status, c.finished, err)
			}
		}
	})
}

// TestRetentionActionIdentityImmutable (ADR 0032 amendment 2026-10-31, migration 00084): no role, the owner and the
// superuser included, rewrites an action's id, code, actor, source, correlation ID or start time — of a started action,
// alone or while finishing it, nor of a finished one. A rewritten start time would let the outbox reaper close a running
// action as unknown.
func TestRetentionActionIdentityImmutable(t *testing.T) {
	w := newRetentionWorld(t)
	env := pgtest.SharedPaddock(t)
	org, _ := w.orgWithDevice(t)
	long := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	const finish = ", status = 'finished', outcome = 'success'"
	rewrites := []struct{ column, set string }{
		{"id", "id = gen_random_uuid()"},
		{"code", "code = 'test.rewritten'"},
		{"actor", `actor = '{"kind":"rewritten"}'`},
		{"source", "source = 'api'"},
		{"correlation_id", "correlation_id = 'rewritten'"},
		{"started_at", "started_at = started_at - interval '1 hour'"},
	}
	unchanged := func(t *testing.T, id uuid.UUID, status string) {
		t.Helper()
		if countRows(t, w.super, `SELECT count(*) FROM action WHERE id = $1 AND code = 'test.retention'
			AND actor = '{"kind":"system"}' AND source IS NULL AND correlation_id = 'retention-test' AND started_at = $2
			AND status = $3`, id, long, status) != 1 {
			t.Errorf("want action %s unchanged", id)
		}
	}
	refused := func(t *testing.T, err error) {
		t.Helper()
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "23514" {
			t.Errorf("got %v, want check_violation", err)
		}
	}

	for _, c := range rewrites {
		t.Run(c.column, func(t *testing.T) {
			for _, r := range []struct {
				role string
				url  string
			}{
				{"paddock_platform", env.Platform},
				{"paddock_relay", env.Relay},
			} {
				for _, set := range []string{c.set, c.set + finish} {
					started := w.action(t, org, long, nil)
					_, err := tryAffected(t, r.url, nil, "UPDATE action SET "+set+" WHERE id = $1", started)
					refused(t, err)
					unchanged(t, started, "started")
				}
			}
			finished := w.action(t, org, long, at(long.Add(time.Minute)))
			_, err := w.super.Exec(context.Background(), "UPDATE action SET "+c.set+" WHERE id = $1", finished)
			refused(t, err)
			unchanged(t, finished, "finished")
		})
	}
}

// TestRetentionActionPoliciesBindEveryRole (ADR 0032 amendment 2026-10-31, migration 00083): the restrictive UPDATE
// and DELETE policies on action hold for every role, also one no migration names (M9's paddock_notifier, say). A
// temporary role with UPDATE and DELETE on action and an organization policy rewrites no finished action and deletes
// no started one; finishing a started action and deleting a finished one show that its grants work.
func TestRetentionActionPoliciesBindEveryRole(t *testing.T) {
	w := newRetentionWorld(t)
	org, _ := w.orgWithDevice(t)
	long := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	role := "paddock_test_unlisted_" + uuid.NewString()[:8]
	ident := pgx.Identifier{role}.Sanitize()
	w.exec(t, "CREATE ROLE "+ident+" NOLOGIN")
	t.Cleanup(func() { _, _ = w.super.Exec(context.Background(), "DROP ROLE "+ident) })
	w.exec(t, "GRANT USAGE ON SCHEMA public TO "+ident)
	t.Cleanup(func() { _, _ = w.super.Exec(context.Background(), "REVOKE ALL ON SCHEMA public FROM "+ident) })
	w.exec(t, "GRANT SELECT, UPDATE, DELETE ON action TO "+ident)
	t.Cleanup(func() { _, _ = w.super.Exec(context.Background(), "REVOKE ALL ON action FROM "+ident) })
	w.exec(t, "CREATE POLICY "+ident+" ON action TO "+ident+`
		USING (organization_id = current_setting('paddock.org_id')::uuid)
		WITH CHECK (organization_id = current_setting('paddock.org_id')::uuid)`)
	t.Cleanup(func() { _, _ = w.super.Exec(context.Background(), "DROP POLICY "+ident+" ON action") })

	run := func(sql string, id uuid.UUID) int64 {
		t.Helper()
		n, err := inTx(t, w.super, role, &org, sql, id)
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	finished := w.action(t, org, long, at(long.Add(time.Minute)))
	started := w.action(t, org, long, nil)
	if n := run(`UPDATE action SET params = '{"rewritten":true}', outcome = 'failure' WHERE id = $1`, finished); n != 0 {
		t.Errorf("rewrote %d finished actions, want 0", n)
	}
	if n := run("DELETE FROM action WHERE id = $1", started); n != 0 {
		t.Errorf("deleted %d started actions, want 0", n)
	}
	if n := run(`UPDATE action SET status = 'finished', outcome = 'success', finished_at = now() WHERE id = $1`, started); n != 1 {
		t.Errorf("finished %d started actions, want 1", n)
	}
	if n := run("DELETE FROM action WHERE id = $1", finished); n != 1 {
		t.Errorf("deleted %d finished actions, want 1", n)
	}
}

// TestRetentionPurgeNeverAheadOfIndex (ADR 0032 amendment 2026-10-31): every store kept by the audit index deletes
// only rows older than the start of the UTC month containing now − the index retention − 7 days, also when that
// instant lies in the previous month while now − the index retention does not, and never a row younger than an hour.
// A row older than now − the index retention but inside that month stays: the index, which drops whole months only,
// may still show its events.
func TestRetentionPurgeNeverAheadOfIndex(t *testing.T) {
	w := newRetentionWorld(t)
	stores := []struct {
		store, table string
		insert       func(t *testing.T, org, dev uuid.UUID, seq int64, at time.Time) uuid.UUID
		purge        func(context.Context, time.Time) (int64, error)
	}{
		{app.StoreAction, "action", func(t *testing.T, org, _ uuid.UUID, _ int64, at time.Time) uuid.UUID {
			return w.action(t, org, at.Add(-time.Hour), &at)
		}, w.retention.PurgeActions},
		{app.StoreDeviceCommand, "device_command", func(t *testing.T, org, dev uuid.UUID, _ int64, at time.Time) uuid.UUID {
			return w.command(t, org, dev, "succeeded", &at)
		}, w.retention.PurgeDeviceCommands},
		{app.StoreDeviceAlert, "device_alert", func(t *testing.T, org, _ uuid.UUID, _ int64, at time.Time) uuid.UUID {
			return w.alert(t, w.device(t, org), &at)
		}, w.retention.PurgeDeviceAlerts},
		{app.StoreDeviceEventGap, "device_event_gap", func(t *testing.T, org, dev uuid.UUID, seq int64, at time.Time) uuid.UUID {
			return w.gap(t, org, dev, seq*100, &at)
		}, w.retention.PurgeEventGaps},
	}
	clocks := []struct {
		name       string
		now, floor time.Time
	}{
		{"mid-month", indexNow, indexFloor},
		{"month boundary", time.Date(2026, 3, 1, 0, 3, 0, 0, time.UTC), time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)},
		{"month boundary within the margin", time.Date(2026, 3, 1, 0, 6, 45, 0, time.UTC), time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)},
		{"never within the last hour", time.Date(2026, 3, 1, 0, 30, 0, 0, time.UTC), time.Date(2026, 2, 28, 23, 30, 0, 0, time.UTC)},
	}
	for _, s := range stores {
		for _, c := range clocks {
			t.Run(s.store+"/"+c.name, func(t *testing.T) {
				org, dev := w.orgWithDevice(t)
				below := s.insert(t, org, dev, 1, c.floor.Add(-time.Minute))
				inMonth := s.insert(t, org, dev, 2, c.floor.Add(time.Minute))
				lagging := s.insert(t, org, dev, 3, c.now.Add(-indexPeriod-time.Minute))

				n, err := s.purge(systemCtx(org), c.now)
				if err != nil || n != 1 {
					t.Fatalf("purged %d (%v), want 1", n, err)
				}
				if w.exists(t, s.table, below) || !w.exists(t, s.table, inMonth) || !w.exists(t, s.table, lagging) {
					t.Fatal("want only the row before the index month deleted")
				}
				w.assertOneSuccess(t, org, s.store, 1, c.floor)
			})
		}
	}
}

// TestRetentionPurgeIndexRetentionTooShort: with an index retention below the bucket default (0 or 399 days) every
// pass kept by the index fails without deleting anything or recording an event.
func TestRetentionPurgeIndexRetentionTooShort(t *testing.T) {
	w := newRetentionWorld(t)
	org, dev := w.orgWithDevice(t)
	old := at(indexFloor.AddDate(-2, 0, 0))
	rows := map[string]uuid.UUID{
		"device_command": w.command(t, org, dev, "succeeded", old), "device_alert": w.alert(t, dev, old),
		"device_event_gap": w.gap(t, org, dev, 1, old), "action": w.action(t, org, old.Add(-time.Hour), old),
	}
	platform := w.action(t, uuid.Nil, old.Add(-time.Hour), old)
	for _, days := range []int{0, 399} {
		w.retention.SetIndexDays(days)
		for name, purge := range map[string]func(context.Context, time.Time) (int64, error){
			app.StoreDeviceCommand: w.retention.PurgeDeviceCommands, app.StoreDeviceAlert: w.retention.PurgeDeviceAlerts,
			app.StoreDeviceEventGap: w.retention.PurgeEventGaps, app.StoreAction: w.retention.PurgeActions,
		} {
			if n, err := purge(systemCtx(org), indexNow); err == nil || n != 0 {
				t.Fatalf("%d days, %s: purged %d (%v), want an error", days, name, n, err)
			}
		}
		if n, err := w.retention.PurgePlatformActions(systemCtx(uuid.Nil), indexNow); err == nil || n != 0 {
			t.Fatalf("%d days, platform actions: purged %d (%v), want an error", days, n, err)
		}
	}
	for table, id := range rows {
		if !w.exists(t, table, id) {
			t.Fatalf("the %s row was deleted", table)
		}
	}
	if !w.exists(t, "action", platform) {
		t.Fatal("the platform action was deleted")
	}
	for _, store := range []string{app.StoreDeviceCommand, app.StoreDeviceAlert, app.StoreDeviceEventGap, app.StoreAction} {
		if events := w.purged(t, org, store); len(events) != 0 {
			t.Fatalf("events %+v of %s, want none", events, store)
		}
	}
}

// TestRetentionPurgeControlPlaneIsolation: a pass deletes only the context's organization's rows and records its event
// there; another organization's expired rows and events stay untouched.
func TestRetentionPurgeControlPlaneIsolation(t *testing.T) {
	w := newRetentionWorld(t)
	now := indexNow
	old := indexFloor.Add(-time.Minute)
	orgA, devA := w.orgWithDevice(t)
	orgB, devB := w.orgWithDevice(t)
	cmdA, cmdB := w.command(t, orgA, devA, "succeeded", &old), w.command(t, orgB, devB, "succeeded", &old)
	alertB, gapB := uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())
	w.exec(t, `INSERT INTO device_alert (id, organization_id, device_id, kind, raised_at, cleared_at)
		VALUES ($1, $2, $3, 'stale_warning', $4, $4)`, alertB, orgB, devB, old)
	w.exec(t, `INSERT INTO device_event_gap (id, organization_id, device_id, from_seq, to_seq, first_seen_at,
		first_seen_last_seq, filled_at) VALUES ($1, $2, $3, 1, 2, $4, 3, $4)`, gapB, orgB, devB, old)

	actionB := w.action(t, orgB, old.Add(-time.Hour), &old)
	ctx := systemCtx(orgA)
	for name, purge := range map[string]func(context.Context, time.Time) (int64, error){
		app.StoreDeviceCommand: w.retention.PurgeDeviceCommands, app.StoreDeviceAlert: w.retention.PurgeDeviceAlerts,
		app.StoreDeviceEventGap: w.retention.PurgeEventGaps, app.StoreAction: w.retention.PurgeActions,
	} {
		if _, err := purge(ctx, now); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
	if w.exists(t, "device_command", cmdA) {
		t.Fatal("organization A's expired command is still there")
	}
	if !w.exists(t, "device_command", cmdB) || !w.exists(t, "device_alert", alertB) || !w.exists(t, "device_event_gap", gapB) ||
		!w.exists(t, "action", actionB) {
		t.Fatal("organization B's rows were deleted by organization A's pass")
	}
	for _, store := range []string{app.StoreDeviceCommand, app.StoreDeviceAlert, app.StoreDeviceEventGap, app.StoreAction} {
		if events := w.purged(t, orgB, store); len(events) != 0 {
			t.Fatalf("organization B has events %+v of %s", events, store)
		}
	}
}

// TestRetentionPurgeControlPlaneSystemOnly: only the worker's system principal may purge these stores.
func TestRetentionPurgeControlPlaneSystemOnly(t *testing.T) {
	w := newRetentionWorld(t)
	now := indexNow
	org, dev := w.orgWithDevice(t)
	cmd := w.command(t, org, dev, "succeeded", at(indexFloor.Add(-time.Minute)))
	admin := principal.With(context.Background(), principal.Principal{Kind: principal.KindAdmin, ID: uuid.Must(uuid.NewV7()),
		Role: principal.RoleOrgAdmin, OrganizationID: org})
	platformAdmin := principal.With(context.Background(), principal.Principal{Kind: principal.KindPlatformAdmin, ID: uuid.Must(uuid.NewV7())})
	if _, err := w.retention.PurgePlatformActions(platformAdmin, now); !errors.Is(err, problem.Unauthenticated) {
		t.Fatalf("platform actions by a platform administrator: %v, want unauthenticated", err)
	}
	for name, purge := range map[string]func(context.Context, time.Time) (int64, error){
		app.StoreDeviceCommand: w.retention.PurgeDeviceCommands, app.StoreDeviceAlert: w.retention.PurgeDeviceAlerts,
		app.StoreDeviceEventGap: w.retention.PurgeEventGaps, app.StoreAction: w.retention.PurgeActions,
	} {
		if _, err := purge(admin, now); !errors.Is(err, problem.Unauthenticated) {
			t.Fatalf("%s by an admin: %v, want unauthenticated", name, err)
		}
	}
	if !w.exists(t, "device_command", cmd) {
		t.Fatal("an admin's purge deleted a command")
	}
}
