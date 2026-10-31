package auditwriter_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/phischl/paddock-mdm/server/internal/adapters/auditpg/auditstore"
	"github.com/phischl/paddock-mdm/server/internal/auditwriter"
	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/pgtest"
)

// Every test of this file uses its own month of 2001, far behind any cutoff, because the shared audit database keeps
// the partitions of every test of the package.

// writeBackdated writes events that occurred in month through the writer, then backdates their recorded_at to their
// occurred_at, as if the writer had recorded them then.
func (s stack) writeBackdated(t *testing.T, org uuid.UUID, month time.Time, n int) []audit.Event {
	t.Helper()
	ctx := context.Background()
	events := make([]audit.Event, n)
	ids := make([]uuid.UUID, n)
	for i := range events {
		events[i] = event(org, month.AddDate(0, 0, 4+i), audit.CodeDeviceGroupCreated)
		ids[i] = events[i].EventID
	}
	if written, err := s.writer.WriteBatch(ctx, events); err != nil || written != n {
		t.Fatalf("WriteBatch = %d, %v", written, err)
	}
	if _, err := s.super.Exec(ctx, "UPDATE audit_event SET recorded_at = occurred_at WHERE event_id = ANY($1)", ids); err != nil {
		t.Fatal(err)
	}
	return events
}

func (s stack) partitionExists(t *testing.T, name string) bool {
	t.Helper()
	var exists bool
	if err := s.super.QueryRow(context.Background(), "SELECT to_regclass($1) IS NOT NULL", name).Scan(&exists); err != nil {
		t.Fatal(err)
	}
	return exists
}

// purgedEvents returns the retention.purged events recorded for partition, from the index.
func (s stack) purgedEvents(t *testing.T, partition string) []purgedRow {
	t.Helper()
	rows, err := s.super.Query(context.Background(),
		`SELECT event_id, organization_id, outcome, params, object_key FROM audit_event
		 WHERE code = $1 AND params->>'store' = 'audit_index' AND params->>'partition' = $2`,
		string(audit.CodeRetentionPurged), partition)
	if err != nil {
		t.Fatal(err)
	}
	out, err := pgx.CollectRows(rows, pgx.RowToStructByPos[purgedRow])
	if err != nil {
		t.Fatal(err)
	}
	return out
}

type purgedRow struct {
	EventID   uuid.UUID
	Org       uuid.UUID
	Outcome   string
	Params    json.RawMessage
	ObjectKey string
}

func partitionOf(t *testing.T, report auditwriter.PurgeReport, name string) auditwriter.PurgedPartition {
	t.Helper()
	for _, p := range report.Partitions {
		if p.Name == name {
			return p
		}
	}
	t.Fatalf("partition %s not in the report: %+v", name, report.Partitions)
	return auditwriter.PurgedPartition{}
}

func month(year int, m time.Month) time.Time { return time.Date(year, m, 1, 0, 0, 0, 0, time.UTC) }

// TestPurgerDropsExpiredPartition (PDK-140): a partition whose events were all recorded before the cutoff is dropped
// and the drop is recorded as retention.purged in the platform pseudo-organization, in the index and in WORM; a
// partition with one event recorded after the cutoff is kept with the reason; the dry run drops nothing.
func TestPurgerDropsExpiredPartition(t *testing.T) {
	s := newStack(t)
	ctx := context.Background()
	org := uuid.Must(uuid.NewV7())
	expired, late := month(2001, time.January), month(2001, time.February)
	s.writeBackdated(t, org, expired, 2)
	s.writeBackdated(t, org, late, 1)
	lateEvent := event(org, late.AddDate(0, 0, 20), audit.CodeDeviceGroupUpdated)
	if _, err := s.writer.WriteBatch(ctx, []audit.Event{lateEvent}); err != nil {
		t.Fatal(err)
	}
	purger := auditwriter.NewPurger(s.pool, s.writer, 400)

	dry, err := purger.Run(ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	if p := partitionOf(t, dry, "audit_event_2001_01"); !p.Due || !p.Dropped || p.Events != 2 {
		t.Errorf("dry run, expired partition = %+v, want due, would drop 2 events", p)
	}
	if p := partitionOf(t, dry, "audit_event_2001_02"); !p.Due || p.Dropped || p.Reason != auditwriter.PurgeReasonLateEvents {
		t.Errorf("dry run, late partition = %+v, want kept for late events", p)
	}
	if !s.partitionExists(t, "audit_event_2001_01") || len(s.purgedEvents(t, "audit_event_2001_01")) != 0 {
		t.Fatal("the dry run dropped or recorded something")
	}

	now := time.Now()
	report, err := purger.Run(ctx, false)
	if err != nil {
		t.Fatal(err)
	}
	if want := now.UTC().AddDate(0, 0, -400); report.Cutoff.Sub(want).Abs() > time.Minute {
		t.Errorf("cutoff = %s, want the database's now − 400 days, about %s", report.Cutoff, want)
	}
	dropped := partitionOf(t, report, "audit_event_2001_01")
	if !dropped.Dropped || dropped.Events != 2 || dropped.Reason != auditwriter.PurgeReasonDropped {
		t.Fatalf("expired partition = %+v, want dropped with 2 events", dropped)
	}
	t.Logf("dropped %s: %d events (cutoff %s)", dropped.Name, dropped.Events, report.Cutoff.Format(time.RFC3339))
	kept := partitionOf(t, report, "audit_event_2001_02")
	if kept.Dropped || kept.Events != 2 || kept.Reason != auditwriter.PurgeReasonLateEvents {
		t.Errorf("late partition = %+v, want kept with 2 events and reason %q", kept, auditwriter.PurgeReasonLateEvents)
	}
	if !report.Complete() {
		t.Error("report not complete")
	}
	if s.partitionExists(t, "audit_event_2001_01") || !s.partitionExists(t, "audit_event_2001_02") {
		t.Fatal("wrong partitions dropped")
	}

	recorded := s.purgedEvents(t, "audit_event_2001_01")
	if len(recorded) != 1 {
		t.Fatalf("%d retention.purged events for the dropped partition, want 1", len(recorded))
	}
	ev := recorded[0]
	var params map[string]any
	if err := json.Unmarshal(ev.Params, &params); err != nil {
		t.Fatal(err)
	}
	if ev.Org != audit.PlatformOrganizationID || ev.Outcome != string(audit.OutcomeSuccess) || params["deleted"] != float64(2) {
		t.Errorf("retention.purged = %+v %v", ev, params)
	}
	// The recorded cutoff is the one the drop's own transaction computed, a moment after the report's.
	if cutoff, err := time.Parse(time.RFC3339Nano, fmt.Sprint(params["cutoff"])); err != nil ||
		cutoff.Before(report.Cutoff) || cutoff.Sub(report.Cutoff) > time.Minute {
		t.Errorf("recorded cutoff %v, want just after the report's %s (%v)", params["cutoff"], report.Cutoff, err)
	}
	body, err := s.store.Get(ctx, ev.ObjectKey)
	if err != nil {
		t.Fatalf("WORM object of retention.purged: %v", err)
	}
	worm, err := auditwriter.DecodeObject(body)
	if err != nil {
		t.Fatal(err)
	}
	if len(worm) != 1 || worm[0].EventID != ev.EventID || worm[0].Code != audit.CodeRetentionPurged ||
		worm[0].Actor.ID != "audit-writer" || worm[0].Source != audit.SourceSystem || worm[0].Params["partition"] != "audit_event_2001_01" {
		t.Errorf("WORM object = %+v", worm)
	}

	// The purge is idempotent: the next night finds nothing more to drop and records nothing again.
	if _, err := purger.Run(ctx, false); err != nil {
		t.Fatal(err)
	}
	if n := len(s.purgedEvents(t, "audit_event_2001_01")); n != 1 {
		t.Errorf("%d retention.purged events after a second run, want 1", n)
	}
	if n := len(s.purgedEvents(t, "audit_event_2001_02")); n != 0 {
		t.Errorf("%d retention.purged events for the kept partition, want 0", n)
	}
}

// TestPurgerMonthBoundary: the cutoff is the database's now − index retention. A partition whose month ends after it
// is kept as not due; with one retention day less, the month ends before the cutoff and the partition is dropped.
func TestPurgerMonthBoundary(t *testing.T) {
	s := newStack(t)
	ctx := context.Background()
	m := month(2001, time.March)
	s.writeBackdated(t, uuid.Must(uuid.NewV7()), m, 1)
	days, sinceMidnight := retentionReaching(t, s, m.AddDate(0, 1, 0))

	report, err := auditwriter.NewPurger(s.pool, s.writer, days+1).Run(ctx, false)
	if err != nil {
		t.Fatal(err)
	}
	if p := partitionOf(t, report, "audit_event_2001_03"); p.Due || p.Dropped || p.Reason != auditwriter.PurgeReasonNotDue {
		t.Errorf("month ending %s after the cutoff = %+v, want kept as not due", 24*time.Hour-sinceMidnight, p)
	}
	if !s.partitionExists(t, "audit_event_2001_03") {
		t.Fatal("partition ending after the cutoff dropped")
	}
	report, err = auditwriter.NewPurger(s.pool, s.writer, days).Run(ctx, false)
	if err != nil {
		t.Fatal(err)
	}
	if p := partitionOf(t, report, "audit_event_2001_03"); !p.Dropped || p.Events != 1 {
		t.Errorf("month ending %s before the cutoff = %+v, want dropped", sinceMidnight, p)
	}
}

// retentionReaching returns the whole days from end to the database's now and the time of day of that now (UTC), so
// that now − days is that time of day after end and now − (days+1) is before it. It skips the test within a minute of
// midnight UTC, where the few milliseconds until the purge reads its own now() could cross the day.
func retentionReaching(t *testing.T, s stack, end time.Time) (days int, sinceMidnight time.Duration) {
	t.Helper()
	var now time.Time
	if err := s.super.QueryRow(context.Background(), "SELECT now()").Scan(&now); err != nil {
		t.Fatal(err)
	}
	since := now.Sub(end)
	sinceMidnight = since % (24 * time.Hour)
	if sinceMidnight < time.Minute || sinceMidnight > 24*time.Hour-time.Minute {
		t.Skip("too close to midnight UTC for a deterministic month boundary")
	}
	return int(since / (24 * time.Hour)), sinceMidnight
}

// TestPurgerLockTimeout: a purge that cannot lock the partition within lock_timeout keeps it with reason
// lock_timeout, records nothing and reports an incomplete run; the next run drops it.
func TestPurgerLockTimeout(t *testing.T) {
	s := newStack(t)
	ctx := context.Background()
	s.writeBackdated(t, uuid.Must(uuid.NewV7()), month(2001, time.April), 1)
	reader := otherSession(t)
	tx, err := reader.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, "SELECT count(*) FROM audit_event_2001_04"); err != nil {
		t.Fatal(err)
	}
	purger := auditwriter.NewPurger(s.pool, s.writer, 400)

	start := time.Now()
	report, err := purger.Run(ctx, false)
	if err != nil {
		t.Fatal(err)
	}
	if took := time.Since(start); took < 4*time.Second || took > 30*time.Second {
		t.Errorf("run took %s, want about the 5 s lock_timeout", took)
	}
	if p := partitionOf(t, report, "audit_event_2001_04"); p.Dropped || p.Failed || p.Reason != auditwriter.PurgeReasonLockTimeout {
		t.Errorf("locked partition = %+v, want kept with reason lock_timeout", p)
	}
	if report.Complete() {
		t.Error("a run with a lock timeout reported complete")
	}
	if !s.partitionExists(t, "audit_event_2001_04") || len(s.purgedEvents(t, "audit_event_2001_04")) != 0 {
		t.Fatal("locked partition dropped or recorded")
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	report, err = purger.Run(ctx, false)
	if err != nil {
		t.Fatal(err)
	}
	if p := partitionOf(t, report, "audit_event_2001_04"); !p.Dropped {
		t.Errorf("retried partition = %+v, want dropped", p)
	}
}

// TestPurgerKeepsEventCommittedDuringPurge (regression): an event of the partition's month that a writer commits
// while the purge waits for its lock is counted, so the partition is kept instead of dropping an event recorded within
// the retention.
func TestPurgerKeepsEventCommittedDuringPurge(t *testing.T) {
	s := newStack(t)
	ctx := context.Background()
	org := uuid.Must(uuid.NewV7())
	m := month(2001, time.May)
	s.writeBackdated(t, org, m, 2)
	inserter := otherSession(t)
	tx, err := inserter.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO audit_event (event_id, organization_id, occurred_at, recorded_at, code, outcome, source, actor, params,
		                          correlation_id, object_key, commit_seq)
		 VALUES ($1, $2, $3, now(), 'device_group.created', 'success', 'portal', '{}', '{}', 'late', 'late', 3)`,
		uuid.Must(uuid.NewV7()), org, m.AddDate(0, 0, 20)); err != nil {
		t.Fatal(err)
	}
	purger := auditwriter.NewPurger(s.pool, s.writer, 400)
	type result struct {
		report auditwriter.PurgeReport
		err    error
	}
	done := make(chan result, 1)
	go func() {
		r, err := purger.Run(ctx, false)
		done <- result{r, err}
	}()
	deadline := time.Now().Add(4 * time.Second)
	for s.count(t, `SELECT count(*) FROM pg_stat_activity WHERE wait_event_type = 'Lock' AND query LIKE '%audit_purge_partition%'`) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the purge never waited for the inserting transaction")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	r := <-done
	if r.err != nil {
		t.Fatal(r.err)
	}
	if p := partitionOf(t, r.report, "audit_event_2001_05"); p.Dropped || p.Events != 3 || p.Reason != auditwriter.PurgeReasonLateEvents {
		t.Errorf("partition = %+v, want kept with 3 events for late events", p)
	}
	if !s.partitionExists(t, "audit_event_2001_05") {
		t.Fatal("partition with an event committed during the purge dropped")
	}
}

// TestPurgerFailedDropIsRecorded: a drop that fails records retention.purged with outcome failure and error_code
// purge_failed and makes Run fail.
func TestPurgerFailedDropIsRecorded(t *testing.T) {
	s := newStack(t)
	ctx := context.Background()
	s.writeBackdated(t, uuid.Must(uuid.NewV7()), month(2001, time.June), 1)
	if _, err := s.super.Exec(ctx, "REVOKE EXECUTE ON FUNCTION audit_purge_partition(date, integer) FROM paddock_audit_writer"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := s.super.Exec(context.Background(), "GRANT EXECUTE ON FUNCTION audit_purge_partition(date, integer) TO paddock_audit_writer"); err != nil {
			t.Error(err)
		}
	})
	report, err := auditwriter.NewPurger(s.pool, s.writer, 400).Run(ctx, false)
	if err == nil {
		t.Fatal("Run succeeded although the drop failed")
	}
	if p := partitionOf(t, report, "audit_event_2001_06"); p.Dropped || !p.Failed {
		t.Errorf("partition = %+v, want failed", p)
	}
	recorded := s.purgedEvents(t, "audit_event_2001_06")
	if len(recorded) != 1 || recorded[0].Outcome != string(audit.OutcomeFailure) {
		t.Fatalf("recorded = %+v, want one failure", recorded)
	}
	var params map[string]any
	if err := json.Unmarshal(recorded[0].Params, &params); err != nil {
		t.Fatal(err)
	}
	if params["error_code"] != "purge_failed" || params["deleted"] != float64(0) {
		t.Errorf("params = %v", params)
	}
}

// TestPurgerLocked: while another replica holds the purge lock, Run returns ErrPurgeLocked; a dry run still reports.
func TestPurgerLocked(t *testing.T) {
	s := newStack(t)
	ctx := context.Background()
	other := otherSession(t)
	if _, err := other.Exec(ctx, "SELECT pg_advisory_lock(hashtext('audit-purge'))"); err != nil {
		t.Fatal(err)
	}
	purger := auditwriter.NewPurger(s.pool, s.writer, 400)
	if _, err := purger.Run(ctx, false); !errors.Is(err, auditwriter.ErrPurgeLocked) {
		t.Errorf("Run = %v, want ErrPurgeLocked", err)
	}
	if _, err := purger.Run(ctx, true); err != nil {
		t.Errorf("dry run = %v", err)
	}
	if _, err := other.Exec(ctx, "SELECT pg_advisory_unlock(hashtext('audit-purge'))"); err != nil {
		t.Fatal(err)
	}
	if _, err := purger.Run(ctx, false); err != nil {
		t.Errorf("Run after unlock = %v", err)
	}
}

// TestPurgerRefusesIndexRetentionBelowWORM: the index is never purged ahead of the WORM retention.
func TestPurgerRefusesIndexRetentionBelowWORM(t *testing.T) {
	s := newStack(t)
	if _, err := auditwriter.NewPurger(s.pool, s.writer, 399).Run(context.Background(), false); err == nil {
		t.Fatal("index retention below the WORM retention accepted")
	}
}

// TestWriterHasNoDeleteOnAuditEvent: the purge migration grants only EXECUTE on audit_purge_partition; the writer
// role still cannot delete or truncate index rows.
func TestWriterHasNoDeleteOnAuditEvent(t *testing.T) {
	s := newStack(t)
	for _, privilege := range []string{"DELETE", "TRUNCATE", "UPDATE"} {
		var has bool
		if err := s.super.QueryRow(context.Background(),
			"SELECT has_table_privilege('paddock_audit_writer', 'audit_event', $1)", privilege).Scan(&has); err != nil {
			t.Fatal(err)
		}
		if has {
			t.Errorf("paddock_audit_writer has %s on audit_event", privilege)
		}
	}
	var canPurge bool
	if err := s.super.QueryRow(context.Background(),
		"SELECT has_function_privilege('paddock_audit_writer', 'audit_purge_partition(date, integer)', 'EXECUTE')").Scan(&canPurge); err != nil {
		t.Fatal(err)
	}
	if !canPurge {
		t.Error("paddock_audit_writer cannot execute audit_purge_partition")
	}
}

// TestPurgePartitionRefusesDaysWithinRetention (PDK-140 review): the writer role calling audit_purge_partition
// directly cannot drop a partition with a retention below the 400-day WORM retention, nor with none; with 400 days,
// it can.
func TestPurgePartitionRefusesDaysWithinRetention(t *testing.T) {
	s := newStack(t)
	ctx := context.Background()
	m := month(2001, time.July)
	s.writeBackdated(t, uuid.Must(uuid.NewV7()), m, 1)
	conn := writerSession(t)
	purge := func(days *int32) (auditstore.PurgeAuditPartitionRow, error) {
		var row auditstore.PurgeAuditPartitionRow
		err := conn.QueryRow(ctx, "SELECT dropped, events, reason FROM audit_purge_partition($1, $2)", m, days).
			Scan(&row.Dropped, &row.Events, &row.Reason)
		return row, err
	}
	for name, days := range map[string]*int32{
		"none":     nil,
		"0 days":   new(int32(0)),
		"399 days": new(int32(399)),
		"negative": new(int32(-36500)),
	} {
		if _, err := purge(days); err == nil || !strings.Contains(err.Error(), "below the minimum retention of 400 days") {
			t.Errorf("%s: err = %v, want the retention floor", name, err)
		}
		if !s.partitionExists(t, "audit_event_2001_07") {
			t.Fatalf("%s dropped the partition", name)
		}
	}
	row, err := purge(new(int32(auditwriter.MinRetentionDays)))
	if err != nil || !row.Dropped || row.Events != 1 {
		t.Fatalf("400 days = %+v, %v, want dropped with 1 event", row, err)
	}
}

// TestPurgePartitionFloorMatchesMinRetentionDays guards against drift between the database floor of
// audit_purge_partition and auditwriter.MinRetentionDays.
func TestPurgePartitionFloorMatchesMinRetentionDays(t *testing.T) {
	s := newStack(t)
	var def string
	if err := s.super.QueryRow(context.Background(),
		"SELECT pg_get_functiondef('public.audit_purge_partition(date, integer)'::regprocedure)").Scan(&def); err != nil {
		t.Fatal(err)
	}
	if want := fmt.Sprintf("p_days < %d", auditwriter.MinRetentionDays); !strings.Contains(def, want) {
		t.Errorf("audit_purge_partition has no floor %q:\n%s", want, def)
	}
}

// TestPurgePartitionIgnoresSessionTimeZone (PDK-140 review): the month decision of audit_purge_partition is the same
// in a caller session with another TimeZone as in UTC. Each call runs in a rolled-back transaction, so the partition
// stays for the next one.
func TestPurgePartitionIgnoresSessionTimeZone(t *testing.T) {
	s := newStack(t)
	ctx := context.Background()
	m := month(2002, time.January)
	s.writeBackdated(t, uuid.Must(uuid.NewV7()), m, 1)
	days, _ := retentionReaching(t, s, m.AddDate(0, 1, 0))
	conn := writerSession(t)
	decide := func(tz string, days int) (dropped bool, reason string) {
		tx, err := conn.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		if _, err := tx.Exec(ctx, "SELECT set_config('TimeZone', $1, true)", tz); err != nil {
			t.Fatal(err)
		}
		if err := tx.QueryRow(ctx, "SELECT dropped, reason FROM audit_purge_partition($1, $2)", m, days).
			Scan(&dropped, &reason); err != nil {
			t.Fatal(err)
		}
		return dropped, reason
	}
	// With days the cutoff is up to a day after the month's end, with days+1 up to a day before it; UTC−12 and UTC+14
	// shift a month end taken in the session's zone across one of the two for every time of day.
	for _, d := range []int{days, days + 1} {
		wantDropped, wantReason := decide("UTC", d)
		if wantDropped != (d == days) {
			t.Fatalf("UTC, %d days: dropped = %v (%s)", d, wantDropped, wantReason)
		}
		for _, tz := range []string{"Etc/GMT+12", "Pacific/Kiritimati", "Europe/Berlin"} {
			if dropped, reason := decide(tz, d); dropped != wantDropped || reason != wantReason {
				t.Errorf("%s, %d days: %v %q, want %v %q as in UTC", tz, d, dropped, reason, wantDropped, wantReason)
			}
		}
	}
}

// TestPurgePartitionExecuteGrantees: besides its owner, only paddock_audit_writer, the role that purges, may execute
// audit_purge_partition.
func TestPurgePartitionExecuteGrantees(t *testing.T) {
	s := newStack(t)
	rows, err := s.super.Query(context.Background(),
		`SELECT CASE WHEN a.grantee = 0 THEN 'PUBLIC' ELSE a.grantee::regrole::text END
		 FROM pg_proc p, aclexplode(p.proacl) a
		 WHERE p.oid = 'public.audit_purge_partition(date, integer)'::regprocedure
		   AND a.privilege_type = 'EXECUTE' AND a.grantee <> p.proowner`)
	if err != nil {
		t.Fatal(err)
	}
	grantees, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		t.Fatal(err)
	}
	if len(grantees) != 1 || grantees[0] != "paddock_audit_writer" {
		t.Errorf("EXECUTE grantees besides the owner = %v, want [paddock_audit_writer]", grantees)
	}
}

// TestPurgePartitionIgnoresTemporaryShadow (PDK-140 review): a temporary table of the writer's session named like a
// partition is never resolved by the SECURITY DEFINER function. The writer has no TEMPORARY privilege today; the test
// grants it, so the function's own search_path stays covered if that ever changes.
func TestPurgePartitionIgnoresTemporaryShadow(t *testing.T) {
	s := newStack(t)
	ctx := context.Background()
	if _, err := s.super.Exec(ctx, "GRANT TEMPORARY ON DATABASE paddock_audit TO paddock_audit_writer"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := s.super.Exec(context.Background(), "REVOKE TEMPORARY ON DATABASE paddock_audit FROM paddock_audit_writer"); err != nil {
			t.Error(err)
		}
	})
	if s.partitionExists(t, "audit_event_2001_08") {
		t.Fatal("audit_event_2001_08 exists; this test needs the month without a partition")
	}
	var row auditstore.PurgeAuditPartitionRow
	conn := writerSession(t)
	if _, err := conn.Exec(ctx, "CREATE TEMPORARY TABLE audit_event_2001_08 (recorded_at timestamptz)"); err != nil {
		t.Fatal(err)
	}
	if err := conn.QueryRow(ctx, "SELECT dropped, events, reason FROM audit_purge_partition($1, $2)",
		month(2001, time.August), auditwriter.MinRetentionDays).Scan(&row.Dropped, &row.Events, &row.Reason); err != nil {
		t.Fatal(err)
	}
	if row.Dropped || row.Reason != "no such partition" {
		t.Errorf("purge with a temporary shadow = %+v, want no such partition", row)
	}
	var exists bool
	if err := conn.QueryRow(ctx, "SELECT to_regclass('pg_temp.audit_event_2001_08') IS NOT NULL").Scan(&exists); err != nil || !exists {
		t.Errorf("temporary table gone (%v)", err)
	}
}

// TestPurgerRecordsDropWithUnknownCommitOutcome (PDK-140 review): when the purge transaction of a partition returns
// an error or is cancelled although its COMMIT went through, the purger finds the dropped relation gone and records
// the drop as retention.purged success, without a deleted count, instead of a failure or nothing. That holds also when
// the writer already created a partition of the same name again for a late event ("recreated").
func TestPurgerRecordsDropWithUnknownCommitOutcome(t *testing.T) {
	for name, m := range map[string]time.Time{
		"error": month(2001, time.September), "cancelled": month(2001, time.October), "recreated": month(2001, time.December),
	} {
		t.Run(name, func(t *testing.T) {
			s := newStack(t)
			org := uuid.Must(uuid.NewV7())
			s.writeBackdated(t, org, m, 1)
			partition := "audit_event_" + m.Format("2006_01")
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			purger := auditwriter.NewPurger(s.pool, s.writer, 400)
			auditwriter.SetPurgeCommitted(purger, func(_ context.Context, part string, err error) error {
				if part != partition || err != nil || s.partitionExists(t, partition) {
					return err
				}
				switch name {
				case "cancelled":
					cancel()
					return context.Canceled
				case "recreated":
					late := event(org, m.AddDate(0, 0, 20), audit.CodeDeviceGroupUpdated)
					if _, err := s.writer.WriteBatch(context.Background(), []audit.Event{late}); err != nil {
						t.Fatal(err)
					}
				}
				return errors.New("unexpected EOF")
			})

			report, err := purger.Run(ctx, false)
			if name != "cancelled" && err != nil {
				t.Fatalf("Run = %v, want nil", err)
			}
			if p := partitionOf(t, report, partition); !p.Dropped || p.Failed || p.Reason != auditwriter.PurgeReasonDropped {
				t.Errorf("partition = %+v, want dropped", p)
			}
			if exists := s.partitionExists(t, partition); exists != (name == "recreated") {
				t.Fatalf("partition exists = %v after the purge", exists)
			}
			recorded := s.purgedEvents(t, partition)
			if len(recorded) != 1 || recorded[0].Outcome != string(audit.OutcomeSuccess) {
				t.Fatalf("recorded = %+v, want one success", recorded)
			}
			var params map[string]any
			if err := json.Unmarshal(recorded[0].Params, &params); err != nil {
				t.Fatal(err)
			}
			if _, ok := params["deleted"]; ok || params["partition"] != partition {
				t.Errorf("params = %v, want the partition and no deleted count", params)
			}
		})
	}
}

// TestPurgerRecordsNoDropOfPartitionGoneBeforehand (PDK-140 review): a partition that someone else dropped before its
// purge transaction, which then fails for an unrelated reason, is recorded as a failed purge, never as a drop.
func TestPurgerRecordsNoDropOfPartitionGoneBeforehand(t *testing.T) {
	s := newStack(t)
	ctx := context.Background()
	org := uuid.Must(uuid.NewV7())
	first, gone := month(2002, time.February), month(2002, time.March)
	s.writeBackdated(t, org, first, 1)
	s.writeBackdated(t, org, gone, 1)
	other := otherSession(t)
	purger := auditwriter.NewPurger(s.pool, s.writer, 400)
	auditwriter.SetPurgeCommitted(purger, func(_ context.Context, part string, err error) error {
		switch part {
		case "audit_event_2002_02":
			for _, stmt := range []string{
				"ALTER TABLE audit_event DETACH PARTITION audit_event_2002_03", "DROP TABLE audit_event_2002_03",
			} {
				if _, err := other.Exec(ctx, stmt); err != nil {
					t.Fatal(err)
				}
			}
		case "audit_event_2002_03":
			return errors.New("unexpected EOF")
		}
		return err
	})

	report, err := purger.Run(ctx, false)
	if err == nil {
		t.Fatal("Run succeeded although the purge transaction failed")
	}
	if p := partitionOf(t, report, "audit_event_2002_03"); p.Dropped || !p.Failed {
		t.Errorf("partition = %+v, want failed, not dropped", p)
	}
	recorded := s.purgedEvents(t, "audit_event_2002_03")
	if len(recorded) != 1 || recorded[0].Outcome != string(audit.OutcomeFailure) {
		t.Fatalf("recorded = %+v, want one failure and no success", recorded)
	}
}

// TestWriterRetriesWhenPurgeDropsPartition (PDK-140 review): when the index purge drops the month's partition between
// ensurePartitions and the insert, the writer retries the transaction, which creates the partition again, instead of
// failing the batch with "no partition".
func TestWriterRetriesWhenPurgeDropsPartition(t *testing.T) {
	s := newStack(t)
	ctx := context.Background()
	org := uuid.Must(uuid.NewV7())
	m := month(2001, time.November)
	s.writeBackdated(t, org, m, 1)
	writer, err := auditwriter.NewWriter(s.pool, s.store, 400)
	if err != nil {
		t.Fatal(err)
	}
	other := otherSession(t)
	attempts := 0
	auditwriter.SetPartitionsEnsured(writer, func() {
		attempts++
		if attempts > 1 {
			return
		}
		if _, err := other.Exec(ctx, "SET lock_timeout = '5s'"); err != nil {
			t.Error(err)
		}
		if _, err := other.Exec(ctx, "ALTER TABLE audit_event DETACH PARTITION audit_event_2001_11"); err != nil {
			t.Errorf("detach: %v", err)
		}
		if _, err := other.Exec(ctx, "DROP TABLE audit_event_2001_11"); err != nil {
			t.Errorf("drop: %v", err)
		}
	})
	late := event(org, m.AddDate(0, 0, 20), audit.CodeDeviceGroupUpdated)
	if written, err := writer.WriteBatch(ctx, []audit.Event{late}); err != nil || written != 1 {
		t.Fatalf("WriteBatch = %d, %v, want 1 written after a retry", written, err)
	}
	if attempts != 2 {
		t.Errorf("%d transactions, want 2", attempts)
	}
	if n := s.count(t, "SELECT count(*) FROM audit_event_2001_11 WHERE event_id = $1", late.EventID); n != 1 {
		t.Errorf("late event indexed %d times, want 1", n)
	}
}

// writerSession opens a session of paddock_audit_writer of its own, outside the writer pool.
func writerSession(t *testing.T) *pgx.Conn {
	t.Helper()
	conn, err := pgx.Connect(context.Background(), pgtest.SharedAudit(t).Writer)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close(context.Background()) })
	return conn
}

// otherSession opens a superuser session of its own, for a concurrent transaction or lock.
func otherSession(t *testing.T) *pgx.Conn {
	t.Helper()
	conn, err := pgx.Connect(context.Background(), pgtest.SharedAudit(t).Super)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close(context.Background()) })
	return conn
}

// TestPartitionMonth: only partitions named audit_event_YYYY_MM have a month; any other name is reported, never purged.
func TestPartitionMonth(t *testing.T) {
	for name, want := range map[string]time.Time{
		"audit_event_2025_01": month(2025, time.January),
		"audit_event_1999_12": month(1999, time.December),
		"audit_event_default": {},
		"audit_event_2025_13": {},
		"audit_event_2025_1":  {},
		"other_2025_01":       {},
	} {
		got, ok := auditwriter.PartitionMonth(name)
		if ok != !want.IsZero() || !got.Equal(want) {
			t.Errorf("PartitionMonth(%q) = %s, %v; want %s", name, got, ok, want)
		}
	}
}

// TestPurgerRunDailyWaitsForOtherReplica: RunDaily seeds the last-success gauge with its start, purges at 01:15 UTC
// and, while another replica holds the purge lock, runs again a minute later, so it reports its own success.
func TestPurgerRunDailyWaitsForOtherReplica(t *testing.T) {
	s := newStack(t)
	other := otherSession(t)
	if _, err := other.Exec(context.Background(), "SELECT pg_advisory_lock(hashtext('audit-purge'))"); err != nil {
		t.Fatal(err)
	}
	start := time.Date(2026, 10, 30, 0, 0, 0, 0, time.UTC)
	var now atomic.Int64
	now.Store(start.Unix())
	waits, fire := make(chan time.Duration, 1), make(chan time.Time)
	purger := auditwriter.NewPurger(s.pool, s.writer, 400)
	auditwriter.SetPurgerClock(purger, func() time.Time { return time.Unix(now.Load(), 0) },
		func(d time.Duration) <-chan time.Time { waits <- d; return fire })
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { purger.RunDaily(ctx); close(done) }()
	defer func() { cancel(); <-done }()

	const lastSuccess = "paddock_audit_index_purge_last_success_timestamp_seconds"
	if d := <-waits; d != auditwriter.PurgeDelay {
		t.Fatalf("first wait %s, want %s", d, auditwriter.PurgeDelay)
	}
	if v := gaugeValue(t, lastSuccess); v != float64(start.Unix()) {
		t.Errorf("seeded gauge %v, want the start %d", v, start.Unix())
	}
	now.Store(start.Add(auditwriter.PurgeDelay).Unix())
	fire <- time.Time{}
	if d := <-waits; d != time.Minute {
		t.Fatalf("wait after losing the lock %s, want 1m", d)
	}
	if _, err := other.Exec(context.Background(), "SELECT pg_advisory_unlock(hashtext('audit-purge'))"); err != nil {
		t.Fatal(err)
	}
	finished := start.Add(auditwriter.PurgeDelay + 2*time.Minute)
	now.Store(finished.Unix())
	fire <- time.Time{}
	if d := <-waits; d <= 0 || d > 24*time.Hour {
		t.Fatalf("wait for the next night %s", d)
	}
	if v := gaugeValue(t, lastSuccess); v != float64(finished.Unix()) {
		t.Errorf("gauge after the retried purge %v, want %d", v, finished.Unix())
	}
}

// TestEnsurePartitionIgnoresTemporaryShadow (PDK-558): temporary tables named like the parent or the partition of the
// writer's session never steer audit_ensure_partition; the partition is created in public all the same.
func TestEnsurePartitionIgnoresTemporaryShadow(t *testing.T) {
	s := newStack(t)
	ctx := context.Background()
	if _, err := s.super.Exec(ctx, "GRANT TEMPORARY ON DATABASE paddock_audit TO paddock_audit_writer"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		bg := context.Background()
		if _, err := s.super.Exec(bg, "DROP TABLE IF EXISTS public.audit_event_2001_09"); err != nil {
			t.Error(err)
		}
		if _, err := s.super.Exec(bg, "REVOKE TEMPORARY ON DATABASE paddock_audit FROM paddock_audit_writer"); err != nil {
			t.Error(err)
		}
	})
	if s.partitionExists(t, "public.audit_event_2001_09") {
		t.Fatal("audit_event_2001_09 exists; this test needs the month without a partition")
	}
	conn := writerSession(t)
	for _, ddl := range []string{
		"CREATE TEMPORARY TABLE audit_event_2001_09 (recorded_at timestamptz)",
		"CREATE TEMPORARY TABLE audit_event (recorded_at timestamptz)",
	} {
		if _, err := conn.Exec(ctx, ddl); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := conn.Exec(ctx, "SELECT audit_ensure_partition($1)", month(2001, time.September)); err != nil {
		t.Fatal(err)
	}
	var partitioned bool
	if err := s.super.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_inherits i
		WHERE i.inhrelid = to_regclass('public.audit_event_2001_09') AND i.inhparent = to_regclass('public.audit_event'))`).
		Scan(&partitioned); err != nil || !partitioned {
		t.Errorf("public.audit_event_2001_09 is not a partition of public.audit_event (%v)", err)
	}
	var temps int
	if err := conn.QueryRow(ctx, `SELECT count(*) FROM pg_class
		WHERE relnamespace = pg_my_temp_schema() AND relname IN ('audit_event', 'audit_event_2001_09')`).Scan(&temps); err != nil || temps != 2 {
		t.Errorf("temporary tables = %d, want 2 untouched (%v)", temps, err)
	}
}

// TestEnsurePartitionIsIdempotent (PDK-558): the normal caller still gets a partition, and a second call is a no-op.
func TestEnsurePartitionIsIdempotent(t *testing.T) {
	s := newStack(t)
	ctx := context.Background()
	t.Cleanup(func() {
		if _, err := s.super.Exec(context.Background(), "DROP TABLE IF EXISTS public.audit_event_2001_10"); err != nil {
			t.Error(err)
		}
	})
	conn := writerSession(t)
	for range 2 {
		if _, err := conn.Exec(ctx, "SELECT audit_ensure_partition($1)", month(2001, time.October)); err != nil {
			t.Fatal(err)
		}
	}
	if !s.partitionExists(t, "public.audit_event_2001_10") {
		t.Error("audit_event_2001_10 not created")
	}
}
