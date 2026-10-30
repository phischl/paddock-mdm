package auditwriter_test

import (
	"context"
	"encoding/json"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

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

	dry, err := purger.Run(ctx, time.Now(), true)
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
	report, err := purger.Run(ctx, now, false)
	if err != nil {
		t.Fatal(err)
	}
	if want := audit.Timestamp(now.UTC().AddDate(0, 0, -400)); !report.Cutoff.Equal(want) {
		t.Errorf("cutoff = %s, want %s", report.Cutoff, want)
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
	if ev.Org != audit.PlatformOrganizationID || ev.Outcome != string(audit.OutcomeSuccess) ||
		params["deleted"] != float64(2) || params["cutoff"] != report.Cutoff.Format(time.RFC3339Nano) {
		t.Errorf("retention.purged = %+v %v", ev, params)
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
	if _, err := purger.Run(ctx, time.Now(), false); err != nil {
		t.Fatal(err)
	}
	if n := len(s.purgedEvents(t, "audit_event_2001_01")); n != 1 {
		t.Errorf("%d retention.purged events after a second run, want 1", n)
	}
	if n := len(s.purgedEvents(t, "audit_event_2001_02")); n != 0 {
		t.Errorf("%d retention.purged events for the kept partition, want 0", n)
	}
}

// TestPurgerMonthBoundary: a partition whose month ends exactly at the cutoff is kept; one second later it is
// dropped.
func TestPurgerMonthBoundary(t *testing.T) {
	s := newStack(t)
	ctx := context.Background()
	m := month(2001, time.March)
	s.writeBackdated(t, uuid.Must(uuid.NewV7()), m, 1)
	purger := auditwriter.NewPurger(s.pool, s.writer, 400)
	atCutoff := m.AddDate(0, 1, 0).AddDate(0, 0, 400)

	report, err := purger.Run(ctx, atCutoff, false)
	if err != nil {
		t.Fatal(err)
	}
	if p := partitionOf(t, report, "audit_event_2001_03"); p.Due || p.Dropped || p.Reason != auditwriter.PurgeReasonNotDue {
		t.Errorf("month ending at the cutoff = %+v, want kept as not due", p)
	}
	if !s.partitionExists(t, "audit_event_2001_03") {
		t.Fatal("partition ending at the cutoff dropped")
	}
	report, err = purger.Run(ctx, atCutoff.Add(time.Second), false)
	if err != nil {
		t.Fatal(err)
	}
	if p := partitionOf(t, report, "audit_event_2001_03"); !p.Dropped || p.Events != 1 {
		t.Errorf("month ending before the cutoff = %+v, want dropped", p)
	}
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
	report, err := purger.Run(ctx, time.Now(), false)
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
	report, err = purger.Run(ctx, time.Now(), false)
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
		                          correlation_id, object_key)
		 VALUES ($1, $2, $3, now(), 'device_group.created', 'success', 'portal', '{}', '{}', 'late', 'late')`,
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
		r, err := purger.Run(ctx, time.Now(), false)
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
	if _, err := s.super.Exec(ctx, "REVOKE EXECUTE ON FUNCTION audit_purge_partition(date, timestamptz) FROM paddock_audit_writer"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := s.super.Exec(context.Background(), "GRANT EXECUTE ON FUNCTION audit_purge_partition(date, timestamptz) TO paddock_audit_writer"); err != nil {
			t.Error(err)
		}
	})
	report, err := auditwriter.NewPurger(s.pool, s.writer, 400).Run(ctx, time.Now(), false)
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
	if _, err := purger.Run(ctx, time.Now(), false); !errors.Is(err, auditwriter.ErrPurgeLocked) {
		t.Errorf("Run = %v, want ErrPurgeLocked", err)
	}
	if _, err := purger.Run(ctx, time.Now(), true); err != nil {
		t.Errorf("dry run = %v", err)
	}
	if _, err := other.Exec(ctx, "SELECT pg_advisory_unlock(hashtext('audit-purge'))"); err != nil {
		t.Fatal(err)
	}
	if _, err := purger.Run(ctx, time.Now(), false); err != nil {
		t.Errorf("Run after unlock = %v", err)
	}
}

// TestPurgerRefusesIndexRetentionBelowWORM: the index is never purged ahead of the WORM retention.
func TestPurgerRefusesIndexRetentionBelowWORM(t *testing.T) {
	s := newStack(t)
	if _, err := auditwriter.NewPurger(s.pool, s.writer, 399).Run(context.Background(), time.Now(), false); err == nil {
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
		"SELECT has_function_privilege('paddock_audit_writer', 'audit_purge_partition(date, timestamptz)', 'EXECUTE')").Scan(&canPurge); err != nil {
		t.Fatal(err)
	}
	if !canPurge {
		t.Error("paddock_audit_writer cannot execute audit_purge_partition")
	}
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
