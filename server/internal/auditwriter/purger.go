package auditwriter

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/phischl/paddock-mdm/server/internal/adapters/auditpg/auditstore"
	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
)

// PurgeDelay is when the index purge starts after 00:00 UTC: after the seal (SealDelay) and the nightly verification
// (VerifyDelay), so it never competes with them for the audit index (plan M10 decision 23).
const PurgeDelay = 75 * time.Minute

// Reasons of a partition the purge keeps. The reasons of audit_purge_partition itself pass through unchanged.
const (
	PurgeReasonNotDue      = "month not past the cutoff"
	PurgeReasonLateEvents  = "late events still within retention"
	PurgeReasonLockTimeout = "lock_timeout"
	PurgeReasonUnknownName = "not a monthly partition"
	PurgeReasonDropped     = "dropped"
)

const (
	storeAuditIndex     = "audit_index"
	errorPurgeFailed    = "purge_failed"
	partitionNamePrefix = "audit_event_"
	// The evidence of a drop that already happened can only be written afterwards; WriteBatch skips an event ID it
	// already indexed, so retrying with the same event cannot record it twice.
	purgeRecordAttempts = 3
	purgeRecordBackoff  = 2 * time.Second
	purgeRecordLimit    = 2 * time.Minute
	// Two writer replicas start the purge at the same time; the one that loses the lock runs again once the other
	// one is done, so both report a success instead of the loser raising PaddockAuditIndexPurgeStale.
	purgeLockedAttempts = 10
	purgeLockedRetry    = time.Minute
	purgeRecheckLimit   = 30 * time.Second
)

// ErrPurgeLocked means another replica is purging the audit index.
var ErrPurgeLocked = errors.New("auditwriter: another replica holds the index purge lock")

var (
	metricPurgeLastSuccess = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "paddock_audit_index_purge_last_success_timestamp_seconds",
		Help: "End of the last index purge without a failed or timed-out partition (at start: the start time).",
	})
	metricPartitionsDropped = promauto.NewCounter(prometheus.CounterOpts{
		Name: "paddock_audit_index_partitions_dropped_total",
		Help: "Monthly audit index partitions dropped by the index purge.",
	})
)

// PurgedPartition is the outcome of one partition of an index purge. Due is set when the month ended before the
// cutoff, so the partition was a candidate; Failed when its purge failed with an error other than a lock timeout.
type PurgedPartition struct {
	Name    string
	Month   time.Time
	Events  int64
	Due     bool
	Dropped bool
	Failed  bool
	Reason  string
}

// PurgeReport is the result of one index purge, oldest partition first. Cutoff is now − index retention by the
// database's clock when the purge listed the partitions; each drop records the cutoff its own transaction computed.
type PurgeReport struct {
	Cutoff     time.Time
	Partitions []PurgedPartition
}

// Complete reports whether no partition failed or timed out, so the next purge has nothing left over.
func (r PurgeReport) Complete() bool {
	for _, p := range r.Partitions {
		if p.Failed || p.Reason == PurgeReasonLockTimeout {
			return false
		}
	}
	return true
}

// Purger drops the monthly partitions of the audit index whose events were all recorded more than the index
// retention ago (ADR 0032 §3, plan M10 decisions 22–25). It never touches the WORM store, audit_object or
// audit_manifest.
type Purger struct {
	pool          *db.AuditWriterPool
	writer        *Writer
	retentionDays int
	now           func() time.Time
	after         func(time.Duration) <-chan time.Time
	committed     func(ctx context.Context, partition string, err error) error // nil; tests turn a committed drop into an unknown outcome
}

// NewPurger creates the index purge. indexRetentionDays below the writer's WORM retention makes every Run fail.
func NewPurger(pool *db.AuditWriterPool, writer *Writer, indexRetentionDays int) *Purger {
	return &Purger{pool: pool, writer: writer, retentionDays: indexRetentionDays, now: time.Now, after: time.After}
}

// Run purges every partition whose month ended before now − index retention, both by the database's clock, so the
// writer's clock never decides what is dropped (plan M10 amendment of 2026-10-30). Each drop runs in its own writer
// transaction with lock_timeout 5 s; a timeout keeps the partition with PurgeReasonLockTimeout for the next night.
// Every drop is recorded as retention.purged in the platform pseudo-organization, every failed drop as its failure.
// With dryRun it only reports, from a read without locks. It returns ErrPurgeLocked when another replica purges and
// an error when a partition failed; the report then still lists every partition.
func (p *Purger) Run(ctx context.Context, dryRun bool) (PurgeReport, error) {
	if p.retentionDays < p.writer.retentionDays {
		return PurgeReport{}, fmt.Errorf("auditwriter: index retention of %d days is below the WORM retention of %d days",
			p.retentionDays, p.writer.retentionDays)
	}
	if p.retentionDays > math.MaxInt32 {
		return PurgeReport{}, fmt.Errorf("auditwriter: index retention of %d days is out of range", p.retentionDays)
	}
	var report PurgeReport
	if dryRun {
		err := p.pool.WithSession(ctx, func(ctx context.Context, q *auditstore.Queries) error {
			return p.plan(ctx, q, &report, true)
		})
		return report, err
	}
	var failed error
	err := p.pool.WithSession(ctx, func(ctx context.Context, q *auditstore.Queries) error {
		locked, err := q.TryAuditPurgeLock(ctx)
		if err != nil {
			return err
		}
		if !locked {
			return ErrPurgeLocked
		}
		defer func() { _, _ = q.ReleaseAuditPurgeLock(context.WithoutCancel(ctx)) }()
		if err := p.plan(ctx, q, &report, false); err != nil {
			return err
		}
		for i := range report.Partitions {
			if err := ctx.Err(); err != nil {
				return err
			}
			if part := &report.Partitions[i]; part.Due {
				failed = errors.Join(failed, p.purge(ctx, part, report.Cutoff))
			}
		}
		return nil
	})
	if err != nil {
		return report, err
	}
	if failed != nil {
		return report, failed
	}
	if report.Complete() {
		metricPurgeLastSuccess.Set(float64(p.now().Unix()))
	}
	return report, nil
}

// plan lists the partitions, oldest first (ListAuditPartitions orders by name, which is by month), and marks the due
// ones. In a dry run it also fills the outcome a purge would have from the partition's current events: Dropped then
// means "would be dropped".
func (p *Purger) plan(ctx context.Context, q *auditstore.Queries, report *PurgeReport, dryRun bool) error {
	cutoff, err := q.PurgeCutoff(ctx, int32(p.retentionDays)) //nolint:gosec // range checked in Run
	if err != nil {
		return fmt.Errorf("auditwriter: read the purge cutoff: %w", err)
	}
	report.Cutoff = audit.Timestamp(cutoff)
	names, err := q.ListAuditPartitions(ctx)
	if err != nil {
		return fmt.Errorf("auditwriter: list audit partitions: %w", err)
	}
	for _, name := range names {
		part := PurgedPartition{Name: name}
		month, ok := partitionMonth(name)
		if !ok {
			part.Reason = PurgeReasonUnknownName
			report.Partitions = append(report.Partitions, part)
			continue
		}
		part.Month = month
		part.Due = month.AddDate(0, 1, 0).Before(report.Cutoff)
		if !part.Due {
			part.Reason = PurgeReasonNotDue
		} else if dryRun {
			stats, err := q.AuditPartitionStats(ctx, auditstore.AuditPartitionStatsParams{
				MonthStart: month, MonthEnd: month.AddDate(0, 1, 0),
			})
			if err != nil {
				return fmt.Errorf("auditwriter: read partition %s: %w", name, err)
			}
			part.Events = stats.Events
			part.Dropped = stats.Events == 0 || stats.Newest.Before(report.Cutoff)
			part.Reason = PurgeReasonDropped
			if !part.Dropped {
				part.Reason = PurgeReasonLateEvents
			}
		}
		report.Partitions = append(report.Partitions, part)
	}
	return nil
}

// purge drops one due partition and records the outcome. planned is the report's cutoff, recorded for a failed
// drop, whose transaction returned no cutoff of its own. It returns an error only for a failed drop or a drop whose
// evidence could not be recorded.
func (p *Purger) purge(ctx context.Context, part *PurgedPartition, planned time.Time) error {
	var row auditstore.PurgeAuditPartitionRow
	err := p.pool.InWriter(ctx, func(ctx context.Context, q *auditstore.Queries) error {
		if err := q.SetPurgeLockTimeout(ctx); err != nil {
			return err
		}
		var err error
		row, err = q.PurgeAuditPartition(ctx, auditstore.PurgeAuditPartitionParams{
			Month: part.Month, Days: int32(p.retentionDays), //nolint:gosec // range checked in Run
		})
		return err
	})
	if p.committed != nil {
		err = p.committed(ctx, part.Name, err)
	}
	cutoff := planned
	if !row.Cutoff.IsZero() {
		cutoff = audit.Timestamp(row.Cutoff)
	}
	// Only a function result that reported the drop can precede a committed drop: without it, no COMMIT was sent.
	// The re-check goes by the dropped relation's OID, since the writer may already have created a partition of the
	// same name again for a late event.
	if err != nil && row.Dropped && p.droppedAnyway(ctx, part.Name, row.Relid) {
		// The COMMIT reached the server although the client saw an error or a cancellation: the drop is final and the
		// next night no longer lists the partition, so its evidence has to be recorded now. The event count died with
		// the transaction's result.
		part.Dropped, part.Reason = true, PurgeReasonDropped
		slog.WarnContext(ctx, "audit index purge: drop committed despite an error", "partition", part.Name, "error", err)
		return p.recordDrop(ctx, part, cutoff, false)
	}
	switch {
	case db.IsLockTimeout(err):
		part.Reason = PurgeReasonLockTimeout
		slog.WarnContext(ctx, "audit index purge: lock timeout, retried next night", "partition", part.Name)
		return nil
	case err != nil && ctx.Err() != nil:
		// A shutdown is no failed drop: the transaction rolled back and the next night retries.
		part.Reason = "interrupted"
		return fmt.Errorf("auditwriter: purge %s: %w", part.Name, err)
	case err != nil:
		part.Failed, part.Reason = true, err.Error()
		slog.ErrorContext(ctx, "audit index purge failed", "partition", part.Name, "error", err)
		return errors.Join(fmt.Errorf("auditwriter: purge %s: %w", part.Name, err), p.record(ctx, *part, cutoff, err, true))
	}
	part.Dropped, part.Events, part.Reason = row.Dropped, row.Events, row.Reason
	if !row.Dropped {
		slog.InfoContext(ctx, "audit index partition kept", "partition", part.Name, "events", row.Events,
			"reason", row.Reason)
		return nil
	}
	return p.recordDrop(ctx, part, cutoff, true)
}

// recordDrop counts a dropped partition and records its retention.purged; countKnown is false when the drop's own
// result was lost, so the event leaves out deleted instead of claiming 0.
func (p *Purger) recordDrop(ctx context.Context, part *PurgedPartition, cutoff time.Time, countKnown bool) error {
	metricPartitionsDropped.Inc()
	slog.InfoContext(ctx, "audit index partition dropped", "partition", part.Name, "events", part.Events,
		"cutoff", cutoff.Format(time.RFC3339Nano))
	if err := p.record(ctx, *part, cutoff, nil, countKnown); err != nil {
		part.Failed = true
		return fmt.Errorf("auditwriter: %s dropped (%d events), but its retention.purged was not recorded: %w",
			part.Name, part.Events, err)
	}
	return nil
}

// droppedAnyway reports whether the relation relid of partition name is gone after its purge transaction returned
// an error. A failed check counts as "still there", which keeps the error path.
func (p *Purger) droppedAnyway(ctx context.Context, name string, relid int64) bool {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), purgeRecheckLimit)
	defer cancel()
	var exists bool
	err := p.pool.WithSession(ctx, func(ctx context.Context, q *auditstore.Queries) error {
		var err error
		exists, err = q.AuditRelationExists(ctx, relid)
		return err
	})
	if err != nil {
		slog.ErrorContext(ctx, "audit index purge: re-check of the partition failed", "partition", name, "error", err)
		return false
	}
	return !exists
}

// record writes retention.purged for a dropped partition, or its failure when purgeErr is set (plan M10 decision 22).
func (p *Purger) record(ctx context.Context, part PurgedPartition, cutoff time.Time, purgeErr error, countKnown bool) error {
	// The drop is already committed and irreversible: a shutdown must not cost its evidence.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), purgeRecordLimit)
	defer cancel()
	ev := audit.Event{
		OrganizationID: audit.PlatformOrganizationID, Code: audit.CodeRetentionPurged, Outcome: audit.OutcomeSuccess,
		Target: &audit.Target{Type: storeAuditIndex, ID: part.Name, Display: part.Name},
		Params: map[string]any{
			"store": storeAuditIndex, "partition": part.Name, "deleted": part.Events,
			"cutoff": cutoff.Format(time.RFC3339Nano),
		},
	}
	if !countKnown {
		delete(ev.Params, "deleted")
	}
	if purgeErr != nil {
		ev.Outcome, ev.ErrorCode, ev.Params["deleted"] = audit.OutcomeFailure, errorPurgeFailed, 0
	}
	id, err := uuid.NewV7()
	if err != nil {
		return err
	}
	ev.EventID = id
	for attempt := 1; ; attempt++ {
		err = RecordSelf(ctx, p.writer, ev)
		if err == nil || attempt == purgeRecordAttempts {
			break
		}
		select {
		case <-ctx.Done():
			return errors.Join(err, ctx.Err())
		case <-p.after(purgeRecordBackoff * time.Duration(attempt)):
		}
	}
	if err != nil {
		slog.ErrorContext(ctx, "audit index purge: retention.purged not recorded", "partition", part.Name,
			"events", part.Events, "cutoff", cutoff.Format(time.RFC3339Nano), "event_id", id, "error", err)
	}
	return err
}

// RunDaily purges the index every day at 01:15 UTC (PurgeDelay) until ctx ends. The last-success gauge starts at the
// start time, so PaddockAuditIndexPurgeStale measures from the writer's start until the first purge.
func (p *Purger) RunDaily(ctx context.Context) {
	metricPurgeLastSuccess.Set(float64(p.now().Unix()))
	for {
		now := p.now().UTC()
		next := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC).Add(PurgeDelay)
		if !next.After(now) {
			next = next.AddDate(0, 0, 1)
		}
		select {
		case <-ctx.Done():
			return
		case <-p.after(next.Sub(now)):
		}
		p.runOnce(ctx)
	}
}

// runOnce runs one nightly purge, retrying while another replica holds the purge lock.
func (p *Purger) runOnce(ctx context.Context) {
	for attempt := 1; ; attempt++ {
		report, err := p.Run(ctx, false)
		switch {
		case errors.Is(err, ErrPurgeLocked) && attempt < purgeLockedAttempts:
			slog.InfoContext(ctx, "audit index purge waits: another replica is purging")
			select {
			case <-ctx.Done():
				return
			case <-p.after(purgeLockedRetry):
			}
			continue
		case err != nil:
			slog.ErrorContext(ctx, "audit index purge failed", "error", err)
		default:
			dropped := 0
			for _, part := range report.Partitions {
				if part.Dropped {
					dropped++
				}
			}
			slog.InfoContext(ctx, "audit index purge finished", "cutoff", report.Cutoff.Format(time.RFC3339Nano),
				"dropped", dropped, "complete", report.Complete())
		}
		return
	}
}

// partitionMonth parses the month of a partition named audit_event_YYYY_MM (audit_ensure_partition).
func partitionMonth(name string) (time.Time, bool) {
	suffix, ok := strings.CutPrefix(name, partitionNamePrefix)
	if !ok {
		return time.Time{}, false
	}
	month, err := time.Parse("2006_01", suffix)
	if err != nil {
		return time.Time{}, false
	}
	return month.UTC(), true
}
