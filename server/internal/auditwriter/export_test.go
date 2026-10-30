package auditwriter

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/adapters/auditpg/auditstore"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
)

// Test-only hooks; they exist only in the test binary.

// SetTransactionTimeout lowers the writer's transaction timeout.
func SetTransactionTimeout(w *Writer, d time.Duration) { w.txTimeout = d }

// SetDayChosen runs fn in the writer transaction after it chose the object's day and before it inserts the object.
func SetDayChosen(w *Writer, fn func(day time.Time)) { w.dayChosen = fn }

// SetRowInserted runs fn in the writer transaction after it inserted the audit_object row and before the WORM put.
func SetRowInserted(w *Writer, fn func(day time.Time)) { w.rowInserted = fn }

// SetPartitionsEnsured runs fn in the writer transaction after it ensured the partitions and before it inserts.
func SetPartitionsEnsured(w *Writer, fn func()) { w.ensured = fn }

// SetPurgeCommitted replaces the error of a partition's purge transaction after it ended, to simulate a COMMIT whose
// outcome the client never learned.
func SetPurgeCommitted(p *Purger, fn func(ctx context.Context, err error) error) { p.committed = fn }

// SetSealerClock replaces the sealer's clock.
func SetSealerClock(s *Sealer, now func() time.Time) { s.now = now }

// SetPurgerClock replaces the purger's clock and timer.
func SetPurgerClock(p *Purger, now func() time.Time, after func(time.Duration) <-chan time.Time) {
	p.now, p.after = now, after
}

// PartitionMonth parses the month of a partition name.
var PartitionMonth = partitionMonth

// EncodeObject renders events as a WORM object body.
var EncodeObject = encodeObject

// AuditOrganization is an organization of the fake index of NewTestNightly.
type AuditOrganization = auditOrganization

// FakeIndex is an in-memory verifyIndex.
type FakeIndex struct {
	Orgs      []AuditOrganization
	Latest    time.Time
	Locked    bool
	LastErr   error
	Failed    []uuid.UUID
	FailedErr error
}

func (f *FakeIndex) lockedOrganizations(ctx context.Context, fn func(ctx context.Context, orgs []auditOrganization) error) error {
	if f.Locked {
		return ErrVerifyLocked
	}
	return fn(ctx, f.Orgs)
}

func (f *FakeIndex) latestNightlyRun(context.Context) (time.Time, bool, error) {
	return f.Latest, !f.Latest.IsZero(), f.LastErr
}

func (f *FakeIndex) latestFailedOrganizations(context.Context) ([]uuid.UUID, error) {
	return f.Failed, f.FailedErr
}

func (f *FakeIndex) organizations(context.Context) ([]auditOrganization, error) { return f.Orgs, nil }

// VerifyFunc and RecordFunc stand in for the verifier and the recorder.
type (
	VerifyFunc func(ctx context.Context, org uuid.UUID, from, to time.Time) (*Report, error)
	RecordFunc func(ctx context.Context, org uuid.UUID, trigger string, from, to, started time.Time, report *Report) (uuid.UUID, error)
)

func (f VerifyFunc) Verify(ctx context.Context, org uuid.UUID, from, to time.Time) (*Report, error) {
	return f(ctx, org, from, to)
}

func (f RecordFunc) Record(ctx context.Context, org uuid.UUID, trigger string, from, to, started time.Time, report *Report) (uuid.UUID, error) {
	return f(ctx, org, trigger, from, to, started, report)
}

// NewTestNightly builds a Nightly on fakes; metrics counts its errors.
func NewTestNightly(index *FakeIndex, verify VerifyFunc, record RecordFunc, metrics *VerifyMetrics, now func() time.Time) *Nightly {
	return &Nightly{index: index, verifier: verify, recorder: record, metrics: metrics, now: now, after: time.After}
}

// InitLastRun runs the start-up part of RunNightly.
func InitLastRun(n *Nightly, ctx context.Context) error {
	_, err := n.initLastRun(ctx, false)
	return err
}

// SetAfter replaces the timer RunNightly waits on.
func SetAfter(n *Nightly, after func(time.Duration) <-chan time.Time) { n.after = after }

// ResetLastRun sets the last-run and failed-organizations gauges back to their unset value.
func ResetLastRun() {
	metricVerifyLastRun.Set(0)
	metricVerifyFailedOrganizations.Set(0)
}

// NewTestVerifyMetrics returns a collector without database counts.
func NewTestVerifyMetrics() *VerifyMetrics { return newVerifyMetrics(nil) }

// CountVerifyError counts a run without a row, as Nightly and Recorder do.
func CountVerifyError(m *VerifyMetrics, trigger, result string) { m.countError(trigger, result) }

// VerificationEvent builds the event of a verification run.
var VerificationEvent = verificationEvent

// SetVerifyCounts replaces the collector's database read.
func SetVerifyCounts(m *VerifyMetrics, counts func(ctx context.Context) ([]auditstore.CountAuditVerificationRunsRow, error)) {
	m.counts = counts
}

// PoolIndex is the database side of the nightly cycle.
func PoolIndex(pool *db.AuditWriterPool) (
	locked func(ctx context.Context, fn func(ctx context.Context, orgs []AuditOrganization) error) error,
	latest func(ctx context.Context) (time.Time, bool, error),
	failed func(ctx context.Context) ([]uuid.UUID, error),
	orgs func(ctx context.Context) ([]AuditOrganization, error),
) {
	p := poolIndex{pool}
	return p.lockedOrganizations, p.latestNightlyRun, p.latestFailedOrganizations, p.organizations
}
