package auditwriter

import (
	"context"
	"errors"
	"log/slog"
	"math/rand/v2"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/phischl/paddock-mdm/server/internal/adapters/auditpg/auditstore"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
)

// VerifyDelay is when the nightly verification starts after 00:00 UTC: 30 minutes after the seal (SealDelay).
const VerifyDelay = 45 * time.Minute

// VerifyWindowDays is how many of the latest sealed days the nightly run verifies per organization.
const VerifyWindowDays = 7

// ErrVerifyLocked means another replica holds the verification lock.
var ErrVerifyLocked = errors.New("auditwriter: another replica holds the verification lock")

var (
	metricVerifyFailedOrganizations = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "paddock_audit_verify_failed_organizations",
		Help: "Organizations whose audit chain failed or could not be verified in the last nightly cycle.",
	})
	metricVerifyLastRun = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "paddock_audit_verify_last_run_timestamp_seconds",
		Help: "End of the last nightly verification cycle (at start: of the last recorded nightly run, else the start time).",
	})
)

// chainVerifier is Verifier.Verify.
type chainVerifier interface {
	Verify(ctx context.Context, org uuid.UUID, from, to time.Time) (*Report, error)
}

// runRecorder is Recorder.Record.
type runRecorder interface {
	Record(ctx context.Context, org uuid.UUID, trigger string, from, to, started time.Time, report *Report) (uuid.UUID, error)
}

// auditOrganization is an organization with audit data and its first audit day.
type auditOrganization struct {
	ID       uuid.UUID
	FirstDay time.Time
}

// verifyIndex is what the nightly cycle reads from the audit index.
type verifyIndex interface {
	// lockedOrganizations runs fn with every organization of the index while holding the verification lock; it
	// returns ErrVerifyLocked when another replica holds it.
	lockedOrganizations(ctx context.Context, fn func(ctx context.Context, orgs []auditOrganization) error) error
	// latestNightlyRun returns the end of the newest recorded nightly run; ok is false before the first one.
	latestNightlyRun(ctx context.Context) (finished time.Time, ok bool, err error)
	// latestFailedOrganizations returns the organizations whose newest recorded nightly window or sample day failed.
	latestFailedOrganizations(ctx context.Context) ([]uuid.UUID, error)
}

// Nightly verifies, every night, the last VerifyWindowDays sealed days of every organization plus one random older
// day (plan M8b decision 27).
type Nightly struct {
	index    verifyIndex
	verifier chainVerifier
	recorder runRecorder
	metrics  *VerifyMetrics
	now      func() time.Time
	after    func(time.Duration) <-chan time.Time
}

// NewNightly creates the nightly verification. It records through recorder, whose collector also counts the runs
// that could not be verified.
func NewNightly(pool *db.AuditWriterPool, verifier *Verifier, recorder *Recorder, now func() time.Time) *Nightly {
	return &Nightly{index: poolIndex{pool}, verifier: verifier, recorder: recorder, metrics: recorder.metrics, now: now, after: time.After}
}

// lastRunRetry is how often RunNightly retries reading the last nightly run while the audit index is unreadable.
const lastRunRetry = time.Minute

// RunNightly seeds the gauges, then runs Cycle every day at 00:45 UTC (VerifyDelay) until ctx ends. While the
// last nightly runs cannot be read, it retries every lastRunRetry until the read succeeds or a cycle sets the gauge.
func (n *Nightly) RunNightly(ctx context.Context) {
	seeded := n.seedLastRun(ctx, false)
	for {
		now := n.now().UTC()
		next := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC).Add(VerifyDelay)
		if !next.After(now) {
			next = next.AddDate(0, 0, 1)
		}
		wait := next.Sub(now)
		retry := !seeded && wait > lastRunRetry
		if retry {
			wait = lastRunRetry
		}
		select {
		case <-ctx.Done():
			return
		case <-n.after(wait):
		}
		if retry {
			seeded = n.seedLastRun(ctx, true)
			continue
		}
		switch err := n.Cycle(ctx); {
		case errors.Is(err, ErrVerifyLocked):
			slog.InfoContext(ctx, "nightly verification skipped: another replica is verifying")
		case err != nil:
			slog.ErrorContext(ctx, "nightly verification failed", "error", err)
		default:
			seeded = true
		}
	}
}

// seedLastRun logs a failed initLastRun unless retried is set, so a long outage logs once, and reports success.
func (n *Nightly) seedLastRun(ctx context.Context, retried bool) bool {
	err := n.initLastRun(ctx)
	if err != nil && !retried {
		slog.WarnContext(ctx, "reading the last nightly verification failed; retrying every minute", "error", err)
	}
	return err == nil
}

// initLastRun sets the last-run gauge to the end of the newest recorded nightly run or, without any, to now, so that
// PaddockAuditVerifyStale measures from the writer's start instead of firing at once. On a read error it leaves the
// gauge unset: the exported 0 lets PaddockAuditVerifyStale fire, because a start-time seed would mask a stale
// verification for up to 37 h (plan M8b decision 27, amendment 2026-10-25). It also sets the failed-organizations
// gauge from the newest recorded nightly and sample runs, so a restart does not clear an active
// PaddockAuditChainBroken (amendment 2026-10-29); it sets neither gauge unless both reads succeed.
func (n *Nightly) initLastRun(ctx context.Context) error {
	finished, ok, err := n.index.latestNightlyRun(ctx)
	if err != nil {
		return err
	}
	failed, err := n.index.latestFailedOrganizations(ctx)
	if err != nil {
		return err
	}
	if !ok {
		finished = n.now()
	}
	metricVerifyFailedOrganizations.Set(float64(len(failed)))
	metricVerifyLastRun.Set(float64(finished.Unix()))
	return nil
}

// Cycle verifies every organization once: its nightly window up to LastSealableDay and, if older days exist, one
// random sample day. A verification error of one organization is logged and counted and does not stop the others.
// The gauges are set after the cycle.
func (n *Nightly) Cycle(ctx context.Context) error {
	to := LastSealableDay(n.now())
	failed := 0
	err := n.index.lockedOrganizations(ctx, func(ctx context.Context, orgs []auditOrganization) error {
		for _, org := range orgs {
			if err := ctx.Err(); err != nil {
				return err
			}
			if !n.verifyOrganization(ctx, org, to) {
				failed++
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	metricVerifyFailedOrganizations.Set(float64(failed))
	metricVerifyLastRun.Set(float64(n.now().Unix()))
	slog.InfoContext(ctx, "nightly verification finished", "through", to.Format(time.DateOnly), "failed_organizations", failed)
	return nil
}

// verifyOrganization reports whether the organization's nightly window and sample day verified.
func (n *Nightly) verifyOrganization(ctx context.Context, org auditOrganization, to time.Time) bool {
	first := dayOf(org.FirstDay)
	if first.After(to) {
		return true
	}
	from := to.AddDate(0, 0, -(VerifyWindowDays - 1))
	if from.Before(first) {
		from = first
	}
	ok := n.run(ctx, org.ID, TriggerNightly, from, to)
	if first.Before(from) {
		older := int(from.Sub(first) / (24 * time.Hour))
		day := first.AddDate(0, 0, rand.IntN(older)) //nolint:gosec // the sample day needs no unpredictability
		ok = n.run(ctx, org.ID, TriggerSample, day, day) && ok
	}
	return ok
}

func (n *Nightly) run(ctx context.Context, org uuid.UUID, trigger string, from, to time.Time) bool {
	started := n.now()
	report, err := n.verifier.Verify(ctx, org, from, to)
	if err != nil {
		n.metrics.countError(trigger, resultError)
		slog.ErrorContext(ctx, "audit chain verification failed to run", "organization_id", org, "trigger", trigger,
			"from", from.Format(time.DateOnly), "to", to.Format(time.DateOnly), "error", err)
		return false
	}
	if _, err := n.recorder.Record(ctx, org, trigger, from, to, started, report); err != nil {
		slog.ErrorContext(ctx, "recording the audit chain verification failed", "organization_id", org,
			"trigger", trigger, "error", err)
	}
	return report.OK()
}

// poolIndex reads the audit index as paddock_audit_writer.
type poolIndex struct{ pool *db.AuditWriterPool }

func (p poolIndex) lockedOrganizations(ctx context.Context, fn func(ctx context.Context, orgs []auditOrganization) error) error {
	return p.pool.WithSession(ctx, func(ctx context.Context, q *auditstore.Queries) error {
		locked, err := q.TryAuditVerifyLock(ctx)
		if err != nil {
			return err
		}
		if !locked {
			return ErrVerifyLocked
		}
		defer func() { _, _ = q.ReleaseAuditVerifyLock(context.WithoutCancel(ctx)) }()
		ids, err := q.ListAuditOrganizations(ctx)
		if err != nil {
			return err
		}
		orgs := make([]auditOrganization, len(ids))
		for i, id := range ids {
			first, err := q.FirstAuditDay(ctx, id)
			if err != nil {
				return err
			}
			orgs[i] = auditOrganization{ID: id, FirstDay: first}
		}
		return fn(ctx, orgs)
	})
}

func (p poolIndex) latestNightlyRun(ctx context.Context) (time.Time, bool, error) {
	var finished time.Time
	err := p.pool.WithSession(ctx, func(ctx context.Context, q *auditstore.Queries) error {
		var err error
		finished, err = q.LatestNightlyRunFinished(ctx)
		return err
	})
	if db.IsNoRows(err) {
		return time.Time{}, false, nil
	}
	return finished, err == nil, err
}

func (p poolIndex) latestFailedOrganizations(ctx context.Context) ([]uuid.UUID, error) {
	var failed []uuid.UUID
	err := p.pool.WithSession(ctx, func(ctx context.Context, q *auditstore.Queries) error {
		var err error
		failed, err = q.ListLatestNightlyFailedOrganizations(ctx)
		return err
	})
	return failed, err
}
