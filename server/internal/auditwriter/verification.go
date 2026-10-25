package auditwriter

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/phischl/paddock-mdm/server/internal/adapters/auditpg/auditstore"
	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
)

// Triggers of a verification run (audit_verification_run.trigger).
const (
	TriggerNightly = "nightly"
	TriggerSample  = "sample"
	TriggerCLI     = "cli"
)

// Values of the result label of paddock_audit_verify_runs_total.
const (
	resultOK          = "ok"
	resultFailed      = "failed"
	resultError       = "error"
	resultRecordError = "record_error"
)

// The verification event's problems list is capped (plan M8b decision 26); problem_count keeps the full number.
const (
	MaxRecordedProblems = 50
	MaxProblemLength    = 500
)

const (
	verifierActorID   = "audit-writer"
	targetAuditChain  = "audit_chain"
	errorChainBroken  = "chain_broken"
	verifyCountsLimit = 5 * time.Second
)

// Recorder records the result of a chain verification: the audit event first, then the audit_verification_run row.
type Recorder struct {
	pool    *db.AuditWriterPool
	writer  *Writer
	now     func() time.Time
	metrics *VerifyMetrics
}

// NewRecorder creates a recorder. now is the clock of OccurredAt and finished_at.
func NewRecorder(pool *db.AuditWriterPool, writer *Writer, now func() time.Time) *Recorder {
	return &Recorder{pool: pool, writer: writer, now: now, metrics: newVerifyMetrics(pool)}
}

// Collector is the collector of paddock_audit_verify_runs_total; the serving audit writer registers it.
func (r *Recorder) Collector() prometheus.Collector { return r.metrics }

// Record writes audit.chain_verified or audit.chain_verification_failed for report into org's index and WORM store,
// then inserts the run row, and returns the run ID. The event is the evidence of record: when only the row insert
// fails, the run ID is returned together with the error.
func (r *Recorder) Record(ctx context.Context, org uuid.UUID, trigger string, from, to, started time.Time, report *Report) (uuid.UUID, error) {
	runID, err := uuid.NewV7()
	if err != nil {
		return uuid.Nil, err
	}
	from, to = dayOf(from), dayOf(to)
	finished := r.now()
	ev, err := verificationEvent(org, runID, trigger, from, to, finished, report)
	if err != nil {
		r.metrics.countError(trigger, resultRecordError)
		return uuid.Nil, err
	}
	if _, err := r.writer.WriteBatch(ctx, []audit.Event{ev}); err != nil {
		r.metrics.countError(trigger, resultRecordError)
		return uuid.Nil, fmt.Errorf("auditwriter: write verification event: %w", err)
	}
	problems, err := json.Marshal(cappedProblems(report.Problems))
	if err != nil {
		r.metrics.countError(trigger, resultRecordError)
		return runID, err
	}
	err = r.pool.InWriter(ctx, func(ctx context.Context, q *auditstore.Queries) error {
		return q.InsertAuditVerificationRun(ctx, auditstore.InsertAuditVerificationRunParams{
			ID: runID, OrganizationID: org, Trigger: trigger, FromDay: from, ToDay: to, StartedAt: started,
			FinishedAt: finished, Days: int32(report.Days), Objects: int32(report.Objects), //nolint:gosec // bounded by the day range and the index
			Ok: report.OK(), Problems: problems, EventID: ev.EventID,
		})
	})
	if err != nil {
		r.metrics.countError(trigger, resultRecordError)
		return runID, fmt.Errorf("auditwriter: record verification run %s: %w", runID, err)
	}
	slog.InfoContext(ctx, "audit chain verification recorded", "organization_id", org, "run_id", runID,
		"trigger", trigger, "from", from.Format(time.DateOnly), "to", to.Format(time.DateOnly), "ok", report.OK(),
		"problems", len(report.Problems))
	return runID, nil
}

// verificationEvent builds the audit event of a verification run (plan M8b decisions 9 and 26).
func verificationEvent(org, runID uuid.UUID, trigger string, from, to, at time.Time, report *Report) (audit.Event, error) {
	eventID, err := uuid.NewV7()
	if err != nil {
		return audit.Event{}, err
	}
	fromDay, toDay := dayOf(from).Format(time.DateOnly), dayOf(to).Format(time.DateOnly)
	ev := audit.Event{
		Schema: audit.Schema, EventID: eventID, OrganizationID: org, OccurredAt: audit.Timestamp(at),
		Code: audit.CodeAuditChainVerified, Outcome: audit.OutcomeSuccess,
		Actor:  audit.Actor{Type: audit.ActorSystem, ID: verifierActorID, Display: verifierActorID},
		Target: &audit.Target{Type: targetAuditChain, ID: org.String(), Display: fromDay + ".." + toDay},
		Source: audit.SourceSystem,
		Params: map[string]any{
			"run_id": runID.String(), "trigger": trigger, "from_day": fromDay, "to_day": toDay,
			"days": report.Days, "objects": report.Objects,
		},
		CorrelationID: "verify-" + runID.String(),
	}
	if !report.OK() {
		ev.Code, ev.Outcome, ev.ErrorCode = audit.CodeAuditChainVerificationFailed, audit.OutcomeFailure, errorChainBroken
		ev.Params["problem_count"] = len(report.Problems)
		ev.Params["problems"] = cappedProblems(report.Problems)
	}
	if err := Validate(ev); err != nil {
		return audit.Event{}, fmt.Errorf("auditwriter: verification event: %w", err)
	}
	return ev, nil
}

// cappedProblems returns at most MaxRecordedProblems problems of at most MaxProblemLength characters each.
func cappedProblems(problems []string) []string {
	n := min(len(problems), MaxRecordedProblems)
	out := make([]string, n)
	for i, p := range problems[:n] {
		if r := []rune(p); len(r) > MaxProblemLength {
			p = string(r[:MaxProblemLength])
		}
		out[i] = p
	}
	return out
}

var (
	metricVerifyRuns = prometheus.NewDesc("paddock_audit_verify_runs_total",
		"Audit chain verification runs per trigger and result. ok and failed count the recorded runs of every process "+
			"(audit_verification_run, the CLI included); error and record_error count this process's runs that could "+
			"not be verified or recorded.",
		[]string{"trigger", "result"}, nil)
	verifyTriggers = []string{TriggerNightly, TriggerSample, TriggerCLI}
)

type verifySeries struct{ trigger, result string }

// VerifyMetrics collects paddock_audit_verify_runs_total. The ok and failed series are read from
// audit_verification_run at scrape time, because `paddock-server audit verify` runs in a process of its own whose
// counters never reach the writer's /metrics (amendment 2026-10-25 to plan M8b decision 27). Runs that wrote no row
// (error, record_error) exist only in the process that saw them and are counted in memory.
type VerifyMetrics struct {
	counts  func(ctx context.Context) ([]auditstore.CountAuditVerificationRunsRow, error)
	mu      sync.Mutex
	errors  map[verifySeries]float64
	failing bool
}

func newVerifyMetrics(pool *db.AuditWriterPool) *VerifyMetrics {
	m := &VerifyMetrics{errors: map[verifySeries]float64{}}
	if pool != nil {
		m.counts = func(ctx context.Context) (rows []auditstore.CountAuditVerificationRunsRow, err error) {
			err = pool.WithSession(ctx, func(ctx context.Context, q *auditstore.Queries) error {
				rows, err = q.CountAuditVerificationRuns(ctx)
				return err
			})
			return rows, err
		}
	}
	return m
}

func (m *VerifyMetrics) countError(trigger, result string) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.errors[verifySeries{trigger, result}]++
}

// Describe implements prometheus.Collector.
func (m *VerifyMetrics) Describe(ch chan<- *prometheus.Desc) { ch <- metricVerifyRuns }

// Collect implements prometheus.Collector. A database error does not fail the scrape: only the in-memory series are
// emitted, and the error is logged once until a later scrape succeeds again.
func (m *VerifyMetrics) Collect(ch chan<- prometheus.Metric) {
	inProcess := map[verifySeries]float64{}
	for _, trigger := range verifyTriggers {
		for _, result := range []string{resultError, resultRecordError} {
			inProcess[verifySeries{trigger, result}] = 0
		}
	}
	m.mu.Lock()
	for s, v := range m.errors {
		inProcess[s] = v
	}
	m.mu.Unlock()
	for s, v := range inProcess {
		ch <- prometheus.MustNewConstMetric(metricVerifyRuns, prometheus.CounterValue, v, s.trigger, s.result)
	}
	if m.counts == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), verifyCountsLimit)
	defer cancel()
	rows, err := m.counts(ctx)
	m.mu.Lock()
	wasFailing := m.failing
	m.failing = err != nil
	m.mu.Unlock()
	if err != nil {
		if !wasFailing {
			slog.Warn("paddock_audit_verify_runs_total: reading audit_verification_run failed; ok and failed series omitted", "error", err)
		}
		return
	}
	recorded := map[verifySeries]float64{}
	for _, r := range rows {
		result := resultFailed
		if r.Ok {
			result = resultOK
		}
		recorded[verifySeries{r.Trigger, result}] += float64(r.Runs)
	}
	for _, trigger := range verifyTriggers {
		for _, result := range []string{resultOK, resultFailed} {
			ch <- prometheus.MustNewConstMetric(metricVerifyRuns, prometheus.CounterValue,
				recorded[verifySeries{trigger, result}], trigger, result)
		}
	}
}
