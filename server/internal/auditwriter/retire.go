package auditwriter

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	amqp "github.com/rabbitmq/amqp091-go"

	"github.com/phischl/paddock-mdm/server/internal/adapters/auditpg/auditstore"
	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
	"github.com/phischl/paddock-mdm/server/internal/domain/offboarding"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/platform/mq"
)

// TriggerFinal is the trigger of the final verification of a deleting organization's chain (ADR 0052 decision 6).
const TriggerFinal = "final"

// AckRepublishInterval is how often the writer republishes acknowledgements the broker has not confirmed (plan M17
// amendment 2026-11-15 o point 5).
const AckRepublishInterval = 5 * time.Minute

// RetirementInterval is how often the retirement loop looks for retirements to complete; a request the consumer
// closed wakes it at once.
const RetirementInterval = 5 * time.Minute

// RetirementRequestWindow is how far back the retirement loop reads the index for requests whose audit_org_retired row
// is missing. It exceeds every realistic outage of the audit writer: the worker records the request once.
const RetirementRequestWindow = 90 * 24 * time.Hour

// AckPublisher publishes with publisher confirms (mq.Publisher).
type AckPublisher interface {
	PublishBatch(ctx context.Context, exchange string, msgs []mq.Message) ([]error, error)
}

// finalVerifier is the part of Verifier the final verification uses.
type finalVerifier interface {
	Verify(ctx context.Context, org uuid.UUID, from, to time.Time) (*Report, error)
	VerifyUnsealed(ctx context.Context, org uuid.UUID, after, to time.Time, report *Report) error
}

// preSealer seals the days of a retiring organization before its final verification (Sealer.sealBeforeFinal).
type preSealer interface {
	sealBeforeFinal(ctx context.Context, org uuid.UUID) (int, error)
}

// Retirement closes the audit log of a deleting organization on the worker's organization.audit_retirement_requested
// (plan M17 decision 16, amendment 2026-11-15 o). The consumer only closes the log: it inserts audit_org_retired under
// the organization's commit-sequence lock, so later events go to the platform pseudo-organization, and acknowledges the
// batch. RunRetirements completes every closed log without a recorded final verification: it seals the days that may be
// sealed, verifies the whole chain and the unsealed tail, records the result with final: true as the last event of the
// organization's log and acknowledges it to the worker on paddock.offboarding. A slow or failing verification therefore
// never holds the audit queue, a failure is retried by the loop, and a crash resumes from the table.
type Retirement struct {
	pool     *db.AuditWriterPool
	writer   *Writer
	verifier finalVerifier
	sealer   preSealer
	metrics  *VerifyMetrics
	acks     AckPublisher
	now      func() time.Time
	wake     chan struct{}
	// beforeClose, set only by tests (export_test.go), fails Close to simulate a database error in the consumer path.
	beforeClose func(org uuid.UUID) error
}

// NewRetirement creates the retirement; recorder's collector counts its runs.
func NewRetirement(pool *db.AuditWriterPool, writer *Writer, verifier *Verifier, sealer *Sealer, recorder *Recorder,
	acks AckPublisher) *Retirement {
	return &Retirement{pool: pool, writer: writer, verifier: verifier, sealer: sealer, metrics: recorder.metrics, acks: acks,
		now: recorder.now, wake: make(chan struct{}, 1)}
}

// Handle is Writer.Handle that also closes the logs of the organizations whose retirement a batch requests.
func (r *Retirement) Handle(ctx context.Context, _ *amqp.Channel, deliveries <-chan amqp.Delivery) error {
	return r.writer.consume(ctx, deliveries, r.Close)
}

// Close closes org's log: once it commits, no event of org is written into its log except the final verification
// (the writers of org hold its commit-sequence lock until they commit, writeGroupOnce). It is idempotent and wakes
// the retirement loop.
func (r *Retirement) Close(ctx context.Context, org uuid.UUID) error {
	if r.beforeClose != nil {
		if err := r.beforeClose(org); err != nil {
			return err
		}
	}
	err := r.pool.InWriter(ctx, func(ctx context.Context, q *auditstore.Queries) error {
		if _, err := q.LockOrgSeq(ctx, org); err != nil {
			return err
		}
		return q.InsertAuditOrgRetired(ctx, org)
	})
	if err != nil {
		return fmt.Errorf("auditwriter: close the log of %s: %w", org, err)
	}
	select {
	case r.wake <- struct{}{}:
	default:
	}
	return nil
}

// RunRetirements completes retirements at start, when the consumer closed a log, and every RetirementInterval, until
// ctx ends.
func (r *Retirement) RunRetirements(ctx context.Context) {
	for {
		if err := r.Complete(ctx); err != nil && ctx.Err() == nil {
			slog.WarnContext(ctx, "completing retired organizations failed; retried", "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-r.wake:
		case <-time.After(RetirementInterval):
		}
	}
}

// Complete closes the logs of indexed requests that have no audit_org_retired row yet, then runs the final
// verification of every closed log without one. A failing organization does not stop the others; their errors are
// returned together and retried at the next call.
func (r *Retirement) Complete(ctx context.Context) error {
	var requested, pending []uuid.UUID
	err := r.pool.WithSession(ctx, func(ctx context.Context, q *auditstore.Queries) error {
		var err error
		requested, err = q.ListAuditRetirementRequestsWithoutRow(ctx, auditstore.ListAuditRetirementRequestsWithoutRowParams{
			PlatformOrganizationID: audit.PlatformOrganizationID, Since: r.now().Add(-RetirementRequestWindow)})
		return err
	})
	if err != nil {
		return fmt.Errorf("auditwriter: list retirement requests: %w", err)
	}
	var errs []error
	for _, org := range requested {
		errs = append(errs, r.Close(ctx, org))
	}
	err = r.pool.WithSession(ctx, func(ctx context.Context, q *auditstore.Queries) error {
		var err error
		pending, err = q.ListAuditOrgRetiredPending(ctx)
		return err
	})
	if err != nil {
		return errors.Join(append(errs, fmt.Errorf("auditwriter: list pending retirements: %w", err))...)
	}
	for _, org := range pending {
		if ctx.Err() != nil {
			break
		}
		errs = append(errs, r.finalize(ctx, org))
	}
	return errors.Join(errs...)
}

// finalize records org's final verification and acknowledges it.
func (r *Retirement) finalize(ctx context.Context, org uuid.UUID) error {
	outcome, err := r.finalVerification(ctx, org)
	if err != nil {
		r.metrics.countError(TriggerFinal, resultError)
		return err
	}
	err = r.pool.InWriter(ctx, func(ctx context.Context, q *auditstore.Queries) error {
		return q.RecordAuditOrgRetiredVerification(ctx, auditstore.RecordAuditOrgRetiredVerificationParams{
			OrganizationID: org, FinalOutcome: &outcome})
	})
	if err != nil {
		return fmt.Errorf("auditwriter: record the final verification of %s: %w", org, err)
	}
	row, err := r.retired(ctx, org)
	if err != nil {
		return err
	}
	if row.AckPublishedAt == nil {
		r.acknowledge(ctx, row)
	}
	return nil
}

func (r *Retirement) retired(ctx context.Context, org uuid.UUID) (auditstore.AuditOrgRetired, error) {
	var row auditstore.AuditOrgRetired
	err := r.pool.InWriter(ctx, func(ctx context.Context, q *auditstore.Queries) error {
		var err error
		row, err = q.GetAuditOrgRetired(ctx, org)
		return err
	})
	if err != nil {
		return row, fmt.Errorf("auditwriter: read the retirement of %s: %w", org, err)
	}
	return row, nil
}

// finalIDs are the fixed run and event IDs of org's final verification, so that a retry after a crash finds the first
// event and run instead of recording a second final verification.
func finalIDs(org uuid.UUID) (runID, eventID uuid.UUID) {
	return uuid.NewSHA1(uuid.NameSpaceURL, []byte("urn:paddock:audit:final-run:"+org.String())),
		uuid.NewSHA1(uuid.NameSpaceURL, []byte("urn:paddock:audit:final-event:"+org.String()))
}

// finalVerification seals what may be sealed, verifies every sealed day of org and every object of the days after the
// newest manifest (the unsealed tail, through the day after now, where a write may file its object), writes
// audit.chain_verified or audit.chain_verification_failed with final: true into org's log, records the run, and
// returns the outcome of the run of record. The final event's own object is written after the check and verified
// offline (paddockctl audit verify-export) with its retired day.
func (r *Retirement) finalVerification(ctx context.Context, org uuid.UUID) (string, error) {
	runID, eventID := finalIDs(org)
	if _, err := r.sealer.sealBeforeFinal(ctx, org); err != nil {
		return "", fmt.Errorf("auditwriter: seal %s before its final verification: %w", org, err)
	}
	started := r.now()
	first, newest, objects, sealed, err := r.chainDays(ctx, org)
	if err != nil {
		return "", err
	}
	report := &Report{}
	from, to := dayOf(started), dayOf(started)
	if sealed {
		from, to = first, newest
		if report, err = r.verifier.Verify(ctx, org, from, to); err != nil {
			return "", fmt.Errorf("auditwriter: final verification of %s: %w", org, err)
		}
	}
	if objects {
		after := newest
		if !sealed {
			after = first.AddDate(0, 0, -1)
		}
		if err := r.verifier.VerifyUnsealed(ctx, org, after, dayOf(started).AddDate(0, 0, 1), report); err != nil {
			return "", fmt.Errorf("auditwriter: final verification of %s's unsealed days: %w", org, err)
		}
	}
	ev, err := verificationEvent(org, runID, TriggerFinal, from, to, r.now(), report)
	if err != nil {
		return "", err
	}
	ev.EventID = eventID
	ev.Params["final"] = true
	if _, err := r.writer.writeGroup(ctx, org, []audit.Event{ev}, true); err != nil {
		return "", fmt.Errorf("auditwriter: write the final verification of %s: %w", org, err)
	}
	problems, err := json.Marshal(cappedProblems(report.Problems))
	if err != nil {
		return "", err
	}
	var ok bool
	err = r.pool.InWriter(ctx, func(ctx context.Context, q *auditstore.Queries) error {
		if err := q.InsertAuditVerificationRunOnce(ctx, auditstore.InsertAuditVerificationRunOnceParams{
			ID: runID, OrganizationID: org, Trigger: TriggerFinal, FromDay: from, ToDay: to, StartedAt: started,
			FinishedAt: ev.OccurredAt, Days: int32(report.Days), Objects: int32(report.Objects), //nolint:gosec // bounded by the day range and the index
			Ok: report.OK(), Problems: problems, EventID: eventID,
		}); err != nil {
			return err
		}
		ok, err = q.GetAuditVerificationRunOK(ctx, runID)
		return err
	})
	if err != nil {
		return "", fmt.Errorf("auditwriter: record the final verification run of %s: %w", org, err)
	}
	outcome := offboarding.AuditFinalVerified
	if !ok {
		outcome = offboarding.AuditFinalFailed
	}
	slog.InfoContext(ctx, "final audit chain verification recorded", "organization_id", org, "run_id", runID,
		"from", from.Format(time.DateOnly), "to", to.Format(time.DateOnly), "objects", report.Objects, "outcome", outcome,
		"problems", len(report.Problems))
	return outcome, nil
}

// chainDays is org's first day and newest manifest day; sealed is false without a manifest, objects false without an
// indexed object.
func (r *Retirement) chainDays(ctx context.Context, org uuid.UUID) (first, newest time.Time, objects, sealed bool, err error) {
	err = r.pool.WithSession(ctx, func(ctx context.Context, q *auditstore.Queries) error {
		_, err := q.LastAuditObjectDay(ctx, org)
		switch {
		case err == nil:
			objects = true
		case !db.IsNoRows(err):
			return err
		}
		latest, err := q.GetLatestAuditManifest(ctx, org)
		switch {
		case err == nil:
			sealed, newest = true, dayOf(latest.Day)
		case !db.IsNoRows(err):
			return err
		}
		if !objects && !sealed {
			return nil
		}
		f, err := q.FirstAuditDay(ctx, org)
		first = dayOf(f)
		return err
	})
	if err != nil {
		err = fmt.Errorf("auditwriter: days of %s: %w", org, err)
	}
	return first, newest, objects, sealed, err
}

// acknowledge publishes the recorded outcome of row to the worker and marks it published once the broker confirmed.
// A failure is logged; RunAcks retries it.
func (r *Retirement) acknowledge(ctx context.Context, row auditstore.AuditOrgRetired) {
	if row.FinalVerifiedAt == nil || row.FinalOutcome == nil {
		return
	}
	body, err := json.Marshal(offboarding.AuditRetired{OrganizationID: row.OrganizationID, FinalOutcome: *row.FinalOutcome,
		FinalVerifiedAt: row.FinalVerifiedAt.UTC()})
	if err == nil {
		var res []error
		res, err = r.acks.PublishBatch(ctx, mq.ExchangeOffboarding, []mq.Message{{
			RoutingKey: mq.AuditRetiredRoutingKey(row.OrganizationID), MessageID: "audit_retired." + row.OrganizationID.String(),
			Body: body}})
		if err == nil && len(res) == 1 {
			err = res[0]
		}
	}
	if err == nil {
		err = r.pool.InWriter(ctx, func(ctx context.Context, q *auditstore.Queries) error {
			return q.MarkAuditOrgRetiredAcknowledged(ctx, row.OrganizationID)
		})
	}
	if err != nil {
		slog.WarnContext(ctx, "acknowledging a retired organization failed; republished later", "organization_id",
			row.OrganizationID, "error", err)
		return
	}
	slog.InfoContext(ctx, "retired organization acknowledged", "organization_id", row.OrganizationID, "outcome", *row.FinalOutcome)
}

// Republish acknowledges every recorded retirement the broker has not confirmed yet.
func (r *Retirement) Republish(ctx context.Context) error {
	var rows []auditstore.AuditOrgRetired
	err := r.pool.WithSession(ctx, func(ctx context.Context, q *auditstore.Queries) error {
		var err error
		rows, err = q.ListAuditOrgRetiredUnacknowledged(ctx)
		return err
	})
	if err != nil {
		return fmt.Errorf("auditwriter: list unacknowledged retirements: %w", err)
	}
	for _, row := range rows {
		r.acknowledge(ctx, row)
	}
	return nil
}

// RunAcks republishes at start and every AckRepublishInterval until ctx ends.
func (r *Retirement) RunAcks(ctx context.Context) {
	for {
		if err := r.Republish(ctx); err != nil {
			slog.WarnContext(ctx, "republishing retirement acknowledgements failed", "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(AckRepublishInterval):
		}
	}
}
