package auditwriter

import (
	"context"
	"encoding/json"
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

// AckPublisher publishes with publisher confirms (mq.Publisher).
type AckPublisher interface {
	PublishBatch(ctx context.Context, exchange string, msgs []mq.Message) ([]error, error)
}

// Retirement closes the audit log of a deleting organization on the worker's organization.audit_retirement_requested
// (plan M17 decision 16, amendment 2026-11-15 o): it marks the organization retired, so that its later events go to the
// platform pseudo-organization, verifies its whole sealed chain once, records the result with final: true as the last
// event of the organization's log and acknowledges it to the worker on paddock.offboarding.
type Retirement struct {
	pool     *db.AuditWriterPool
	writer   *Writer
	verifier chainVerifier
	metrics  *VerifyMetrics
	acks     AckPublisher
	now      func() time.Time
}

// NewRetirement creates the retirement; recorder's collector counts its runs.
func NewRetirement(pool *db.AuditWriterPool, writer *Writer, verifier chainVerifier, recorder *Recorder, acks AckPublisher) *Retirement {
	return &Retirement{pool: pool, writer: writer, verifier: verifier, metrics: recorder.metrics, acks: acks, now: recorder.now}
}

// Handle is Writer.Handle that also retires the organizations whose retirement a batch requests.
func (r *Retirement) Handle(ctx context.Context, _ *amqp.Channel, deliveries <-chan amqp.Delivery) error {
	return r.writer.consume(ctx, deliveries, r.Retire)
}

// Retire retires org once; a repeated request finds the recorded result and only acknowledges it again when the broker
// has not confirmed the acknowledgement yet. A failed publish is no error: RunAcks republishes it.
func (r *Retirement) Retire(ctx context.Context, org uuid.UUID) error {
	// The writers of org hold its commit-sequence lock until they commit (writeGroupOnce), so once this commits no
	// event of org is written into its log except the final verification.
	err := r.pool.InWriter(ctx, func(ctx context.Context, q *auditstore.Queries) error {
		if _, err := q.LockOrgSeq(ctx, org); err != nil {
			return err
		}
		return q.InsertAuditOrgRetired(ctx, org)
	})
	if err != nil {
		return fmt.Errorf("auditwriter: close the log of %s: %w", org, err)
	}
	row, err := r.retired(ctx, org)
	if err != nil {
		return err
	}
	if row.FinalVerifiedAt == nil {
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
		if row, err = r.retired(ctx, org); err != nil {
			return err
		}
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

// finalVerification verifies every sealed day of org, writes audit.chain_verified or audit.chain_verification_failed
// with final: true into org's log and records the run, and returns the outcome of the run of record.
func (r *Retirement) finalVerification(ctx context.Context, org uuid.UUID) (string, error) {
	runID, eventID := finalIDs(org)
	started := r.now()
	from, to, sealed, err := r.sealedRange(ctx, org, started)
	if err != nil {
		return "", err
	}
	report := &Report{}
	if sealed {
		if report, err = r.verifier.Verify(ctx, org, from, to); err != nil {
			return "", fmt.Errorf("auditwriter: final verification of %s: %w", org, err)
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
		"from", from.Format(time.DateOnly), "to", to.Format(time.DateOnly), "outcome", outcome,
		"problems", len(report.Problems))
	return outcome, nil
}

// sealedRange is org's first day through its newest manifest; sealed is false when org has no manifest yet, and the
// range is then the day of now.
func (r *Retirement) sealedRange(ctx context.Context, org uuid.UUID, now time.Time) (from, to time.Time, sealed bool, err error) {
	err = r.pool.WithSession(ctx, func(ctx context.Context, q *auditstore.Queries) error {
		latest, err := q.GetLatestAuditManifest(ctx, org)
		if db.IsNoRows(err) {
			return nil
		}
		if err != nil {
			return err
		}
		first, err := q.FirstAuditDay(ctx, org)
		if err != nil {
			return err
		}
		from, to, sealed = dayOf(first), dayOf(latest.Day), true
		return nil
	})
	if err != nil {
		return from, to, false, fmt.Errorf("auditwriter: sealed days of %s: %w", org, err)
	}
	if !sealed {
		from, to = dayOf(now), dayOf(now)
	}
	return from, to, sealed, nil
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
