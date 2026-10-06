package outbox

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
)

var metricReaped = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "paddock_actions_reaped_total", Help: "Stuck actions finalized with outcome unknown.",
}, []string{"code"})

// DefaultReaperThreshold is the production age after which a started action is finalized as unknown.
const DefaultReaperThreshold = 10 * time.Minute

// Reaper finalizes actions stuck in status started (a crash between an external call and its recording).
type Reaper struct {
	pool      *db.RelayPool
	threshold time.Duration
	now       func() time.Time
}

// NewReaper creates a reaper; threshold is DefaultReaperThreshold outside development.
func NewReaper(pool *db.RelayPool, threshold time.Duration) *Reaper {
	return &Reaper{pool: pool, threshold: threshold, now: time.Now}
}

// Run finalizes stuck actions every 60 s until ctx ends.
func (r *Reaper) Run(ctx context.Context) {
	for {
		if n, err := r.RunOnce(ctx); err != nil {
			slog.WarnContext(ctx, "reaper failed", "error", err)
		} else if n > 0 {
			slog.WarnContext(ctx, "reaper finalized stuck actions with outcome unknown", "count", n)
		}
		if !sleep(ctx, 60*time.Second) {
			return
		}
	}
}

// RunOnce finalizes every action older than the threshold, one transaction per row. The event keeps the original
// action code; outcome=unknown, error_code="reaped".
func (r *Reaper) RunOnce(ctx context.Context) (int, error) {
	count := 0
	for {
		var done bool
		err := r.pool.InRelay(ctx, func(ctx context.Context, q *pgstore.Queries) error {
			rows, err := q.ListStaleActions(ctx, pgstore.ListStaleActionsParams{
				StartedBefore: r.now().Add(-r.threshold), MaxRows: 1,
			})
			if err != nil {
				return err
			}
			if len(rows) == 0 {
				done = true
				return nil
			}
			return r.finalize(ctx, q, rows[0])
		})
		if err != nil {
			return count, err
		}
		if done {
			return count, nil
		}
		count++
	}
}

func (r *Reaper) finalize(ctx context.Context, q *pgstore.Queries, a pgstore.Action) error {
	var actor audit.Actor
	if err := json.Unmarshal(a.Actor, &actor); err != nil {
		return err
	}
	var target *audit.Target
	if len(a.Target) > 0 && string(a.Target) != "null" {
		target = &audit.Target{}
		if err := json.Unmarshal(a.Target, target); err != nil {
			return err
		}
	}
	params := map[string]any{}
	if err := json.Unmarshal(a.Params, &params); err != nil {
		return err
	}
	finished := audit.Timestamp(r.now())
	outcome, errorCode := string(audit.OutcomeUnknown), "reaped"
	if _, err := q.FinishAction(ctx, pgstore.FinishActionParams{
		ID: a.ID, Outcome: &outcome, ErrorCode: &errorCode, Target: a.Target, Params: a.Params,
		OrganizationID: a.OrganizationID, FinishedAt: &finished,
	}); err != nil {
		return err
	}
	source := audit.SourceForActor(actor.Type)
	payload, err := json.Marshal(audit.Event{
		Schema: audit.Schema, EventID: a.ID, OrganizationID: a.OrganizationID, OccurredAt: finished,
		Code: audit.Code(a.Code), Outcome: audit.OutcomeUnknown, Actor: actor, Target: target, Source: source,
		Params: params, ErrorCode: errorCode, CorrelationID: a.CorrelationID,
	})
	if err != nil {
		return err
	}
	if err := q.InsertOutbox(ctx, pgstore.InsertOutboxParams{
		OrganizationID: a.OrganizationID, Subject: audit.Subject(a.OrganizationID, source), MsgID: a.ID.String(),
		Payload: payload,
	}); err != nil {
		return err
	}
	metricReaped.WithLabelValues(string(audit.CodeActionFinalizedUnknown)).Inc()
	slog.WarnContext(ctx, "action finalized as unknown", "action_id", a.ID, "code", a.Code, "started_at", a.StartedAt)
	return nil
}
