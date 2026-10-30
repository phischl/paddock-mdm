package app

import (
	"context"
	"fmt"
	"time"

	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/problem"
)

// StoreDeviceUserSeen is the store name of the users seen on devices in retention.purged (plan M10 decision 13).
const StoreDeviceUserSeen = "device_user_seen"

// retentionBatch is the row limit of one deletion statement; every batch commits on its own, so it bounds how long the
// rows stay locked (plan M10 amendment 2026-10-30).
const retentionBatch = 1000

// retentionPassBudget bounds one pass over one store of an organization. It stays well below the outbox reaper's
// threshold (outbox.DefaultReaperThreshold, 10 minutes): a pass still running then would be finalized as unknown
// without its deleted count. The rows left over follow in the next round (plan M10 amendment 2026-10-30).
const retentionPassBudget = 5 * time.Minute

// SpecRetentionPurged records one retention pass over one store of an organization; system principal only.
var SpecRetentionPurged = ActionSpec{Code: audit.CodeRetentionPurged}

// Retention deletes the expired rows of an organization's stores with deletion evidence (ADR 0032, plan M10 §3.3).
type Retention struct {
	runner *ActionRunner
	org    *db.OrgPool
	// unit is the length of a retention day: 24 hours, a second in development (PADDOCK_RETENTION_UNIT).
	unit time.Duration
	// budget bounds one pass (retentionPassBudget).
	budget time.Duration
}

// NewRetention creates the use cases.
func NewRetention(runner *ActionRunner, org *db.OrgPool, unit time.Duration) *Retention {
	return &Retention{runner: runner, org: org, unit: unit, budget: retentionPassBudget}
}

// PurgeUserSeen deletes the users seen on the context's organization's devices whose last login is older than
// SeenWindow at now (system principal). Without expired rows it records nothing. It returns the number of deleted rows
// (purgeBatches).
func (r *Retention) PurgeUserSeen(ctx context.Context, now time.Time) (int64, error) {
	if p, ok := principal.From(ctx); !ok || p.Kind != principal.KindSystem {
		return 0, problem.Unauthenticated
	}
	cutoff := now.Add(-time.Duration(SeenWindow/(24*time.Hour)) * r.unit)
	var expired bool
	err := r.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		var err error
		expired, err = q.HasExpiredDeviceUserSeen(ctx, cutoff)
		return err
	})
	if err != nil || !expired {
		return 0, err
	}
	return purgeBatches(ctx, r.runner, r.org, StoreDeviceUserSeen, cutoff, r.budget, func(ctx context.Context, q *pgstore.Queries) (int64, error) {
		return q.DeleteExpiredDeviceUserSeen(ctx, cutoff)
	})
}

// purgeBatches deletes a store's rows older than cutoff in batches of retentionBatch rows, each batch in its own
// transaction, and records them as one retention.purged event (plan M10 amendment 2026-10-30): a long backlog then
// never holds the locks of all its rows in one transaction, so the agents' logins do not wait for the purge. The event
// carries the rows of the committed batches; when a batch fails, the batches before it stay deleted and the event is
// recorded with outcome failure and their number. Once budget has elapsed after a committed batch, the pass ends with
// outcome success and the rows deleted so far; the rest follows in the next round.
func purgeBatches(ctx context.Context, runner *ActionRunner, org *db.OrgPool, store string, cutoff time.Time, budget time.Duration,
	batch func(ctx context.Context, q *pgstore.Queries) (int64, error)) (int64, error) {
	spec := SpecRetentionPurged
	spec.Params = map[string]any{"store": store, "cutoff": audit.Timestamp(cutoff).Format(time.RFC3339Nano)}
	var deleted int64
	err := runner.RunExternal(ctx, ScopeOrg, spec,
		func(context.Context, *pgstore.Queries, Recorder) error { return nil },
		func(ctx context.Context) error {
			start := time.Now()
			for {
				var n int64
				if err := org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
					var err error
					n, err = batch(ctx, q)
					return err
				}); err != nil {
					return fmt.Errorf("purge %s: %w", store, err)
				}
				deleted += n
				if n < retentionBatch || time.Since(start) >= budget {
					return nil
				}
			}
		},
		func(_ context.Context, _ *pgstore.Queries, rec Recorder, _ error) error {
			rec.SetParam("deleted", deleted)
			return nil
		})
	return deleted, err
}
