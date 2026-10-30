package app

import (
	"context"
	"time"

	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/problem"
)

// StoreDeviceUserSeen is the store name of the users seen on devices in retention.purged (plan M10 decision 13).
const StoreDeviceUserSeen = "device_user_seen"

// retentionBatch is the row limit of one deletion statement; it bounds the lock scope, not the transaction.
const retentionBatch = 1000

// SpecRetentionPurged records one retention pass over one store of an organization; system principal only.
var SpecRetentionPurged = ActionSpec{Code: audit.CodeRetentionPurged}

// Retention deletes the expired rows of an organization's stores with deletion evidence (ADR 0032, plan M10 §3.3).
type Retention struct {
	runner *ActionRunner
	org    *db.OrgPool
	// unit is the length of a retention day: 24 hours, a second in development (PADDOCK_RETENTION_UNIT).
	unit time.Duration
}

// NewRetention creates the use cases.
func NewRetention(runner *ActionRunner, org *db.OrgPool, unit time.Duration) *Retention {
	return &Retention{runner: runner, org: org, unit: unit}
}

// PurgeUserSeen deletes the users seen on the context's organization's devices whose last login is older than
// SeenWindow at now, in batches of 1 000 rows inside one transaction with its retention.purged event, so evidence and
// deletion commit or roll back together. Without expired rows it records nothing. It returns the number of deleted
// rows; a failure rolls every batch back and records the event with outcome failure and deleted 0.
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
	spec := SpecRetentionPurged
	spec.Params = map[string]any{
		"store": StoreDeviceUserSeen, "cutoff": audit.Timestamp(cutoff).Format(time.RFC3339Nano), "deleted": int64(0),
	}
	var deleted int64
	err = r.runner.RunTx(ctx, ScopeOrg, spec, func(ctx context.Context, q *pgstore.Queries, rec Recorder) error {
		for {
			n, err := q.DeleteExpiredDeviceUserSeen(ctx, cutoff)
			if err != nil {
				return err
			}
			deleted += n
			if n < retentionBatch {
				break
			}
		}
		rec.SetParam("deleted", deleted)
		return nil
	})
	if err != nil {
		return 0, err
	}
	return deleted, nil
}
