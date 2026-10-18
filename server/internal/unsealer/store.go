package unsealer

import (
	"context"

	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/domain/autounseal"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
)

// PGStore is the Store on the pool of role paddock_unsealer.
type PGStore struct{ pool *db.UnsealerPool }

// NewPGStore creates the store.
func NewPGStore(pool *db.UnsealerPool) *PGStore { return &PGStore{pool: pool} }

// State reads the setting.
func (s *PGStore) State(ctx context.Context) (autounseal.State, error) {
	var state autounseal.State
	err := s.pool.InUnsealer(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		row, err := q.GetAutoUnseal(ctx)
		state = autounseal.State(row.State)
		return err
	})
	return state, err
}

// Report records that the unsealer ran and whether it holds shares.
func (s *PGStore) Report(ctx context.Context, sharesPresent bool) error {
	return s.pool.InUnsealer(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		return q.ReportUnsealer(ctx, sharesPresent)
	})
}

// RecordUnseal counts one automatic unseal.
func (s *PGStore) RecordUnseal(ctx context.Context) error {
	return s.pool.InUnsealer(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		return q.RecordUnseal(ctx)
	})
}

// RecordFailure counts one failed attempt with its reason (a FailureReason* constant).
func (s *PGStore) RecordFailure(ctx context.Context, reason string) error {
	return s.pool.InUnsealer(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		return q.RecordUnsealFailure(ctx, &reason)
	})
}
