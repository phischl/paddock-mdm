package compiler

import (
	"context"

	"github.com/phischl/paddock-mdm/pkg/bundle"
	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
)

// loadWatchedUnits returns the presence policy of the context's organization for v2 bundles (plan M9 decision 39);
// without watched units there is no section, so a bundle of an organization that never used it is unchanged.
func loadWatchedUnits(ctx context.Context, q *pgstore.Queries) (*bundle.WatchSpec, error) {
	rows, err := q.ListWatchedUnits(ctx)
	if err != nil || len(rows) == 0 {
		return nil, err
	}
	units := make([]string, len(rows))
	for i, r := range rows {
		units[i] = r.Unit
	}
	return &bundle.WatchSpec{Units: units}, nil
}
