package compiler

import (
	"context"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/pkg/bundle"
	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/app"
)

// orgUpdates are the organization's update settings and package holds, loaded once per compile round.
type orgUpdates struct {
	settings app.UpdateSettings
	holds    []pgstore.PackageHold
}

// loadUpdates returns the update settings and holds of the context's organization (plan M5b decision 4).
func loadUpdates(ctx context.Context, q *pgstore.Queries) (*orgUpdates, error) {
	s, err := app.LoadUpdateSettings(ctx, q)
	if err != nil {
		return nil, err
	}
	holds, err := q.ListAllPackageHolds(ctx)
	if err != nil {
		return nil, err
	}
	return &orgUpdates{settings: s, holds: holds}, nil
}

// section returns the updates section of a device in groups.
func (u *orgUpdates) section(groups []uuid.UUID) *bundle.UpdatesSpec {
	return app.UpdatesSection(u.settings, u.holds, groups)
}
