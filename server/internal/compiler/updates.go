package compiler

import (
	"context"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/pkg/bundle"
	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/domain/updates"
)

// orgUpdates are the organization's update settings and package holds, loaded once per compile round.
type orgUpdates struct {
	settings app.UpdateSettings
	holds    []pgstore.PackageHold
	// groupPolicies are the agent update policy overrides of the organization's device groups (nil = inherit).
	groupPolicies map[uuid.UUID]*string
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
	groups, err := q.ListAllDeviceGroups(ctx)
	if err != nil {
		return nil, err
	}
	policies := make(map[uuid.UUID]*string, len(groups))
	for _, g := range groups {
		policies[g.ID] = g.AgentUpdatePolicy
	}
	return &orgUpdates{settings: s, holds: holds, groupPolicies: policies}, nil
}

// updatePolicy returns the agent update policy of a device in groups (plan M8d decision 22).
func (u *orgUpdates) updatePolicy(groups []uuid.UUID) string {
	overrides := make([]*string, 0, len(groups))
	for _, g := range groups {
		overrides = append(overrides, u.groupPolicies[g])
	}
	return updates.BundleUpdatePolicy(u.settings.AgentUpdatePolicy, overrides)
}

// section returns the updates section of a device in groups.
func (u *orgUpdates) section(groups []uuid.UUID) *bundle.UpdatesSpec {
	return app.UpdatesSection(u.settings, u.holds, groups)
}
