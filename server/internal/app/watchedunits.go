package app

import (
	"context"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/pkg/policy"
	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
	"github.com/phischl/paddock-mdm/server/internal/domain/statechange"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/problem"
)

// SpecWatchedUnitsChange is the privileged action settings.watched_units_changed: an organization administrator with a
// fresh step-up; API tokens never complete it (plan M9 decision 38).
var SpecWatchedUnitsChange = ActionSpec{Code: audit.CodeSettingsWatchedUnitsChanged, AllowedRoles: RolesAdmin, RequiresStepUp: true}

// MaxWatchedUnits bounds the watched units of an organization.
const MaxWatchedUnits = 32

// WatchedUnitSettings are the third-party units of an organization's presence policy. UpdatedAt is the time of the
// last save that left at least one unit; nil for an empty list.
type WatchedUnitSettings struct {
	Units     []string
	UpdatedAt *time.Time
}

// WatchedUnits are the use cases of the presence policy (plan M9 §3.10).
type WatchedUnits struct {
	runner *ActionRunner
	org    *db.OrgPool
}

// NewWatchedUnits creates the use cases.
func NewWatchedUnits(runner *ActionRunner, org *db.OrgPool) *WatchedUnits {
	return &WatchedUnits{runner: runner, org: org}
}

// Get returns the watched units (roles org_admin, org_operator, org_auditor).
func (w *WatchedUnits) Get(ctx context.Context) (WatchedUnitSettings, error) {
	if _, err := RequireOrg(ctx, RolesRead); err != nil {
		return WatchedUnitSettings{}, err
	}
	var out WatchedUnitSettings
	err := w.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		var err error
		out, err = loadWatchedUnits(ctx, q)
		return err
	})
	return out, err
}

// Set replaces the watched units and recompiles every device of the organization (audited:
// settings.watched_units_changed with the added and removed units and the resulting list). Every unit is checked
// with policy.ValidateUnit and must be a service; at most 32, duplicates are refused.
func (w *WatchedUnits) Set(ctx context.Context, units []string) (WatchedUnitSettings, error) {
	var out WatchedUnitSettings
	err := w.runner.RunTx(ctx, ScopeOrg, SpecWatchedUnitsChange, withChangeSet(func(ctx context.Context, q *pgstore.Queries, rec Recorder) error {
		cur, err := loadWatchedUnits(ctx, q)
		if err != nil {
			return err
		}
		next := sortedUnits(units)
		added, removed := diffUnits(cur.Units, next)
		rec.SetParam("added", added)
		rec.SetParam("removed", removed)
		rec.SetParam("units", next)
		if err := validateWatchedUnits(next); err != nil {
			return err
		}
		org, err := orgOf(ctx)
		if err != nil {
			return err
		}
		if out, err = storeWatchedUnits(ctx, q, org, next); err != nil {
			return err
		}
		rec.StateChanged(statechange.ScopeOrg, org)
		return nil
	}))
	return out, err
}

func sortedUnits(units []string) []string {
	next := slices.Clone(units)
	if next == nil {
		next = []string{}
	}
	slices.Sort(next)
	return next
}

// storeWatchedUnits replaces the stored list with validated, sorted units; the declarative path shares it so that both
// entry points apply one rule.
func storeWatchedUnits(ctx context.Context, q *pgstore.Queries, org uuid.UUID, next []string) (WatchedUnitSettings, error) {
	// Replacing the whole list keeps created_at equal to the time of the last save (the UpdatedAt of the settings).
	if err := q.DeleteWatchedUnits(ctx); err != nil {
		return WatchedUnitSettings{}, err
	}
	for _, u := range next {
		if err := q.InsertWatchedUnit(ctx, pgstore.InsertWatchedUnitParams{OrganizationID: org, Unit: u}); err != nil {
			return WatchedUnitSettings{}, err
		}
	}
	return loadWatchedUnits(ctx, q)
}

// validateWatchedUnits expects sorted units.
func validateWatchedUnits(units []string) error {
	if len(units) > MaxWatchedUnits {
		return problem.InvalidRequest.WithDetail("at most 32 watched units")
	}
	for i, u := range units {
		if i > 0 && units[i-1] == u {
			return problem.InvalidRequest.WithDetail(u + ": listed twice")
		}
		if err := policy.ValidateUnit(u); err != nil || !strings.HasSuffix(u, ".service") {
			return problem.UnitNotAllowed.WithDetail(u + ": not a watchable service unit")
		}
	}
	return nil
}

func diffUnits(cur, next []string) (added, removed []string) {
	added, removed = []string{}, []string{}
	for _, u := range next {
		if !slices.Contains(cur, u) {
			added = append(added, u)
		}
	}
	for _, u := range cur {
		if !slices.Contains(next, u) {
			removed = append(removed, u)
		}
	}
	return added, removed
}

func loadWatchedUnits(ctx context.Context, q *pgstore.Queries) (WatchedUnitSettings, error) {
	rows, err := q.ListWatchedUnits(ctx)
	if err != nil {
		return WatchedUnitSettings{}, err
	}
	out := WatchedUnitSettings{Units: make([]string, 0, len(rows))}
	for _, r := range rows {
		out.Units = append(out.Units, r.Unit)
		if out.UpdatedAt == nil || r.CreatedAt.After(*out.UpdatedAt) {
			t := r.CreatedAt
			out.UpdatedAt = &t
		}
	}
	return out, nil
}
