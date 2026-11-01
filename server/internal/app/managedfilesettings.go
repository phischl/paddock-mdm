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
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/problem"
)

// SpecManagedFileSettingsChange is the privileged action settings.managed_files_changed: an organization
// administrator with a fresh step-up; API tokens never complete it (ADR 0034 amendment 2026-10-16).
var SpecManagedFileSettingsChange = ActionSpec{Code: audit.CodeSettingsManagedFilesChanged, AllowedRoles: RolesAdmin, RequiresStepUp: true}

// MaxOperatorRoots bounds the operator roots of an organization (the column's check constraint).
const MaxOperatorRoots = 50

// ManagedFileSettings are the operator roots of an organization (plan M8s decision 7c).
type ManagedFileSettings struct {
	OperatorRoots []string
	UpdatedAt     *time.Time
}

// GetManagedFileSettings returns the operator roots (roles org_admin, org_operator, org_auditor).
func (m *ManagedConfig) GetManagedFileSettings(ctx context.Context) (ManagedFileSettings, error) {
	if _, err := RequireOrg(ctx, RolesRead); err != nil {
		return ManagedFileSettings{}, err
	}
	var out ManagedFileSettings
	err := m.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		s, err := q.GetManagedFileSettings(ctx)
		if db.IsNoRows(err) {
			out = ManagedFileSettings{OperatorRoots: []string{}}
			return nil
		}
		out = ManagedFileSettings{OperatorRoots: s.ManagedFileOperatorRoots, UpdatedAt: &s.UpdatedAt}
		return err
	})
	return out, err
}

// SetOperatorRoots replaces the operator roots (audited: settings.managed_files_changed). Existing definitions keep
// their rows; the security review lists those whose tier rose (plan M8s decision 7d).
func (m *ManagedConfig) SetOperatorRoots(ctx context.Context, roots []string) (ManagedFileSettings, error) {
	var out ManagedFileSettings
	err := m.runner.RunTx(ctx, ScopeOrg, SpecManagedFileSettingsChange, withChangeSet(func(ctx context.Context, q *pgstore.Queries, rec Recorder) error {
		old, err := operatorRoots(ctx, q)
		if err != nil {
			return err
		}
		rec.SetParam("old_operator_roots", old)
		next, err := normalizeOperatorRoots(roots)
		rec.SetParam("operator_roots", next)
		if err != nil {
			return err
		}
		org, err := orgOf(ctx)
		if err != nil {
			return err
		}
		p, _ := principal.From(ctx)
		s, err := q.UpsertManagedFileSettings(ctx, pgstore.UpsertManagedFileSettingsParams{
			OrganizationID: org, ManagedFileOperatorRoots: next,
			UpdatedBy: uuid.NullUUID{UUID: p.ID, Valid: p.Kind == principal.KindAdmin && p.ID != uuid.Nil},
		})
		out = ManagedFileSettings{OperatorRoots: s.ManagedFileOperatorRoots, UpdatedAt: &s.UpdatedAt}
		return err
	}))
	return out, err
}

// normalizeOperatorRoots trims, sorts and deduplicates roots and checks each with policy.ValidateOperatorRoot; a
// refused root is 422 path_not_allowed naming it.
func normalizeOperatorRoots(roots []string) ([]string, error) {
	out := sortedRoots(roots)
	if len(out) > MaxOperatorRoots {
		return out, problem.InvalidRequest.WithDetail("at most 50 operator roots")
	}
	for _, r := range out {
		if err := policy.ValidateOperatorRoot(r); err != nil {
			return out, problem.PathNotAllowed.WithDetail(r + ": " + err.Error())
		}
	}
	return out, nil
}

// sortedRoots trims, sorts and deduplicates roots, so that the same set always compares equal.
func sortedRoots(roots []string) []string {
	out := []string{}
	for _, r := range roots {
		out = append(out, strings.TrimSpace(r))
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// operatorRoots reads the operator roots inside an organization transaction; without a row the list is empty.
func operatorRoots(ctx context.Context, q *pgstore.Queries) ([]string, error) {
	s, err := q.GetManagedFileSettings(ctx)
	if db.IsNoRows(err) {
		return []string{}, nil
	}
	return s.ManagedFileOperatorRoots, err
}
