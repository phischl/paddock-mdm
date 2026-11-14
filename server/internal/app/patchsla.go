package app

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
	"github.com/phischl/paddock-mdm/server/internal/domain/patchsla"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/problem"
)

// SpecPatchSLASettings is the privileged action settings.patch_sla_changed (plan M13c decision 17).
var SpecPatchSLASettings = ActionSpec{Code: audit.CodeSettingsPatchSLAChanged, AllowedRoles: RolesAdmin}

// PatchSLASettings are the organization's patch SLA and when it last changed.
type PatchSLASettings struct {
	patchsla.SLA
	UpdatedAt time.Time
}

// PatchSLA are the use cases of the organization's patch SLA (plan M13c decision 17).
type PatchSLA struct {
	runner *ActionRunner
	org    *db.OrgPool
}

// NewPatchSLA creates the use cases.
func NewPatchSLA(runner *ActionRunner, org *db.OrgPool) *PatchSLA {
	return &PatchSLA{runner: runner, org: org}
}

// LoadPatchSLA returns the organization's patch SLA in an organization transaction; the defaults without a row (the
// trigger of migration 00130 creates one for every organization).
func LoadPatchSLA(ctx context.Context, q *pgstore.Queries) (PatchSLASettings, error) {
	s, err := q.GetPatchSLA(ctx)
	if db.IsNoRows(err) {
		return PatchSLASettings{SLA: patchsla.Defaults()}, nil
	}
	if err != nil {
		return PatchSLASettings{}, err
	}
	return toPatchSLASettings(s), nil
}

func toPatchSLASettings(s pgstore.OrganizationPatchSla) PatchSLASettings {
	return PatchSLASettings{SLA: patchsla.SLA{CriticalDays: int(s.CriticalDays), HighDays: int(s.HighDays),
		MediumDays: int(s.MediumDays), LowDays: int(s.LowDays)}, UpdatedAt: s.UpdatedAt}
}

// Get returns the organization's patch SLA (org_admin, org_operator, org_auditor).
func (p *PatchSLA) Get(ctx context.Context) (PatchSLASettings, error) {
	if _, err := RequireOrg(ctx, RolesRead); err != nil {
		return PatchSLASettings{}, err
	}
	var out PatchSLASettings
	err := p.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		var err error
		out, err = LoadPatchSLA(ctx, q)
		return err
	})
	return out, err
}

// Update replaces the organization's patch SLA (audited: settings.patch_sla_changed with the four new values).
func (p *PatchSLA) Update(ctx context.Context, in patchsla.SLA) (PatchSLASettings, error) {
	spec := SpecPatchSLASettings
	if org, err := orgOf(ctx); err == nil {
		spec.Target = &audit.Target{Type: "organization", ID: org.String()}
	}
	spec.Params = map[string]any{"critical_days": in.CriticalDays, "high_days": in.HighDays, "medium_days": in.MediumDays,
		"low_days": in.LowDays}
	var out PatchSLASettings
	err := p.runner.RunTx(ctx, ScopeOrg, spec, withChangeSet(func(ctx context.Context, q *pgstore.Queries, _ Recorder) error {
		var err error
		pr, _ := principal.From(ctx)
		out, err = upsertPatchSLA(ctx, q, pr, in)
		return err
	}))
	return out, err
}

// upsertPatchSLA validates and stores the SLA in an organization transaction (API and declarative apply).
func upsertPatchSLA(ctx context.Context, q *pgstore.Queries, pr principal.Principal, in patchsla.SLA) (PatchSLASettings, error) {
	if err := in.Validate(); err != nil {
		return PatchSLASettings{}, problem.InvalidRequest.WithDetail(err.Error())
	}
	s, err := q.UpsertPatchSLA(ctx, pgstore.UpsertPatchSLAParams{
		OrganizationID: pr.OrganizationID,
		CriticalDays:   int32(in.CriticalDays), //nolint:gosec // validated 0–365
		HighDays:       int32(in.HighDays),     //nolint:gosec // validated 0–365
		MediumDays:     int32(in.MediumDays),   //nolint:gosec // validated 0–365
		LowDays:        int32(in.LowDays),      //nolint:gosec // validated 0–365
		UpdatedBy:      uuid.NullUUID{UUID: pr.ID, Valid: pr.ID != uuid.Nil},
	})
	if err != nil {
		return PatchSLASettings{}, err
	}
	return toPatchSLASettings(s), nil
}
