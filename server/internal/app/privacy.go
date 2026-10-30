package app

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/problem"
)

// Bounds and default of PrivacySettings.RetiredInventoryDays (plan M10 §6.1).
const (
	RetiredInventoryDaysMin     = 1
	RetiredInventoryDaysMax     = 365
	RetiredInventoryDaysDefault = 30
)

// SpecPrivacySettings is the privileged action settings.privacy_changed (plan M10 decision 8).
var SpecPrivacySettings = ActionSpec{Code: audit.CodeSettingsPrivacyChanged, AllowedRoles: RolesAdmin}

// PrivacySettings are the privacy settings of an organization (ADR 0032 §2): how long the inventory of a retired
// device is kept and whether audit searches and inventory views are recorded.
type PrivacySettings struct {
	RetiredInventoryDays  int
	AuditSearchRecorded   bool
	InventoryViewRecorded bool
	UpdatedAt             time.Time
}

// Validate checks the bounds of the settings.
func (s PrivacySettings) Validate() error {
	if s.RetiredInventoryDays < RetiredInventoryDaysMin || s.RetiredInventoryDays > RetiredInventoryDaysMax {
		return fmt.Errorf("retired_inventory_days must be between %d and %d", RetiredInventoryDaysMin, RetiredInventoryDaysMax)
	}
	return nil
}

// Privacy are the use cases of the organization's privacy settings (plan M10 decisions 7–8).
type Privacy struct {
	runner *ActionRunner
	org    *db.OrgPool
}

// NewPrivacy creates the use cases.
func NewPrivacy(runner *ActionRunner, org *db.OrgPool) *Privacy {
	return &Privacy{runner: runner, org: org}
}

// LoadPrivacySettings returns the organization's privacy settings in an organization transaction; the defaults
// without a row (the trigger of migration 00074 creates one for every organization).
func LoadPrivacySettings(ctx context.Context, q *pgstore.Queries) (PrivacySettings, error) {
	s, err := q.GetPrivacySettings(ctx)
	if db.IsNoRows(err) {
		return PrivacySettings{RetiredInventoryDays: RetiredInventoryDaysDefault}, nil
	}
	if err != nil {
		return PrivacySettings{}, err
	}
	return toPrivacySettings(s), nil
}

func toPrivacySettings(s pgstore.OrganizationPrivacySetting) PrivacySettings {
	return PrivacySettings{
		RetiredInventoryDays: int(s.RetiredInventoryDays), AuditSearchRecorded: s.AuditSearchRecorded,
		InventoryViewRecorded: s.InventoryViewRecorded, UpdatedAt: s.UpdatedAt,
	}
}

// Get returns the organization's privacy settings.
func (p *Privacy) Get(ctx context.Context) (PrivacySettings, error) {
	if _, err := RequireOrg(ctx, RolesRead); err != nil {
		return PrivacySettings{}, err
	}
	var out PrivacySettings
	err := p.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		var err error
		out, err = LoadPrivacySettings(ctx, q)
		return err
	})
	return out, err
}

// Update replaces the organization's privacy settings (audited: settings.privacy_changed with the three new values).
func (p *Privacy) Update(ctx context.Context, in PrivacySettings) (PrivacySettings, error) {
	var out PrivacySettings
	err := p.runner.RunTx(ctx, ScopeOrg, privacySpec(ctx, in), func(ctx context.Context, q *pgstore.Queries, _ Recorder) error {
		var err error
		pr, _ := principal.From(ctx)
		out, err = upsertPrivacySettings(ctx, q, pr, in)
		return err
	})
	return out, err
}

// privacySpec is SpecPrivacySettings with the organization as target and the new values as params, so that a
// denied attempt records them too.
func privacySpec(ctx context.Context, in PrivacySettings) ActionSpec {
	spec := SpecPrivacySettings
	if org, err := orgOf(ctx); err == nil {
		spec.Target = &audit.Target{Type: "organization", ID: org.String()}
	}
	spec.Params = map[string]any{
		"retired_inventory_days": in.RetiredInventoryDays, "audit_search_recorded": in.AuditSearchRecorded,
		"inventory_view_recorded": in.InventoryViewRecorded,
	}
	return spec
}

// upsertPrivacySettings validates and stores the settings in an organization transaction (API and declarative apply).
func upsertPrivacySettings(ctx context.Context, q *pgstore.Queries, pr principal.Principal, in PrivacySettings) (PrivacySettings, error) {
	if err := in.Validate(); err != nil {
		return PrivacySettings{}, problem.InvalidRequest.WithDetail(err.Error())
	}
	s, err := q.UpsertPrivacySettings(ctx, pgstore.UpsertPrivacySettingsParams{
		OrganizationID:        pr.OrganizationID,
		RetiredInventoryDays:  int32(in.RetiredInventoryDays), //nolint:gosec // validated 1–365
		AuditSearchRecorded:   in.AuditSearchRecorded,
		InventoryViewRecorded: in.InventoryViewRecorded,
		UpdatedBy:             uuid.NullUUID{UUID: pr.ID, Valid: pr.ID != uuid.Nil},
	})
	if err != nil {
		return PrivacySettings{}, err
	}
	return toPrivacySettings(s), nil
}
