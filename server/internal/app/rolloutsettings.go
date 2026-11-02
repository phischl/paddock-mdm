package app

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
	"github.com/phischl/paddock-mdm/server/internal/domain/configrollout"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/problem"
)

// SpecRolloutSettings is the action of changing the rollout settings (plan M11 decision 24).
var SpecRolloutSettings = ActionSpec{Code: audit.CodeSettingsRolloutChanged, AllowedRoles: RolesAdmin}

// RolloutSettings are the use cases of the organization's configuration rollout settings.
type RolloutSettings struct {
	runner *ActionRunner
	org    *db.OrgPool
	// development lowers the minimum wave duration (PADDOCK_ENV=development).
	development bool
}

// NewRolloutSettings creates the use cases.
func NewRolloutSettings(runner *ActionRunner, org *db.OrgPool, development bool) *RolloutSettings {
	return &RolloutSettings{runner: runner, org: org, development: development}
}

// RolloutConfig are the rollout settings of an organization; UpdatedAt is nil until they were changed.
type RolloutConfig struct {
	configrollout.Settings
	CanaryDeviceGroupID *uuid.UUID
	UpdatedAt           *time.Time
}

// LoadRolloutSettings returns the organization's rollout settings, the defaults without a row (compiler, worker).
func LoadRolloutSettings(ctx context.Context, q *pgstore.Queries) (RolloutConfig, error) {
	r, err := q.GetRolloutSettings(ctx)
	if db.IsNoRows(err) {
		return RolloutConfig{Settings: configrollout.Defaults()}, nil
	}
	if err != nil {
		return RolloutConfig{}, err
	}
	waves := make([]int, len(r.Waves))
	for i, w := range r.Waves {
		waves[i] = int(w)
	}
	out := RolloutConfig{
		Settings: configrollout.Settings{
			Enabled: r.Enabled, Waves: waves, MinWaveMinutes: int(r.MinWaveMinutes),
			FailureThresholdPercent: int(r.FailureThresholdPercent), FailureThresholdMin: int(r.FailureThresholdMin),
		},
		UpdatedAt: &r.UpdatedAt,
	}
	if r.CanaryDeviceGroupID.Valid {
		id := r.CanaryDeviceGroupID.UUID
		out.CanaryDeviceGroupID = &id
	}
	return out, nil
}

// Get returns the organization's rollout settings.
func (r *RolloutSettings) Get(ctx context.Context) (RolloutConfig, error) {
	if _, err := RequireOrg(ctx, RolesRead); err != nil {
		return RolloutConfig{}, err
	}
	var out RolloutConfig
	err := r.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		var err error
		out, err = LoadRolloutSettings(ctx, q)
		return err
	})
	return out, err
}

// Update replaces the organization's rollout settings (audited: settings.rollout_changed). A rollout that is
// already running keeps the parameters it started with.
func (r *RolloutSettings) Update(ctx context.Context, in RolloutConfig) (RolloutConfig, error) {
	spec := SpecRolloutSettings
	if org, err := orgOf(ctx); err == nil {
		spec.Target = &audit.Target{Type: "organization", ID: org.String()}
	}
	var canary any
	if in.CanaryDeviceGroupID != nil {
		canary = in.CanaryDeviceGroupID.String()
	}
	spec.Params = map[string]any{
		"enabled": in.Enabled, "waves": in.Waves, "min_wave_minutes": in.MinWaveMinutes,
		"failure_threshold_percent": in.FailureThresholdPercent, "failure_threshold_min": in.FailureThresholdMin,
		"canary_device_group_id": canary,
	}
	var out RolloutConfig
	err := r.runner.RunTx(ctx, ScopeOrg, spec, func(ctx context.Context, q *pgstore.Queries, rec Recorder) error {
		if err := in.Validate(r.development); err != nil {
			return problem.InvalidRequest.WithDetail(err.Error())
		}
		if in.CanaryDeviceGroupID != nil {
			if _, err := q.GetDeviceGroup(ctx, *in.CanaryDeviceGroupID); err != nil {
				return notFound(err)
			}
		}
		p, _ := principal.From(ctx)
		waves := make([]int32, len(in.Waves))
		for i, w := range in.Waves {
			waves[i] = int32(w) //nolint:gosec // validated 1..100
		}
		_, err := q.UpsertRolloutSettings(ctx, pgstore.UpsertRolloutSettingsParams{
			OrganizationID: p.OrganizationID, Enabled: in.Enabled, Waves: waves,
			MinWaveMinutes:          int32(in.MinWaveMinutes),          //nolint:gosec // validated
			FailureThresholdPercent: int32(in.FailureThresholdPercent), //nolint:gosec // validated
			FailureThresholdMin:     int32(in.FailureThresholdMin),     //nolint:gosec // validated
			CanaryDeviceGroupID:     nullID(in.CanaryDeviceGroupID),
			UpdatedBy:               uuid.NullUUID{UUID: p.ID, Valid: p.ID != uuid.Nil},
		})
		if err != nil {
			return err
		}
		out, err = LoadRolloutSettings(ctx, q)
		return err
	})
	return out, err
}
