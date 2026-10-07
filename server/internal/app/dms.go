package app

import (
	"context"
	"log/slog"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/pkg/command"
	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
	"github.com/phischl/paddock-mdm/server/internal/domain/revocation"
	"github.com/phischl/paddock-mdm/server/internal/domain/statechange"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/problem"
)

// SpecDMSUpdate is the privileged action settings.dms_changed.
var SpecDMSUpdate = ActionSpec{Code: audit.CodeSettingsDMSChanged, AllowedRoles: RolesAdmin}

// CommandCache removes a token from cmd:<device_id> (devicecache.Cache).
type CommandCache interface {
	DeleteCommand(ctx context.Context, device, id uuid.UUID) error
}

// DMS are the use cases of the organization's dead man's switch (plan M4c decision 15).
type DMS struct {
	runner    *ActionRunner
	org       *db.OrgPool
	cache     CommandCache
	enabled   bool
	minPeriod int
	now       func() time.Time
}

// NewDMS creates the use cases; enabled is PADDOCK_REVOCATION_ENABLED, development (PADDOCK_ENV=development) allows
// periods from revocation.DevMinPeriodDays.
func NewDMS(runner *ActionRunner, org *db.OrgPool, cache CommandCache, enabled, development bool) *DMS {
	minPeriod := revocation.MinPeriodDays
	if development {
		minPeriod = revocation.DevMinPeriodDays
	}
	return &DMS{runner: runner, org: org, cache: cache, enabled: enabled, minPeriod: minPeriod, now: time.Now}
}

// DMSSettings are the dead man's switch settings of an organization.
type DMSSettings struct {
	Enabled    bool
	PeriodDays int
	WarnDays   []int
	UpdatedAt  *time.Time
}

func toDMSSettings(s pgstore.OrganizationDmsSetting) DMSSettings {
	out := DMSSettings{Enabled: s.Enabled, PeriodDays: int(s.PeriodDays), WarnDays: make([]int, len(s.WarnDays)), UpdatedAt: &s.UpdatedAt}
	for i, d := range s.WarnDays {
		out.WarnDays[i] = int(d)
	}
	return out
}

// Get returns the settings; an organization that never changed them has the switch off with the defaults.
func (d *DMS) Get(ctx context.Context) (DMSSettings, error) {
	if _, err := RequireOrg(ctx, RolesRead); err != nil {
		return DMSSettings{}, err
	}
	var out DMSSettings
	err := d.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		var err error
		out, err = currentDMS(ctx, q)
		return err
	})
	return out, err
}

func currentDMS(ctx context.Context, q *pgstore.Queries) (DMSSettings, error) {
	s, err := q.GetDMSSettings(ctx)
	if db.IsNoRows(err) {
		return DMSSettings{PeriodDays: revocation.DefaultPeriodDays, WarnDays: revocation.DefaultWarnDays}, nil
	}
	if err != nil {
		return DMSSettings{}, err
	}
	return toDMSSettings(s), nil
}

// Update replaces the settings (audited: settings.dms_changed): turning the switch on, or changing it while on, needs
// a step-up. Every device is recompiled; the revocation-issuer then issues or replaces the self-lock tokens. Turning
// it off cancels every self-lock token and tells every active device to delete its copy.
func (d *DMS) Update(ctx context.Context, in DMSSettings) (DMSSettings, error) {
	spec := SpecDMSUpdate
	spec.Params = map[string]any{"enabled": in.Enabled, "period_days": in.PeriodDays, "warn_days": in.WarnDays}
	if !d.enabled {
		return DMSSettings{}, d.runner.RecordRejected(ctx, ScopeOrg, spec, disabled())
	}
	var out DMSSettings
	var cancelled []pgstore.CancelSelfLocksRow
	err := d.runner.RunTx(ctx, ScopeOrg, spec, func(ctx context.Context, q *pgstore.Queries, rec Recorder) error {
		if err := revocation.ValidateDMS(d.minPeriod, in.PeriodDays, in.WarnDays); err != nil {
			return problem.InvalidRequest.WithDetail(err.Error())
		}
		if in.Enabled {
			if err := rec.RequireStepUp(); err != nil {
				return err
			}
		}
		cur, err := currentDMS(ctx, q)
		if err != nil {
			return err
		}
		p, _ := principal.From(ctx)
		rec.SetTarget(audit.Target{Type: "organization", ID: p.OrganizationID.String()})
		warn := make([]int32, len(in.WarnDays))
		for i, w := range in.WarnDays {
			warn[i] = int32(w) //nolint:gosec // validated below MaxPeriodDays
		}
		s, err := q.UpsertDMSSettings(ctx, pgstore.UpsertDMSSettingsParams{
			OrganizationID: p.OrganizationID, Enabled: in.Enabled, PeriodDays: int32(in.PeriodDays), //nolint:gosec // validated
			WarnDays: warn, UpdatedBy: uuid.NullUUID{UUID: p.ID, Valid: p.ID != uuid.Nil},
		})
		if err != nil {
			return err
		}
		out = toDMSSettings(s)
		rec.StateChanged(statechange.ScopeOrg, p.OrganizationID)
		if !cur.Enabled || in.Enabled {
			return nil
		}
		now := d.now()
		if cancelled, err = q.CancelSelfLocks(ctx, pgstore.CancelSelfLocksParams{Now: now, Enabled: false, RenewBefore: now}); err != nil {
			return err
		}
		devices, err := q.ListActiveDeviceIDs(ctx)
		if err != nil {
			return err
		}
		for _, id := range devices {
			if _, err := queueCommand(ctx, q, rec, id, command.TypeDeleteSelfLock, nil, now, nil); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return out, err
	}
	for _, c := range cancelled {
		if err := d.cache.DeleteCommand(ctx, c.DeviceID, c.ID); err != nil {
			slog.WarnContext(ctx, "removing a cancelled self-lock token failed; the device keeps it until it expires",
				"device_id", c.DeviceID, "request_id", c.ID, "error", err)
		}
	}
	return out, nil
}

// MarkSilent marks the devices of the context's organization that have been silent for longer than the period while
// the switch is on as presumed self-locked, audited once per silence (device.presumed_self_locked), and clears the
// mark of devices that are back or of a switch that is off (worker, plan M4c decision 17).
func (d *DMS) MarkSilent(ctx context.Context, now time.Time) error {
	var marked []uuid.UUID
	var period int
	err := d.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		s, err := currentDMS(ctx, q)
		if err != nil {
			return err
		}
		period = s.PeriodDays
		since := now.Add(-time.Duration(period) * 24 * time.Hour)
		if _, err := q.ClearPresumedSelfLocked(ctx, pgstore.ClearPresumedSelfLockedParams{SilentSince: since, Enabled: s.Enabled}); err != nil {
			return err
		}
		if !s.Enabled {
			return nil
		}
		marked, err = q.MarkPresumedSelfLocked(ctx, pgstore.MarkPresumedSelfLockedParams{Now: now, SilentSince: since})
		return err
	})
	if err != nil {
		return err
	}
	for _, id := range marked {
		spec := ActionSpec{
			Code: audit.CodeDevicePresumedSelfLocked, Target: &audit.Target{Type: "device", ID: id.String()},
			Params: map[string]any{"period_days": period},
		}
		if err := d.runner.RunTx(ctx, ScopeOrg, spec, func(context.Context, *pgstore.Queries, Recorder) error { return nil }); err != nil {
			return err
		}
	}
	return nil
}
