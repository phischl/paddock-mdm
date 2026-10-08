package app

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
	"github.com/phischl/paddock-mdm/server/internal/domain/device"
	"github.com/phischl/paddock-mdm/server/internal/domain/updates"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
)

// Staleness raises and clears the staleness alerts of devices (plan M5b decision 10, worker).
type Staleness struct {
	runner *ActionRunner
	org    *db.OrgPool
	unit   time.Duration
}

// NewStaleness creates the use case; unit is the unit of the thresholds, an hour (a minute in development, gate U4).
func NewStaleness(runner *ActionRunner, org *db.OrgPool, unit time.Duration) *Staleness {
	return &Staleness{runner: runner, org: org, unit: unit}
}

// staleCodes are the audit codes of the transitions to a level.
var staleCodes = map[string]audit.Code{
	updates.StaleWarning: audit.CodeDeviceStaleWarning, updates.StaleCritical: audit.CodeDeviceStaleCritical,
	updates.StaleNone: audit.CodeDeviceStaleCleared,
}

// Evaluate compares the last contact of every active device of the context's organization with its thresholds at
// now and records each transition exactly once: an alert and its audit event, critical also marks the device
// presumed lost, and a contact clears both (device.stale_cleared). Devices that left the active state lose their
// alert without an event; their retirement or quarantine is audited already.
func (s *Staleness) Evaluate(ctx context.Context, now time.Time) error {
	var settings UpdateSettings
	var candidates []pgstore.ListStalenessCandidatesRow
	err := s.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		var err error
		if settings, err = LoadUpdateSettings(ctx, q); err != nil {
			return err
		}
		candidates, err = q.ListStalenessCandidates(ctx)
		return err
	})
	if err != nil {
		return err
	}
	for _, c := range candidates {
		current := ""
		if c.OpenKind != nil {
			current = *c.OpenKind
		}
		if c.State != device.StateActive {
			if err := s.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error { return clearStale(ctx, q, c.ID, now) }); err != nil {
				return err
			}
			continue
		}
		if c.LastContactAt == nil {
			continue
		}
		want := updates.StaleLevel(*c.LastContactAt, now, settings.StalenessWarningH, settings.StalenessCriticalH, s.unit)
		if want == current {
			continue
		}
		if err := s.transition(ctx, c.ID, *c.LastContactAt, current, want, settings, now); err != nil {
			return err
		}
	}
	return nil
}

// transition moves a device from level from to level to, audited once: the claim re-reads the open alert in the
// event's transaction and records nothing when another round got there first.
func (s *Staleness) transition(ctx context.Context, id uuid.UUID, last time.Time, from, to string, settings UpdateSettings, now time.Time) error {
	spec := ActionSpec{
		Code: staleCodes[to], Target: &audit.Target{Type: "device", ID: id.String()},
		Params: map[string]any{"last_contact_at": audit.Timestamp(last).Format(time.RFC3339Nano)},
	}
	switch to {
	case updates.StaleWarning:
		spec.Params["threshold_h"] = settings.StalenessWarningH
	case updates.StaleCritical:
		spec.Params["threshold_h"] = settings.StalenessCriticalH
	default:
		spec.Params["previous"] = from
	}
	_, err := s.runner.RecordOnce(ctx, spec, func(ctx context.Context, q *pgstore.Queries) (bool, error) {
		open, err := q.GetOpenDeviceAlertKind(ctx, id)
		if db.IsNoRows(err) {
			open, err = updates.StaleNone, nil
		}
		if err != nil || open != from {
			return false, err
		}
		if to == updates.StaleNone {
			return true, clearStale(ctx, q, id, now)
		}
		if _, err := q.ClearDeviceAlerts(ctx, pgstore.ClearDeviceAlertsParams{DeviceID: id, Now: now}); err != nil {
			return false, err
		}
		org, err := orgOf(ctx)
		if err != nil {
			return false, err
		}
		n, err := q.RaiseDeviceAlert(ctx, pgstore.RaiseDeviceAlertParams{
			ID: uuid.Must(uuid.NewV7()), OrganizationID: org, DeviceID: id, Kind: to, Now: now,
		})
		if err != nil || n != 1 {
			return false, err
		}
		if to == updates.StaleCritical {
			return true, q.SetPresumedLost(ctx, pgstore.SetPresumedLostParams{DeviceID: id, Now: now})
		}
		return true, q.ClearPresumedLost(ctx, id)
	})
	return err
}

func clearStale(ctx context.Context, q *pgstore.Queries, id uuid.UUID, now time.Time) error {
	if _, err := q.ClearDeviceAlerts(ctx, pgstore.ClearDeviceAlertsParams{DeviceID: id, Now: now}); err != nil {
		return err
	}
	return q.ClearPresumedLost(ctx, id)
}
