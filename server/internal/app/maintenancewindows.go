package app

import (
	"context"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
	"github.com/phischl/paddock-mdm/server/internal/domain/devicegroup"
	"github.com/phischl/paddock-mdm/server/internal/domain/statechange"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/problem"
)

// Specs of the maintenance window actions (plan M13c decision 4).
var (
	SpecMaintenanceWindowSet    = ActionSpec{Code: audit.CodeDeviceGroupMaintenanceWindowChanged, AllowedRoles: RolesWrite}
	SpecMaintenanceWindowDelete = ActionSpec{Code: audit.CodeDeviceGroupMaintenanceWindowRemoved, AllowedRoles: RolesWrite}
)

// MaintenanceWindow is the stored maintenance window of a device group.
type MaintenanceWindow = pgstore.DeviceGroupMaintenanceWindow

// WindowOf returns the window of a stored row.
func WindowOf(row MaintenanceWindow) devicegroup.Window {
	days := make([]int, len(row.Days))
	for i, d := range row.Days {
		days[i] = int(d)
	}
	return devicegroup.Window{Days: days, StartMinute: int(row.StartMinute), DurationMinutes: int(row.DurationMinutes),
		Timezone: row.Timezone}
}

// recordWindow sets the params of a window, with prefix "" or "old_"; a nil window sets them null.
func recordWindow(rec Recorder, prefix string, w *devicegroup.Window) {
	var days, start, duration, zone any
	if w != nil {
		days, start, duration, zone = w.Days, w.StartMinute, w.DurationMinutes, w.Timezone
	}
	rec.SetParam(prefix+"days", days)
	rec.SetParam(prefix+"start_minute", start)
	rec.SetParam(prefix+"duration_minutes", duration)
	rec.SetParam(prefix+"timezone", zone)
}

// storeWindow writes a validated window of a device group.
func storeWindow(ctx context.Context, q *pgstore.Queries, org, group uuid.UUID, w devicegroup.Window, by uuid.NullUUID) (MaintenanceWindow, error) {
	days := make([]int32, len(w.Days))
	for i, d := range w.Days {
		days[i] = int32(d) //nolint:gosec // validated: 1 to 7
	}
	return q.UpsertMaintenanceWindow(ctx, pgstore.UpsertMaintenanceWindowParams{
		OrganizationID: org, DeviceGroupID: group, Days: days,
		StartMinute: int32(w.StartMinute), DurationMinutes: int32(w.DurationMinutes), //nolint:gosec // validated: at most 1440
		Timezone: w.Timezone, UpdatedBy: by,
	})
}

// MaintenanceWindow returns the maintenance window of a device group; a group without one, a missing group and
// another organization's are all not_found.
func (d *DeviceGroups) MaintenanceWindow(ctx context.Context, group uuid.UUID) (MaintenanceWindow, error) {
	var out MaintenanceWindow
	if _, err := RequireOrg(ctx, RolesRead); err != nil {
		return out, err
	}
	err := d.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		var err error
		out, err = q.GetMaintenanceWindow(ctx, group)
		return notFound(err)
	})
	return out, err
}

// SetMaintenanceWindow sets or replaces the maintenance window of a device group (audited:
// device_group.maintenance_window_changed with the new and the old window) and recompiles the group's members.
func (d *DeviceGroups) SetMaintenanceWindow(ctx context.Context, group uuid.UUID, w devicegroup.Window) (MaintenanceWindow, error) {
	var out MaintenanceWindow
	w = devicegroup.NormalizeWindow(w)
	spec := SpecMaintenanceWindowSet
	spec.Target = &audit.Target{Type: "device_group", ID: group.String()}
	err := d.runner.RunTx(ctx, ScopeOrg, spec, withChangeSet(func(ctx context.Context, q *pgstore.Queries, rec Recorder) error {
		g, err := q.GetDeviceGroup(ctx, group)
		if err != nil {
			return notFound(err)
		}
		rec.SetTarget(audit.Target{Type: "device_group", ID: group.String(), Display: g.Name})
		rec.SetParam("name", g.Name)
		recordWindow(rec, "", &w)
		var old *devicegroup.Window
		switch row, err := q.GetMaintenanceWindow(ctx, group); {
		case err == nil:
			ow := WindowOf(row)
			old = &ow
		case !db.IsNoRows(err):
			return err
		}
		recordWindow(rec, "old_", old)
		if err := devicegroup.ValidateWindow(w); err != nil {
			return problem.InvalidRequest.WithDetail(err.Error())
		}
		p, _ := principal.From(ctx)
		if out, err = storeWindow(ctx, q, g.OrganizationID, group, w, uuid.NullUUID{UUID: p.ID, Valid: p.ID != uuid.Nil}); err != nil {
			return err
		}
		rec.StateChanged(statechange.ScopeDeviceGroup, group)
		return nil
	}))
	return out, err
}

// DeleteMaintenanceWindow removes the maintenance window of a device group (audited:
// device_group.maintenance_window_removed with the removed window); a group without one is not_found.
func (d *DeviceGroups) DeleteMaintenanceWindow(ctx context.Context, group uuid.UUID) error {
	spec := SpecMaintenanceWindowDelete
	spec.Target = &audit.Target{Type: "device_group", ID: group.String()}
	return d.runner.RunTx(ctx, ScopeOrg, spec, withChangeSet(func(ctx context.Context, q *pgstore.Queries, rec Recorder) error {
		g, err := q.GetDeviceGroup(ctx, group)
		if err != nil {
			return notFound(err)
		}
		rec.SetTarget(audit.Target{Type: "device_group", ID: group.String(), Display: g.Name})
		rec.SetParam("name", g.Name)
		row, err := q.GetMaintenanceWindow(ctx, group)
		if err != nil {
			return notFound(err)
		}
		w := WindowOf(row)
		recordWindow(rec, "", &w)
		if _, err := q.DeleteMaintenanceWindow(ctx, group); err != nil {
			return err
		}
		rec.StateChanged(statechange.ScopeDeviceGroup, group)
		return nil
	}))
}
