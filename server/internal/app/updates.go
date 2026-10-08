package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/pkg/bundle"
	"github.com/phischl/paddock-mdm/pkg/command"
	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
	"github.com/phischl/paddock-mdm/server/internal/domain/device"
	"github.com/phischl/paddock-mdm/server/internal/domain/statechange"
	"github.com/phischl/paddock-mdm/server/internal/domain/updates"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/problem"
)

// Specs of the update management actions (plan M5b decisions 1–3).
var (
	SpecUpdateSettings    = ActionSpec{Code: audit.CodeSettingsUpdatesChanged, AllowedRoles: RolesAdmin}
	SpecPackageHoldCreate = ActionSpec{Code: audit.CodePackageHoldCreated, AllowedRoles: RolesWrite}
	SpecPackageHoldUpdate = ActionSpec{Code: audit.CodePackageHoldUpdated, AllowedRoles: RolesWrite}
	SpecPackageHoldDelete = ActionSpec{Code: audit.CodePackageHoldDeleted, AllowedRoles: RolesWrite}
	SpecInstallNow        = ActionSpec{Code: audit.CodeDeviceInstallNowRequested, AllowedRoles: RolesWrite}
)

// Updates are the use cases of update management: the organization's update settings, package holds, immediate
// installs and the update state of a device (plan M5b decisions 1–4 and 12).
type Updates struct {
	runner *ActionRunner
	org    *db.OrgPool
	now    func() time.Time
}

// NewUpdates creates the use cases.
func NewUpdates(runner *ActionRunner, org *db.OrgPool) *Updates {
	return &Updates{runner: runner, org: org, now: time.Now}
}

// UpdateSettings are the update settings of an organization; UpdatedAt is nil until they were changed.
type UpdateSettings struct {
	updates.Settings
	UpdatedAt *time.Time
}

// LoadUpdateSettings returns the organization's update settings, the defaults without a row (compiler, worker).
func LoadUpdateSettings(ctx context.Context, q *pgstore.Queries) (UpdateSettings, error) {
	s, err := q.GetUpdateSettings(ctx)
	if db.IsNoRows(err) {
		return UpdateSettings{Settings: updates.Defaults()}, nil
	}
	if err != nil {
		return UpdateSettings{}, err
	}
	return UpdateSettings{
		Settings: updates.Settings{
			SecurityDailyAt: s.SecurityDailyAt, RegularSchedule: s.RegularSchedule, RegularUpdatesEnabled: s.RegularUpdatesEnabled,
			MaxRandomDelayMin: int(s.MaxRandomDelayMin), StalenessWarningH: int(s.StalenessWarningH),
			StalenessCriticalH: int(s.StalenessCriticalH),
		},
		UpdatedAt: &s.UpdatedAt,
	}, nil
}

// GetSettings returns the organization's update settings.
func (u *Updates) GetSettings(ctx context.Context) (UpdateSettings, error) {
	if _, err := RequireOrg(ctx, RolesRead); err != nil {
		return UpdateSettings{}, err
	}
	var out UpdateSettings
	err := u.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		var err error
		out, err = LoadUpdateSettings(ctx, q)
		return err
	})
	return out, err
}

// UpdateSettings replaces the organization's update settings (audited: settings.updates_changed); every device is
// recompiled.
func (u *Updates) UpdateSettings(ctx context.Context, in updates.Settings) (UpdateSettings, error) {
	spec := SpecUpdateSettings
	spec.Params = map[string]any{
		"security_daily_at": in.SecurityDailyAt, "regular_schedule": in.RegularSchedule,
		"regular_updates_enabled": in.RegularUpdatesEnabled, "max_random_delay_min": in.MaxRandomDelayMin,
		"staleness_warning_h": in.StalenessWarningH, "staleness_critical_h": in.StalenessCriticalH,
	}
	var out UpdateSettings
	err := u.runner.RunTx(ctx, ScopeOrg, spec, func(ctx context.Context, q *pgstore.Queries, rec Recorder) error {
		if err := in.Validate(); errors.Is(err, updates.ErrSchedule) {
			return problem.InvalidSchedule.WithDetail(err.Error())
		} else if err != nil {
			return problem.InvalidRequest.WithDetail(err.Error())
		}
		p, _ := principal.From(ctx)
		rec.SetTarget(audit.Target{Type: "organization", ID: p.OrganizationID.String()})
		_, err := q.UpsertUpdateSettings(ctx, pgstore.UpsertUpdateSettingsParams{
			OrganizationID: p.OrganizationID, SecurityDailyAt: in.SecurityDailyAt, RegularSchedule: in.RegularSchedule,
			RegularUpdatesEnabled: in.RegularUpdatesEnabled,
			MaxRandomDelayMin:     int32(in.MaxRandomDelayMin),  //nolint:gosec // validated
			StalenessWarningH:     int32(in.StalenessWarningH),  //nolint:gosec // validated
			StalenessCriticalH:    int32(in.StalenessCriticalH), //nolint:gosec // validated
			UpdatedBy:             uuid.NullUUID{UUID: p.ID, Valid: p.ID != uuid.Nil},
		})
		if err != nil {
			return err
		}
		if out, err = LoadUpdateSettings(ctx, q); err != nil {
			return err
		}
		rec.StateChanged(statechange.ScopeOrg, p.OrganizationID)
		return nil
	})
	return out, err
}

// HoldQuery selects a page of package holds.
type HoldQuery struct {
	Page    ListPage
	GroupID *uuid.UUID
}

// ListHolds returns one page of package holds.
func (u *Updates) ListHolds(ctx context.Context, query HoldQuery) (Listed[pgstore.PackageHold], error) {
	var out Listed[pgstore.PackageHold]
	if _, err := RequireOrg(ctx, RolesRead); err != nil {
		return out, err
	}
	err := u.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		group := nullID(query.GroupID)
		n, err := q.CountPackageHolds(ctx, pgstore.CountPackageHoldsParams{QPattern: query.Page.QPattern, DeviceGroupID: group, CountLimit: countLimit})
		if err != nil {
			return fmt.Errorf("count package holds: %w", err)
		}
		out.Count = int(n)
		out.Items, err = q.ListPackageHolds(ctx, pgstore.ListPackageHoldsParams{
			QPattern: query.Page.QPattern, DeviceGroupID: group, Sort: query.Page.Sort, SkipRows: query.Page.Offset, MaxRows: query.Page.Limit,
		})
		return err
	})
	return out, err
}

// GetHold returns one package hold.
func (u *Updates) GetHold(ctx context.Context, id uuid.UUID) (pgstore.PackageHold, error) {
	if _, err := RequireOrg(ctx, RolesRead); err != nil {
		return pgstore.PackageHold{}, err
	}
	var h pgstore.PackageHold
	err := u.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		var err error
		h, err = q.GetPackageHold(ctx, id)
		return notFound(err)
	})
	return h, err
}

// HoldInput are the fields of a package hold. On update, the scope and the package are fixed; Version and Reason
// replace the current values.
type HoldInput struct {
	DeviceGroupID *uuid.UUID
	Package       string
	Version       *string
	Reason        string
}

// CreateHold holds a package for the organization or a device group (audited: package_hold.created); the affected
// devices are recompiled.
func (u *Updates) CreateHold(ctx context.Context, in HoldInput) (pgstore.PackageHold, error) {
	var h pgstore.PackageHold
	spec := SpecPackageHoldCreate
	spec.Params = holdParams(in.Package, in.Version, in.DeviceGroupID, in.Reason)
	err := u.runner.RunTx(ctx, ScopeOrg, spec, func(ctx context.Context, q *pgstore.Queries, rec Recorder) error {
		if err := updates.ValidateHold(in.Package, in.Version, in.Reason); err != nil {
			return problem.InvalidRequest.WithDetail(err.Error())
		}
		if err := requireGroups(ctx, q, optionalID(in.DeviceGroupID)); err != nil {
			return err
		}
		org, err := orgOf(ctx)
		if err != nil {
			return err
		}
		p, _ := principal.From(ctx)
		h, err = q.InsertPackageHold(ctx, pgstore.InsertPackageHoldParams{
			ID: uuid.Must(uuid.NewV7()), OrganizationID: org, DeviceGroupID: nullID(in.DeviceGroupID), Package: in.Package,
			Version: in.Version, Reason: in.Reason, CreatedBy: uuid.NullUUID{UUID: p.ID, Valid: p.ID != uuid.Nil},
		})
		if db.IsUniqueViolation(err, "") {
			return problem.AlreadyExists.WithDetail("this package is already held in this scope")
		}
		if err != nil {
			return err
		}
		rec.SetTarget(audit.Target{Type: "package_hold", ID: h.ID.String(), Display: h.Package})
		stateChangedFor(rec, h.OrganizationID, h.DeviceGroupID)
		return nil
	})
	return h, err
}

// UpdateHold changes the version and the reason of a package hold (audited: package_hold.updated).
func (u *Updates) UpdateHold(ctx context.Context, id uuid.UUID, version *string, reason string) (pgstore.PackageHold, error) {
	var h pgstore.PackageHold
	spec := SpecPackageHoldUpdate
	spec.Target = &audit.Target{Type: "package_hold", ID: id.String()}
	err := u.runner.RunTx(ctx, ScopeOrg, spec, func(ctx context.Context, q *pgstore.Queries, rec Recorder) error {
		old, err := q.GetPackageHold(ctx, id)
		if err != nil {
			return notFound(err)
		}
		rec.SetTarget(audit.Target{Type: "package_hold", ID: id.String(), Display: old.Package})
		for k, v := range holdParams(old.Package, version, groupPtr(old.DeviceGroupID), reason) {
			rec.SetParam(k, v)
		}
		rec.SetParam("old_version", versionParam(old.Version))
		if err := updates.ValidateHold(old.Package, version, reason); err != nil {
			return problem.InvalidRequest.WithDetail(err.Error())
		}
		if h, err = q.UpdatePackageHold(ctx, pgstore.UpdatePackageHoldParams{ID: id, Version: version, Reason: reason}); err != nil {
			return notFound(err)
		}
		stateChangedFor(rec, h.OrganizationID, h.DeviceGroupID)
		return nil
	})
	return h, err
}

// DeleteHold removes a package hold (audited: package_hold.deleted); the affected devices are recompiled and release
// the hold.
func (u *Updates) DeleteHold(ctx context.Context, id uuid.UUID) error {
	spec := SpecPackageHoldDelete
	spec.Target = &audit.Target{Type: "package_hold", ID: id.String()}
	return u.runner.RunTx(ctx, ScopeOrg, spec, func(ctx context.Context, q *pgstore.Queries, rec Recorder) error {
		old, err := q.GetPackageHold(ctx, id)
		if err != nil {
			return notFound(err)
		}
		rec.SetTarget(audit.Target{Type: "package_hold", ID: id.String(), Display: old.Package})
		rec.SetParam("package", old.Package)
		rec.SetParam("version", versionParam(old.Version))
		rec.SetParam("device_group_id", idParam(groupPtr(old.DeviceGroupID)))
		if _, err := q.DeletePackageHold(ctx, id); err != nil {
			return err
		}
		stateChangedFor(rec, old.OrganizationID, old.DeviceGroupID)
		return nil
	})
}

func holdParams(pkg string, version *string, group *uuid.UUID, reason string) map[string]any {
	return map[string]any{"package": pkg, "version": versionParam(version), "device_group_id": idParam(group), "reason": reason}
}

func versionParam(v *string) any {
	if v == nil {
		return nil
	}
	return *v
}

func toHolds(rows []pgstore.PackageHold) []updates.Hold {
	out := make([]updates.Hold, len(rows))
	for i, r := range rows {
		out[i] = updates.Hold{GroupID: groupPtr(r.DeviceGroupID), Package: r.Package, Version: r.Version}
	}
	return out
}

// InstallNow issues install_now for packages to an active device (audited: device.install_now_requested). A package
// held for the device is refused with package_on_hold and no command is issued (holds win, plan M5b decision 3).
func (u *Updates) InstallNow(ctx context.Context, deviceID uuid.UUID, packages []string) (pgstore.DeviceCommand, error) {
	spec := SpecInstallNow
	spec.Target = &audit.Target{Type: "device", ID: deviceID.String()}
	spec.Params = map[string]any{"packages": packages[:min(len(packages), command.MaxInstallPackages+1)]}
	var out pgstore.DeviceCommand
	err := u.runner.RunTx(ctx, ScopeOrg, spec, func(ctx context.Context, q *pgstore.Queries, rec Recorder) error {
		dev, err := q.GetDevice(ctx, deviceID)
		if err != nil {
			return notFound(err)
		}
		rec.SetTarget(audit.Target{Type: "device", ID: deviceID.String(), Display: dev.Hostname})
		rec.SetParam("hostname", dev.Hostname)
		pkgs, err := updates.NormalizeInstall(packages, command.MaxInstallPackages)
		if err != nil {
			return problem.InvalidRequest.WithDetail(err.Error())
		}
		rec.SetParam("packages", pkgs)
		if dev.State != device.StateActive {
			return problem.InvalidState.WithDetail("commands are delivered to active devices only")
		}
		holds, err := q.ListDeviceHolds(ctx, deviceID)
		if err != nil {
			return err
		}
		if held := updates.Held(toHolds(holds), pkgs); len(held) > 0 {
			return problem.PackageOnHold.WithDetail("held on this device: " + held[0])
		}
		out, err = issueCommand(ctx, q, rec, deviceID, command.TypeInstallNow, map[string]any{"packages": pkgs}, u.now(), nil)
		return err
	})
	return out, err
}

// InstallNowGroup issues install_now for packages to every active device of a device group, one command per device
// (audited once: device.install_now_requested with device_count). More than updates.MaxInstallDevices devices are
// refused with too_many_devices, a package held for any of them with package_on_hold; then no command is issued.
func (u *Updates) InstallNowGroup(ctx context.Context, groupID uuid.UUID, packages []string) (int, error) {
	spec := SpecInstallNow
	spec.Target = &audit.Target{Type: "device_group", ID: groupID.String()}
	spec.Params = map[string]any{"packages": packages[:min(len(packages), command.MaxInstallPackages+1)]}
	count := 0
	err := u.runner.RunTx(ctx, ScopeOrg, spec, func(ctx context.Context, q *pgstore.Queries, rec Recorder) error {
		g, err := q.GetDeviceGroup(ctx, groupID)
		if err != nil {
			return notFound(err)
		}
		rec.SetTarget(audit.Target{Type: "device_group", ID: groupID.String(), Display: g.Name})
		pkgs, err := updates.NormalizeInstall(packages, command.MaxInstallPackages)
		if err != nil {
			return problem.InvalidRequest.WithDetail(err.Error())
		}
		rec.SetParam("packages", pkgs)
		devices, err := q.ListActiveGroupMemberIDs(ctx, groupID)
		if err != nil {
			return err
		}
		rec.SetParam("device_count", len(devices))
		if len(devices) > updates.MaxInstallDevices {
			return problem.TooManyDevices.WithDetail(fmt.Sprintf("at most %d active devices per request", updates.MaxInstallDevices))
		}
		holds, err := q.ListGroupMembersHolds(ctx, groupID)
		if err != nil {
			return err
		}
		if held := updates.Held(toHolds(holds), pkgs); len(held) > 0 {
			return problem.PackageOnHold.WithDetail("held on a device of this group: " + held[0])
		}
		now := u.now()
		for _, id := range devices {
			if _, err := queueCommand(ctx, q, rec, id, command.TypeInstallNow, map[string]any{"packages": pkgs}, now, nil); err != nil {
				return err
			}
		}
		count = len(devices)
		return nil
	})
	return count, err
}

// DeviceHold is a hold that applies to a device, with its scope.
type DeviceHold struct {
	Package       string
	Version       *string
	DeviceGroupID *uuid.UUID
}

// DeviceUpdateState is the update state of a device (plan M5b decision 12): the last run of each kind (the latest
// updates.run event, {type, occurred_at, params}), whether its last check-in reported a pending reboot, the holds
// that apply to it and the packages held with different versions.
type DeviceUpdateState struct {
	LastSecurityRun json.RawMessage
	LastRegularRun  json.RawMessage
	RebootRequired  bool
	Holds           []DeviceHold
	Effective       []bundle.Hold
	Conflicts       []updates.Conflict
}

// DeviceUpdates returns the update state of a device; an unknown or foreign device is not_found.
func (u *Updates) DeviceUpdates(ctx context.Context, deviceID uuid.UUID) (DeviceUpdateState, error) {
	var out DeviceUpdateState
	if _, err := RequireOrg(ctx, RolesRead); err != nil {
		return out, err
	}
	err := u.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		if _, err := q.GetDevice(ctx, deviceID); err != nil {
			return notFound(err)
		}
		rows, err := q.ListDeviceHolds(ctx, deviceID)
		if err != nil {
			return err
		}
		for _, r := range rows {
			out.Holds = append(out.Holds, DeviceHold{Package: r.Package, Version: r.Version, DeviceGroupID: groupPtr(r.DeviceGroupID)})
		}
		out.Effective, out.Conflicts = updates.Merge(toHolds(rows))
		status, err := q.GetDeviceStatus(ctx, deviceID)
		if db.IsNoRows(err) {
			return nil
		}
		if err != nil {
			return err
		}
		var state map[string]json.RawMessage
		if json.Unmarshal(status.LoginState, &state) == nil {
			out.LastSecurityRun, out.LastRegularRun = state["updates_security"], state["updates_regular"]
		}
		out.RebootRequired = RebootRequired(status.Health)
		return nil
	})
	return out, err
}

// RebootRequired reads reboot_required from the health report of a check-in (plan M5b decision 8).
func RebootRequired(health json.RawMessage) bool {
	var h struct {
		RebootRequired bool `json:"reboot_required"`
	}
	return json.Unmarshal(health, &h) == nil && h.RebootRequired
}

// UpdatesSection returns the updates section of a device in groups (compiler): the organization's schedule and the
// merged holds of the organization and the device's groups.
func UpdatesSection(s UpdateSettings, holds []pgstore.PackageHold, groups []uuid.UUID) *bundle.UpdatesSpec {
	var applicable []updates.Hold
	for _, h := range toHolds(holds) {
		if h.GroupID == nil || slices.Contains(groups, *h.GroupID) {
			applicable = append(applicable, h)
		}
	}
	merged, _ := updates.Merge(applicable)
	return &bundle.UpdatesSpec{
		SecurityDailyAt: s.SecurityDailyAt, RegularSchedule: s.RegularSchedule, RegularUpdatesEnabled: s.RegularUpdatesEnabled,
		MaxRandomDelayMin: s.MaxRandomDelayMin, Holds: merged,
	}
}
