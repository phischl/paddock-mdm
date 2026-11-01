package compiler

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/domain/configrollout"
	"github.com/phischl/paddock-mdm/server/internal/domain/declarative"
	"github.com/phischl/paddock-mdm/server/internal/domain/managedconfig"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
)

// rolloutOverlay is the organization's open configuration rollout as the compiler applies it (plan M11 decision 30,
// ADR 0033): a device outside the current wave renders the before-state of every staged key, a device inside renders
// the live tables and its bundle names the rollout. Keys the rollout does not stage render live for every device.
type rolloutOverlay struct {
	id      uuid.UUID
	percent int
	canary  map[uuid.UUID]bool
	// files, units and holds are the before items of the staged keys an update or deletion replaced; a staged
	// creation has none, so outside the wave the item is absent.
	files    []managedconfig.File
	units    []managedconfig.Unit
	holds    []pgstore.PackageHold
	settings *app.UpdateSettings
	// stagedFiles, stagedUnits and stagedHolds are the staged keys (declarative.Key.String) by section.
	stagedFiles, stagedUnits, stagedHolds map[string]bool
	stagedSettings                        bool
	// groupNames maps the organization's device group IDs to their names, which the keys use.
	groupNames map[uuid.UUID]string
}

// loadOverlay returns the open rollout of the context's organization; nil without one. Completed and reverted rollouts
// are not open, so they apply no overlay.
func loadOverlay(ctx context.Context, q *pgstore.Queries) (*rolloutOverlay, error) {
	r, err := q.GetOpenConfigRolloutOverlay(ctx)
	if db.IsNoRows(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("open configuration rollout: %w", err)
	}
	var plan declarative.Plan
	if err := json.Unmarshal(r.Plan, &plan); err != nil {
		return nil, fmt.Errorf("decode the plan of rollout %s: %w", r.ID, err)
	}
	var before map[string]map[string]json.RawMessage
	if len(r.Before) > 0 {
		if err := json.Unmarshal(r.Before, &before); err != nil {
			return nil, fmt.Errorf("decode the before-states of rollout %s: %w", r.ID, err)
		}
	}
	waves := make([]int, len(r.Waves))
	for i, w := range r.Waves {
		waves[i] = int(w)
	}
	o := &rolloutOverlay{id: r.ID, percent: configrollout.Percent(r.Status, waves, int(r.CurrentWaveIndex)),
		canary: map[uuid.UUID]bool{}, groupNames: map[uuid.UUID]string{}}
	if r.CanaryDeviceGroupID.Valid {
		members, err := q.ListActiveGroupMemberIDs(ctx, r.CanaryDeviceGroupID.UUID)
		if err != nil {
			return nil, fmt.Errorf("canary group of rollout %s: %w", r.ID, err)
		}
		for _, m := range members {
			o.canary[m] = true
		}
	}
	groups, err := q.ListAllDeviceGroups(ctx)
	if err != nil {
		return nil, err
	}
	groupIDs := make(map[string]uuid.UUID, len(groups))
	for _, g := range groups {
		o.groupNames[g.ID] = g.Name
		groupIDs[g.Name] = g.ID
	}
	staged := configrollout.StagedKeys(plan)
	o.stagedFiles, o.stagedUnits, o.stagedHolds = staged[declarative.SectionManagedFiles], staged[declarative.SectionManagedUnits],
		staged[declarative.SectionPackageHolds]
	o.stagedSettings = staged[declarative.SectionSettingsUpdates][""]
	if err := o.loadBefore(before, groupIDs); err != nil {
		return nil, fmt.Errorf("before-states of rollout %s: %w", r.ID, err)
	}
	return o, nil
}

// loadBefore turns the stored before items of the staged keys into the compiler's definitions. An item whose device
// group no longer exists is left out: it can reach no device, and scoping it to every device would widen it.
func (o *rolloutOverlay) loadBefore(before map[string]map[string]json.RawMessage, groupIDs map[string]uuid.UUID) error {
	group := func(name *string) (*uuid.UUID, bool) {
		if name == nil {
			return nil, true
		}
		id, ok := groupIDs[*name]
		return &id, ok
	}
	for key, raw := range before[declarative.SectionManagedFiles] {
		var f struct {
			declarative.ManagedFile
			ID uuid.UUID `json:"id"`
		}
		if err := json.Unmarshal(raw, &f); err != nil {
			return fmt.Errorf("managed file %s: %w", key, err)
		}
		if g, ok := group(f.DeviceGroup); ok && o.stagedFiles[key] {
			o.files = append(o.files, managedconfig.File{ID: f.ID, GroupID: g, Path: f.Path, Mode: f.Mode, Owner: f.Owner,
				Group: f.Group, Content: f.Content})
		}
	}
	for key, raw := range before[declarative.SectionManagedUnits] {
		var u struct {
			declarative.ManagedUnit
			ID uuid.UUID `json:"id"`
		}
		if err := json.Unmarshal(raw, &u); err != nil {
			return fmt.Errorf("managed unit %s: %w", key, err)
		}
		if g, ok := group(u.DeviceGroup); ok && o.stagedUnits[key] {
			o.units = append(o.units, managedconfig.Unit{ID: u.ID, GroupID: g, Unit: u.Unit, Enabled: u.Enabled, Active: u.Active})
		}
	}
	for key, raw := range before[declarative.SectionPackageHolds] {
		var h struct {
			declarative.PackageHold
			ID uuid.UUID `json:"id"`
		}
		if err := json.Unmarshal(raw, &h); err != nil {
			return fmt.Errorf("package hold %s: %w", key, err)
		}
		if g, ok := group(h.DeviceGroup); ok && o.stagedHolds[key] {
			hold := pgstore.PackageHold{ID: h.ID, Package: h.Package, Version: h.Version, Reason: h.Reason}
			if g != nil {
				hold.DeviceGroupID = uuid.NullUUID{UUID: *g, Valid: true}
			}
			o.holds = append(o.holds, hold)
		}
	}
	if raw, ok := before[declarative.SectionSettingsUpdates][""]; ok && o.stagedSettings {
		var s declarative.UpdateSettings
		if err := json.Unmarshal(raw, &s); err != nil {
			return fmt.Errorf("update settings: %w", err)
		}
		o.settings = &app.UpdateSettings{}
		o.settings.SecurityDailyAt, o.settings.RegularSchedule = s.SecurityDailyAt, s.RegularSchedule
		o.settings.RegularUpdatesEnabled, o.settings.MaxRandomDelayMin = s.RegularUpdatesEnabled, s.MaxRandomDelayMin
		o.settings.StalenessWarningH, o.settings.StalenessCriticalH = s.StalenessWarningH, s.StalenessCriticalH
		o.settings.AgentUpdatePolicy = s.AgentUpdatePolicy
	}
	return nil
}

// eligible reports whether device is inside the current wave (by bucket or as a canary member). Report-only devices
// (PDK-160) are not distinguished yet: every device is eligible by bucket or canary.
func (o *rolloutOverlay) eligible(device uuid.UUID) bool {
	return configrollout.Eligible(configrollout.Bucket(device, o.id), o.percent, o.canary[device])
}

// apply returns copies of defs and u in which every staged key carries its before-state: a staged creation is removed,
// a staged update or deletion is replaced by (or restored as) its before item, staged update settings are replaced by
// the before settings. defs and u are not changed; they serve the other devices of the round.
func (o *rolloutOverlay) apply(defs app.ManagedDefinitions, u *orgUpdates) (app.ManagedDefinitions, *orgUpdates) {
	out := defs
	out.Files = make([]managedconfig.File, 0, len(defs.Files)+len(o.files))
	for _, f := range defs.Files {
		if !o.stagedFiles[declarative.ManagedFile{Path: f.Path, DeviceGroup: o.groupName(f.GroupID)}.Key().String()] {
			out.Files = append(out.Files, f)
		}
	}
	out.Files = append(out.Files, o.files...)
	out.Units = make([]managedconfig.Unit, 0, len(defs.Units)+len(o.units))
	for _, un := range defs.Units {
		if !o.stagedUnits[declarative.ManagedUnit{Unit: un.Unit, DeviceGroup: o.groupName(un.GroupID)}.Key().String()] {
			out.Units = append(out.Units, un)
		}
	}
	out.Units = append(out.Units, o.units...)
	if u == nil {
		return out, nil
	}
	next := *u
	next.holds = make([]pgstore.PackageHold, 0, len(u.holds)+len(o.holds))
	for _, h := range u.holds {
		var g *uuid.UUID
		if h.DeviceGroupID.Valid {
			g = &h.DeviceGroupID.UUID
		}
		if !o.stagedHolds[declarative.PackageHold{Package: h.Package, DeviceGroup: o.groupName(g)}.Key().String()] {
			next.holds = append(next.holds, h)
		}
	}
	next.holds = append(next.holds, o.holds...)
	if o.settings != nil {
		next.settings = *o.settings
	}
	return out, &next
}

// groupName is the name of device group id as keys use it; nil for every device.
func (o *rolloutOverlay) groupName(id *uuid.UUID) *string {
	if id == nil {
		return nil
	}
	name := o.groupNames[*id]
	return &name
}
