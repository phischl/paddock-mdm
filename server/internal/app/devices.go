package app

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/google/uuid"

	"github.com/paddock-mdm/paddock/pkg/bundle"
	"github.com/paddock-mdm/paddock/server/internal/adapters/postgres/pgstore"
	"github.com/paddock-mdm/paddock/server/internal/domain/audit"
	"github.com/paddock-mdm/paddock/server/internal/domain/device"
	"github.com/paddock-mdm/paddock/server/internal/domain/managedconfig"
	"github.com/paddock-mdm/paddock/server/internal/domain/statechange"
	"github.com/paddock-mdm/paddock/server/internal/platform/db"
	"github.com/paddock-mdm/paddock/server/internal/problem"
)

// Devices are the device administration use cases (plan M2a §6.4).
type Devices struct {
	runner *ActionRunner
	org    *db.OrgPool
}

// NewDevices creates the use cases.
func NewDevices(runner *ActionRunner, org *db.OrgPool) *Devices {
	return &Devices{runner: runner, org: org}
}

// Specs of the privileged device actions.
var (
	SpecDeviceApprove           = ActionSpec{Code: audit.CodeDeviceApproved, AllowedRoles: RolesWrite}
	SpecDeviceReject            = ActionSpec{Code: audit.CodeDeviceRejected, AllowedRoles: RolesAdmin}
	SpecDeviceReleaseQuarantine = ActionSpec{Code: audit.CodeDeviceQuarantineReleased, AllowedRoles: RolesWrite}
	SpecDeviceRetire            = ActionSpec{Code: audit.CodeDeviceRetired, AllowedRoles: RolesAdmin}
	SpecDeviceSetGroups         = ActionSpec{Code: audit.CodeDeviceGroupsChanged, AllowedRoles: RolesWrite}
)

// DeviceQuery selects a page of devices.
type DeviceQuery struct {
	Page    ListPage
	States  []string
	GroupID *uuid.UUID
}

// List returns one page of devices with their status.
func (d *Devices) List(ctx context.Context, query DeviceQuery) (Listed[pgstore.ListDevicesRow], error) {
	var out Listed[pgstore.ListDevicesRow]
	if _, err := RequireOrg(ctx, RolesRead); err != nil {
		return out, err
	}
	err := d.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		return listDevices(ctx, q, query, &out)
	})
	return out, err
}

// ListGroupMembers returns one page of the members of a device group; a missing or foreign group is not_found.
func (d *Devices) ListGroupMembers(ctx context.Context, groupID uuid.UUID, query DeviceQuery) (Listed[pgstore.ListDevicesRow], error) {
	var out Listed[pgstore.ListDevicesRow]
	if _, err := RequireOrg(ctx, RolesRead); err != nil {
		return out, err
	}
	query.GroupID = &groupID
	err := d.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		if _, err := q.GetDeviceGroup(ctx, groupID); err != nil {
			return notFound(err)
		}
		return listDevices(ctx, q, query, &out)
	})
	return out, err
}

func listDevices(ctx context.Context, q *pgstore.Queries, query DeviceQuery, out *Listed[pgstore.ListDevicesRow]) error {
	group := nullID(query.GroupID)
	n, err := q.CountDevices(ctx, pgstore.CountDevicesParams{
		QPattern: query.Page.QPattern, States: query.States, DeviceGroupID: group, CountLimit: countLimit,
	})
	if err != nil {
		return fmt.Errorf("count devices: %w", err)
	}
	out.Count = int(n)
	out.Items, err = q.ListDevices(ctx, pgstore.ListDevicesParams{
		QPattern: query.Page.QPattern, States: query.States, DeviceGroupID: group, Sort: query.Page.Sort,
		SkipRows: query.Page.Offset, MaxRows: query.Page.Limit,
	})
	if err != nil {
		return fmt.Errorf("list devices: %w", err)
	}
	return nil
}

// DeviceDetail is a device with status, latest bundle, group memberships and identity keys.
type DeviceDetail struct {
	Device       pgstore.Device
	Status       *pgstore.DeviceStatus
	LatestBundle *pgstore.Bundle
	Groups       []pgstore.ListDeviceGroupsOfDeviceRow
	IdentityKeys []pgstore.DeviceIdentityKey
}

// Get returns one device; missing and foreign devices are both not_found.
func (d *Devices) Get(ctx context.Context, id uuid.UUID) (DeviceDetail, error) {
	if _, err := RequireOrg(ctx, RolesRead); err != nil {
		return DeviceDetail{}, err
	}
	var out DeviceDetail
	err := d.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		var err error
		out, err = loadDeviceDetail(ctx, q, id)
		return err
	})
	return out, err
}

func loadDeviceDetail(ctx context.Context, q *pgstore.Queries, id uuid.UUID) (DeviceDetail, error) {
	var out DeviceDetail
	var err error
	if out.Device, err = q.GetDevice(ctx, id); err != nil {
		return out, notFound(err)
	}
	status, err := q.GetDeviceStatus(ctx, id)
	switch {
	case err == nil:
		out.Status = &status
	case !db.IsNoRows(err):
		return out, err
	}
	latest, err := q.GetLatestBundle(ctx, id)
	switch {
	case err == nil:
		out.LatestBundle = &latest
	case !db.IsNoRows(err):
		return out, err
	}
	if out.Groups, err = q.ListDeviceGroupsOfDevice(ctx, id); err != nil {
		return out, err
	}
	out.IdentityKeys, err = q.ListDeviceIdentityKeys(ctx, id)
	return out, err
}

// Approve activates a pending device (audited: device.approved).
func (d *Devices) Approve(ctx context.Context, id uuid.UUID) (pgstore.Device, error) {
	return d.transition(ctx, SpecDeviceApprove, device.ActionApprove, id)
}

// Reject rejects a pending device (audited: device.rejected).
func (d *Devices) Reject(ctx context.Context, id uuid.UUID) (pgstore.Device, error) {
	return d.transition(ctx, SpecDeviceReject, device.ActionReject, id)
}

// ReleaseQuarantine returns a quarantined device to active (audited: device.quarantine_released).
func (d *Devices) ReleaseQuarantine(ctx context.Context, id uuid.UUID) (pgstore.Device, error) {
	return d.transition(ctx, SpecDeviceReleaseQuarantine, device.ActionReleaseQuarantine, id)
}

// Retire retires a device and revokes its identity keys (audited: device.retired).
func (d *Devices) Retire(ctx context.Context, id uuid.UUID) (pgstore.Device, error) {
	return d.transition(ctx, SpecDeviceRetire, device.ActionRetire, id)
}

func (d *Devices) transition(ctx context.Context, spec ActionSpec, action device.Action, id uuid.UUID) (pgstore.Device, error) {
	var out pgstore.Device
	spec.Target = &audit.Target{Type: "device", ID: id.String()}
	err := d.runner.RunTx(ctx, ScopeOrg, spec, func(ctx context.Context, q *pgstore.Queries, rec Recorder) error {
		var err error
		out, err = TransitionDevice(ctx, q, rec, action, id)
		return err
	})
	return out, err
}

// TransitionDevice applies a lifecycle action inside an action transaction: it locks the device, checks the
// transition, records hostname and previous state, revokes the keys of retired and rejected devices and queues a
// recompile. Shared by the administrator actions and the worker's quarantine.
func TransitionDevice(ctx context.Context, q *pgstore.Queries, rec Recorder, action device.Action, id uuid.UUID) (pgstore.Device, error) {
	cur, err := q.LockDevice(ctx, id)
	if err != nil {
		return pgstore.Device{}, notFound(err)
	}
	rec.SetTarget(audit.Target{Type: "device", ID: id.String(), Display: cur.Hostname})
	rec.SetParam("hostname", cur.Hostname)
	rec.SetParam("from_state", cur.State)
	to, err := device.Transition(action, cur.State)
	if errors.Is(err, device.ErrInvalidTransition) {
		return pgstore.Device{}, problem.InvalidState.WithDetail(fmt.Sprintf("%s is not possible for a %s device", action, cur.State))
	}
	out, err := q.SetDeviceState(ctx, pgstore.SetDeviceStateParams{ID: id, State: to, FromState: cur.State})
	if err != nil {
		return pgstore.Device{}, err
	}
	if to == device.StateRetired || to == device.StateRejected {
		if err := q.RevokeDeviceIdentityKeys(ctx, id); err != nil {
			return pgstore.Device{}, err
		}
	}
	rec.StateChanged(statechange.ScopeDevice, id)
	return out, nil
}

// SetGroups replaces the device group memberships of a device (audited: device.groups_changed).
func (d *Devices) SetGroups(ctx context.Context, id uuid.UUID, groupIDs []uuid.UUID) (DeviceDetail, error) {
	var out DeviceDetail
	spec := SpecDeviceSetGroups
	spec.Target = &audit.Target{Type: "device", ID: id.String()}
	err := d.runner.RunTx(ctx, ScopeOrg, spec, func(ctx context.Context, q *pgstore.Queries, rec Recorder) error {
		dev, err := q.LockDevice(ctx, id)
		if err != nil {
			return notFound(err)
		}
		rec.SetTarget(audit.Target{Type: "device", ID: id.String(), Display: dev.Hostname})
		rec.SetParam("hostname", dev.Hostname)
		want := slices.Compact(slices.SortedFunc(slices.Values(groupIDs), compareIDs))
		if err := requireGroups(ctx, q, want); err != nil {
			return err
		}
		added, removed, err := replaceMemberships(ctx, q, dev, want)
		if err != nil {
			return err
		}
		rec.SetParam("added", added)
		rec.SetParam("removed", removed)
		rec.StateChanged(statechange.ScopeDevice, id)
		out, err = loadDeviceDetail(ctx, q, id)
		return err
	})
	return out, err
}

// replaceMemberships makes want the device's groups and returns the added and removed group IDs.
func replaceMemberships(ctx context.Context, q *pgstore.Queries, dev pgstore.Device, want []uuid.UUID) (added, removed []string, err error) {
	have, err := q.ListDeviceGroupIDsOfDevice(ctx, dev.ID)
	if err != nil {
		return nil, nil, err
	}
	added, removed = []string{}, []string{}
	for _, g := range want {
		if slices.Contains(have, g) {
			continue
		}
		added = append(added, g.String())
		if err := q.InsertDeviceGroupMember(ctx, pgstore.InsertDeviceGroupMemberParams{
			OrganizationID: dev.OrganizationID, DeviceGroupID: g, DeviceID: dev.ID,
		}); err != nil {
			return nil, nil, err
		}
	}
	for _, g := range have {
		if slices.Contains(want, g) {
			continue
		}
		removed = append(removed, g.String())
		if err := q.DeleteDeviceGroupMember(ctx, pgstore.DeleteDeviceGroupMemberParams{DeviceGroupID: g, DeviceID: dev.ID}); err != nil {
			return nil, nil, err
		}
	}
	return added, removed, nil
}

func compareIDs(a, b uuid.UUID) int { return bytes.Compare(a[:], b[:]) }

// EffectiveConfig is the managed configuration that applies to a device: the winning definitions, the conflicts
// between device groups and the bundle resources they render to.
type EffectiveConfig struct {
	Files     []pgstore.ManagedFile
	Units     []pgstore.ManagedUnit
	Conflicts []managedconfig.Conflict
	Resources []bundle.Resource
}

// EffectiveConfig resolves the managed files and units of a device (plan M2a decision 7).
func (d *Devices) EffectiveConfig(ctx context.Context, id uuid.UUID) (EffectiveConfig, error) {
	if _, err := RequireOrg(ctx, RolesRead); err != nil {
		return EffectiveConfig{}, err
	}
	var out EffectiveConfig
	err := d.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		if _, err := q.GetDevice(ctx, id); err != nil {
			return notFound(err)
		}
		defs, err := LoadManagedDefinitions(ctx, q)
		if err != nil {
			return err
		}
		groups, err := q.ListDeviceGroupIDsOfDevice(ctx, id)
		if err != nil {
			return err
		}
		eff := defs.Resolve(groups)
		for _, f := range eff.Files {
			out.Files = append(out.Files, defs.fileRows[f.ID])
		}
		for _, u := range eff.Units {
			out.Units = append(out.Units, defs.unitRows[u.ID])
		}
		out.Conflicts = eff.Conflicts
		out.Resources, err = managedconfig.Resources(eff)
		return err
	})
	return out, err
}

// ManagedDefinitions are all managed files and units of an organization.
type ManagedDefinitions struct {
	Files []managedconfig.File
	Units []managedconfig.Unit

	fileRows map[uuid.UUID]pgstore.ManagedFile
	unitRows map[uuid.UUID]pgstore.ManagedUnit
}

// Resolve returns the effective configuration of a member of groups.
func (m ManagedDefinitions) Resolve(groups []uuid.UUID) managedconfig.Effective {
	return managedconfig.Resolve(m.Files, m.Units, groups)
}

// LoadManagedDefinitions reads every managed file and unit of the organization of the transaction.
func LoadManagedDefinitions(ctx context.Context, q *pgstore.Queries) (ManagedDefinitions, error) {
	out := ManagedDefinitions{fileRows: map[uuid.UUID]pgstore.ManagedFile{}, unitRows: map[uuid.UUID]pgstore.ManagedUnit{}}
	files, err := q.ListAllManagedFiles(ctx)
	if err != nil {
		return out, fmt.Errorf("load managed files: %w", err)
	}
	for _, f := range files {
		out.fileRows[f.ID] = f
		out.Files = append(out.Files, managedconfig.File{
			ID: f.ID, GroupID: groupPtr(f.DeviceGroupID), Path: f.Path, Mode: f.Mode, Owner: f.Owner, Group: f.Grp, Content: f.Content,
		})
	}
	units, err := q.ListAllManagedUnits(ctx)
	if err != nil {
		return out, fmt.Errorf("load managed units: %w", err)
	}
	for _, u := range units {
		out.unitRows[u.ID] = u
		out.Units = append(out.Units, managedconfig.Unit{
			ID: u.ID, GroupID: groupPtr(u.DeviceGroupID), Unit: u.Unit, Enabled: u.Enabled, Active: u.Active,
		})
	}
	return out, nil
}

func groupPtr(id uuid.NullUUID) *uuid.UUID {
	if !id.Valid {
		return nil
	}
	return &id.UUID
}
