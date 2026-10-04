package app

import (
	"context"
	"slices"

	"github.com/google/uuid"

	"github.com/paddock-mdm/paddock/server/internal/adapters/postgres/pgstore"
	"github.com/paddock-mdm/paddock/server/internal/domain/audit"
	"github.com/paddock-mdm/paddock/server/internal/domain/organization"
	"github.com/paddock-mdm/paddock/server/internal/domain/statechange"
	"github.com/paddock-mdm/paddock/server/internal/platform/db"
	"github.com/paddock-mdm/paddock/server/internal/ports"
	"github.com/paddock-mdm/paddock/server/internal/problem"
)

// Logins are the device login use cases: login assignment and suspension (plan M3a decisions 9 and 11).
type Logins struct {
	runner *ActionRunner
	org    *db.OrgPool
	dir    ports.GroupDirectory
}

// NewLogins creates the use cases.
func NewLogins(runner *ActionRunner, org *db.OrgPool, dir ports.GroupDirectory) *Logins {
	return &Logins{runner: runner, org: org, dir: dir}
}

// Specs of the privileged login actions.
var (
	SpecDeviceSetLoginAssignment = ActionSpec{Code: audit.CodeDeviceLoginAssignmentChange, AllowedRoles: RolesWrite}
	SpecDeviceSuspendLogins      = ActionSpec{Code: audit.CodeDeviceLoginsSuspended, AllowedRoles: RolesWrite}
	SpecDeviceResumeLogins       = ActionSpec{Code: audit.CodeDeviceLoginsResumed, AllowedRoles: RolesWrite}
)

// SetAssignment replaces the users and groups that may log in on a device (audited: device.login_assignment_changed).
// Directly assigned users are kept as members of the per-device group paddock.<slug>.d.<device_id>, which exists
// only while users are assigned directly.
func (l *Logins) SetAssignment(ctx context.Context, deviceID uuid.UUID, users, groups []uuid.UUID) error {
	spec := SpecDeviceSetLoginAssignment
	spec.Target = &audit.Target{Type: "device", ID: deviceID.String()}
	users = slices.Compact(slices.SortedFunc(slices.Values(users), compareIDs))
	groups = slices.Compact(slices.SortedFunc(slices.Values(groups), compareIDs))
	var slug string
	var direct []string // Authentik pks of the directly assigned users
	return l.runner.RunExternal(ctx, ScopeOrg, spec,
		func(ctx context.Context, q *pgstore.Queries, rec Recorder) error {
			dev, err := q.LockDevice(ctx, deviceID)
			if err != nil {
				return notFound(err)
			}
			rec.SetTarget(audit.Target{Type: "device", ID: deviceID.String(), Display: dev.Hostname})
			rec.SetParam("hostname", dev.Hostname)
			names := []string{}
			for _, u := range users {
				usr, err := q.GetAppUser(ctx, u)
				if err != nil {
					return problem.InvalidRequest.WithDetail("unknown user " + u.String())
				}
				names = append(names, usr.Username)
				direct = append(direct, usr.AuthentikPk)
			}
			groupSlugs := []string{}
			for _, g := range groups {
				grp, err := q.GetUserGroup(ctx, g)
				if err != nil {
					return problem.InvalidRequest.WithDetail("unknown user group " + g.String())
				}
				groupSlugs = append(groupSlugs, grp.Slug)
			}
			rec.SetParam("users", names)
			rec.SetParam("groups", groupSlugs)
			o, err := q.GetOrganization(ctx, dev.OrganizationID)
			if err != nil {
				return err
			}
			slug = o.Slug
			if err := q.DeleteDeviceLoginAssignments(ctx, deviceID); err != nil {
				return err
			}
			for _, s := range []struct {
				typ string
				ids []uuid.UUID
			}{{SubjectUser, users}, {SubjectGroup, groups}} {
				for _, id := range s.ids {
					if err := q.InsertDeviceLoginAssignment(ctx, pgstore.InsertDeviceLoginAssignmentParams{
						OrganizationID: dev.OrganizationID, DeviceID: deviceID, SubjectType: s.typ, SubjectID: id,
					}); err != nil {
						return err
					}
				}
			}
			// The bundle names the per-device group at once; its membership follows in the external step and is
			// repaired by the worker's reconcile if that step fails.
			rec.StateChanged(statechange.ScopeDevice, deviceID)
			return nil
		},
		func(ctx context.Context) error { return SyncDeviceLoginGroup(ctx, l.dir, slug, deviceID, direct) },
		func(context.Context, *pgstore.Queries, Recorder, error) error { return nil })
}

// SyncDeviceLoginGroup makes the per-device group of a device have exactly the given members (Authentik pks), and
// deletes it when there are none.
func SyncDeviceLoginGroup(ctx context.Context, dir ports.GroupDirectory, slug string, deviceID uuid.UUID, members []string) error {
	name := organization.DeviceLoginGroup(slug, deviceID)
	if len(members) == 0 {
		pk, err := dir.FindGroup(ctx, name)
		if err != nil || pk == "" {
			return err
		}
		return dir.DeleteGroup(ctx, pk)
	}
	pk, err := dir.EnsureGroup(ctx, slug, name)
	if err != nil {
		return err
	}
	return SyncMembers(ctx, dir, pk, members)
}

// SyncMembers adds and removes members of an Authentik group until it has exactly want (Authentik pks).
func SyncMembers(ctx context.Context, dir ports.GroupDirectory, groupPK string, want []string) error {
	have, err := dir.GroupMembers(ctx, groupPK)
	if err != nil {
		return err
	}
	for _, pk := range want {
		if pk != "" && !slices.Contains(have, pk) {
			if err := dir.AddMember(ctx, groupPK, pk); err != nil {
				return err
			}
		}
	}
	for _, pk := range have {
		if !slices.Contains(want, pk) {
			if err := dir.RemoveMember(ctx, groupPK, pk); err != nil {
				return err
			}
		}
	}
	return nil
}

// Suspend suspends directory logins on a device (audited: device.logins_suspended); the device is recompiled on
// the priority lane.
func (l *Logins) Suspend(ctx context.Context, deviceID uuid.UUID) (pgstore.Device, error) {
	return l.setSuspended(ctx, SpecDeviceSuspendLogins, deviceID, true)
}

// Resume resumes directory logins on a device (audited: device.logins_resumed).
func (l *Logins) Resume(ctx context.Context, deviceID uuid.UUID) (pgstore.Device, error) {
	return l.setSuspended(ctx, SpecDeviceResumeLogins, deviceID, false)
}

func (l *Logins) setSuspended(ctx context.Context, spec ActionSpec, deviceID uuid.UUID, suspended bool) (pgstore.Device, error) {
	spec.Target = &audit.Target{Type: "device", ID: deviceID.String()}
	var out pgstore.Device
	err := l.runner.RunTx(ctx, ScopeOrg, spec, func(ctx context.Context, q *pgstore.Queries, rec Recorder) error {
		dev, err := q.LockDevice(ctx, deviceID)
		if err != nil {
			return notFound(err)
		}
		rec.SetTarget(audit.Target{Type: "device", ID: deviceID.String(), Display: dev.Hostname})
		rec.SetParam("hostname", dev.Hostname)
		if out, err = q.SetDeviceLoginsSuspended(ctx, pgstore.SetDeviceLoginsSuspendedParams{ID: deviceID, LoginsSuspended: suspended}); err != nil {
			return err
		}
		rec.PriorityStateChanged(statechange.ScopeDevice, deviceID)
		return nil
	})
	return out, err
}

// LoginAssignment is the login assignment of a device with the names of its subjects.
type LoginAssignment struct {
	Users  []pgstore.AppUser
	Groups []pgstore.UserGroup
}

// loadLoginAssignment reads the login assignment of a device.
func loadLoginAssignment(ctx context.Context, q *pgstore.Queries, deviceID uuid.UUID) (LoginAssignment, error) {
	out := LoginAssignment{Users: []pgstore.AppUser{}, Groups: []pgstore.UserGroup{}}
	rows, err := q.ListDeviceLoginAssignments(ctx, deviceID)
	if err != nil {
		return out, err
	}
	for _, a := range rows {
		if a.SubjectType == SubjectUser {
			u, err := q.GetAppUser(ctx, a.SubjectID)
			if err != nil {
				return out, err
			}
			out.Users = append(out.Users, u)
			continue
		}
		g, err := q.GetUserGroup(ctx, a.SubjectID)
		if err != nil {
			return out, err
		}
		out.Groups = append(out.Groups, g)
	}
	return out, nil
}
