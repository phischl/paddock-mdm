package app

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/google/uuid"

	"github.com/paddock-mdm/paddock/server/internal/adapters/postgres/pgstore"
	"github.com/paddock-mdm/paddock/server/internal/domain/organization"
	"github.com/paddock-mdm/paddock/server/internal/domain/privilege"
	"github.com/paddock-mdm/paddock/server/internal/domain/usergroup"
)

// Identity is everything of one organization that effective profiles and login allow lists depend on: users, groups
// and memberships, profiles and assignments, the device groups and login assignments of the active devices. It is
// loaded once per transaction (use cases, compiler).
type Identity struct {
	Org         pgstore.Organization
	Settings    pgstore.OrganizationLoginSetting
	Users       map[uuid.UUID]pgstore.AppUser
	Groups      map[uuid.UUID]pgstore.UserGroup
	Profiles    []privilege.Profile
	Assignments []privilege.Assignment

	userGroups   map[uuid.UUID][]uuid.UUID // user → groups
	groupUsers   map[uuid.UUID][]uuid.UUID // group → users
	deviceGroups map[uuid.UUID][]uuid.UUID // active device → device groups
	logins       map[uuid.UUID][]pgstore.DeviceLoginAssignment
	byUsername   map[string]uuid.UUID
}

// LoadIdentity reads the identity data of the organization of the transaction.
func LoadIdentity(ctx context.Context, q *pgstore.Queries) (*Identity, error) {
	org, err := orgOf(ctx)
	if err != nil {
		return nil, err
	}
	id := &Identity{
		Users: map[uuid.UUID]pgstore.AppUser{}, Groups: map[uuid.UUID]pgstore.UserGroup{},
		userGroups: map[uuid.UUID][]uuid.UUID{}, groupUsers: map[uuid.UUID][]uuid.UUID{},
		deviceGroups: map[uuid.UUID][]uuid.UUID{}, logins: map[uuid.UUID][]pgstore.DeviceLoginAssignment{},
		byUsername: map[string]uuid.UUID{},
	}
	if id.Org, err = q.GetOrganization(ctx, org); err != nil {
		return nil, fmt.Errorf("load organization: %w", err)
	}
	if id.Settings, err = q.GetLoginSettings(ctx); err != nil {
		return nil, fmt.Errorf("load login settings: %w", err)
	}
	users, err := q.ListAllAppUsers(ctx)
	if err != nil {
		return nil, fmt.Errorf("load users: %w", err)
	}
	for _, u := range users {
		id.Users[u.ID] = u
		id.byUsername[u.Username] = u.ID
	}
	groups, err := q.ListAllUserGroups(ctx)
	if err != nil {
		return nil, fmt.Errorf("load user groups: %w", err)
	}
	for _, g := range groups {
		id.Groups[g.ID] = g
	}
	members, err := q.ListAllUserGroupMembers(ctx)
	if err != nil {
		return nil, fmt.Errorf("load group members: %w", err)
	}
	for _, m := range members {
		id.userGroups[m.UserID] = append(id.userGroups[m.UserID], m.GroupID)
		id.groupUsers[m.GroupID] = append(id.groupUsers[m.GroupID], m.UserID)
	}
	if id.Profiles, err = loadProfiles(ctx, q); err != nil {
		return nil, err
	}
	if id.Assignments, err = loadAssignments(ctx, q); err != nil {
		return nil, err
	}
	active, err := q.ListActiveDeviceIDs(ctx)
	if err != nil {
		return nil, fmt.Errorf("load devices: %w", err)
	}
	for _, d := range active {
		id.deviceGroups[d] = []uuid.UUID{}
	}
	dgm, err := q.ListAllDeviceGroupMembers(ctx)
	if err != nil {
		return nil, fmt.Errorf("load device group members: %w", err)
	}
	for _, m := range dgm {
		if _, ok := id.deviceGroups[m.DeviceID]; ok {
			id.deviceGroups[m.DeviceID] = append(id.deviceGroups[m.DeviceID], m.DeviceGroupID)
		}
	}
	las, err := q.ListAllDeviceLoginAssignments(ctx)
	if err != nil {
		return nil, fmt.Errorf("load login assignments: %w", err)
	}
	for _, a := range las {
		id.logins[a.DeviceID] = append(id.logins[a.DeviceID], a)
	}
	return id, nil
}

func loadProfiles(ctx context.Context, q *pgstore.Queries) ([]privilege.Profile, error) {
	rows, err := q.ListAllPermissionProfiles(ctx)
	if err != nil {
		return nil, fmt.Errorf("load permission profiles: %w", err)
	}
	out := make([]privilege.Profile, len(rows))
	for i, p := range rows {
		out[i] = profileOf(p)
	}
	return out, nil
}

func profileOf(p pgstore.PermissionProfile) privilege.Profile {
	return privilege.Profile{
		ID: p.ID, Name: p.Name, Class: privilege.Class(p.Class), Commands: p.Commands, RequirePassword: p.RequirePassword,
		TimestampTimeoutMin: int(p.TimestampTimeoutMin), Lecture: privilege.Lecture(p.Lecture),
	}
}

func loadAssignments(ctx context.Context, q *pgstore.Queries) ([]privilege.Assignment, error) {
	rows, err := q.ListAllProfileAssignments(ctx)
	if err != nil {
		return nil, fmt.Errorf("load profile assignments: %w", err)
	}
	out := make([]privilege.Assignment, len(rows))
	for i, a := range rows {
		out[i] = assignmentOf(a)
	}
	return out, nil
}

func assignmentOf(a pgstore.ProfileAssignment) privilege.Assignment {
	return privilege.Assignment{
		ID: a.ID, ProfileID: a.ProfileID, SubjectType: privilege.SubjectType(a.SubjectType),
		SubjectID: a.SubjectID.UUID, DeviceGroupID: a.DeviceGroupID.UUID,
	}
}

// Effective is the effective profile of a user on a device that is a member of deviceGroups.
func (id *Identity) Effective(user uuid.UUID, deviceGroups []uuid.UUID) privilege.EffectiveProfile {
	return privilege.Effective(privilege.Input{
		UserID: user, UserGroups: id.userGroups[user], DeviceGroups: deviceGroups,
		Assignments: id.Assignments, Profiles: id.Profiles,
	})
}

// DeviceGroups returns the device groups of an active device (nil for other devices).
func (id *Identity) DeviceGroups(device uuid.UUID) []uuid.UUID { return id.deviceGroups[device] }

// HighestClass is the highest reported class of a user over all active devices ("none" without devices), the
// privilege measure of membership changes (plan M3a decision 4).
func (id *Identity) HighestClass(user uuid.UUID) privilege.Class {
	class := privilege.ClassNone
	seen := map[string]bool{}
	for _, groups := range id.deviceGroups {
		k := fmt.Sprint(slices.SortedFunc(slices.Values(groups), compareIDs))
		if seen[k] {
			continue
		}
		seen[k] = true
		class = privilege.MaxReportedClass(class, id.Effective(user, groups).ReportedClass)
	}
	return class
}

// GroupsOf returns the groups of a user.
func (id *Identity) GroupsOf(user uuid.UUID) []uuid.UUID { return id.userGroups[user] }

// UserByName returns the user with the username (case-insensitive).
func (id *Identity) UserByName(username string) (uuid.UUID, bool) {
	u, ok := id.byUsername[strings.ToLower(username)]
	return u, ok
}

// AuthentikGroupName is the Authentik name of a user group: paddock.<slug>.g.<group> or .s.<group>.
func AuthentikGroupName(slug string, g pgstore.UserGroup) string {
	if g.Source == usergroup.SourceSynced {
		return organization.SyncedUserGroup(slug, g.Slug)
	}
	return organization.LocalUserGroup(slug, g.Slug)
}

// LoginAssignment returns the assigned users and groups of a device.
func (id *Identity) LoginAssignment(device uuid.UUID) (users, groups []uuid.UUID) {
	for _, a := range id.logins[device] {
		if a.SubjectType == SubjectUser {
			users = append(users, a.SubjectID)
		} else {
			groups = append(groups, a.SubjectID)
		}
	}
	return users, groups
}

// Login assignment subject types (device_login_assignment.subject_type).
const (
	SubjectUser  = "user"
	SubjectGroup = "group"
)

// AllowList is the login allow list of a device (pam_allow_groups, plan M3a decision 9): empty when logins are
// suspended; the organization's root group when nobody is assigned; otherwise the assigned groups' Authentik names
// plus the per-device group when users are assigned directly. Sorted.
func (id *Identity) AllowList(device uuid.UUID, suspended bool) []string {
	if suspended {
		return []string{}
	}
	users, groups := id.LoginAssignment(device)
	if len(users) == 0 && len(groups) == 0 {
		return []string{organization.RootGroup(id.Org.Slug)}
	}
	var out []string
	for _, g := range groups {
		if group, ok := id.Groups[g]; ok {
			out = append(out, AuthentikGroupName(id.Org.Slug, group))
		}
	}
	if len(users) > 0 {
		out = append(out, organization.DeviceLoginGroup(id.Org.Slug, device))
	}
	slices.Sort(out)
	return out
}

// AllowedUsers are the users that may log in on a device by its login assignment (every user of the organization
// when nobody is assigned), sorted by username.
func (id *Identity) AllowedUsers(device uuid.UUID) []uuid.UUID {
	users, groups := id.LoginAssignment(device)
	set := map[uuid.UUID]bool{}
	if len(users) == 0 && len(groups) == 0 {
		for u := range id.Users {
			set[u] = true
		}
	}
	for _, u := range users {
		set[u] = true
	}
	for _, g := range groups {
		for _, u := range id.groupUsers[g] {
			set[u] = true
		}
	}
	return id.sortedByUsername(set)
}

func (id *Identity) sortedByUsername(set map[uuid.UUID]bool) []uuid.UUID {
	var out []uuid.UUID
	for u := range set {
		if _, ok := id.Users[u]; ok {
			out = append(out, u)
		}
	}
	slices.SortFunc(out, func(a, b uuid.UUID) int { return strings.Compare(id.Users[a].Username, id.Users[b].Username) })
	return out
}

// ActiveDevices returns the active devices.
func (id *Identity) ActiveDevices() []uuid.UUID {
	return slices.SortedFunc(func(yield func(uuid.UUID) bool) {
		for d := range id.deviceGroups {
			if !yield(d) {
				return
			}
		}
	}, compareIDs)
}
