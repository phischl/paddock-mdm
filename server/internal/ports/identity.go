// Package ports declares the interfaces the application needs from external systems.
package ports

import (
	"context"
	"errors"
	"time"
)

// OrgIdentityRefs are the Authentik primary keys of an organization's groups.
type OrgIdentityRefs struct{ RootGroupPK, AdminsGroupPK, OperatorsGroupPK, AuditorsGroupPK, LockedGroupPK string }

// IdentityProvider manages the identity objects of organizations (Authentik, ADR 0007).
type IdentityProvider interface {
	// EnsureOrganization creates the organization's groups (root, roles, locked) and its device login provider,
	// application, groups claim mapping and access policy if missing, and corrects them if they drifted; idempotent.
	EnsureOrganization(ctx context.Context, slug string) (OrgIdentityRefs, error)
	// DeleteOrganization deletes what EnsureOrganization and the user directory created for the organization (plan M17
	// decision 10): the device login application, its provider, groups mapping, access policy and binding, every group
	// paddock.<slug> and paddock.<slug>.*, and every user Paddock created there. Users synced from upstream stay.
	// Missing objects count as deleted; idempotent.
	DeleteOrganization(ctx context.Context, slug string) (OrgIdentityDeletion, error)
}

// OrgIdentityDeletion counts the identity provider objects DeleteOrganization deleted; objects that were already gone
// are not counted.
type OrgIdentityDeletion struct{ Groups, Users, Applications, Providers, Policies, Mappings int }

// Total is the number of objects deleted.
func (d OrgIdentityDeletion) Total() int {
	return d.Groups + d.Users + d.Applications + d.Providers + d.Policies + d.Mappings
}

// ErrUsernameTaken means the identity provider already has a user with this username (possibly of another
// organization; the caller must not reveal which).
var ErrUsernameTaken = errors.New("ports: username taken")

// ErrGroupNotFound means the identity provider has no group of that name.
var ErrGroupNotFound = errors.New("ports: group not found")

// IdentityUser is a user as the identity provider knows it.
type IdentityUser struct {
	PK       string
	Username string
	Name     string
	Email    string
	// Managed is true for users Paddock created (attribute paddock_managed); others are synced from upstream.
	Managed bool
	// Active is false for a user deactivated in the identity provider.
	Active bool
	// UID is the user's stable identifier, the subject of the portal's and the step-up's ID tokens (Authentik's uid
	// under the providers' sub_mode hashed_user_id) and so admin_account.authentik_sub.
	UID string
	// MFAEnrolAtLogin is true for a user marked to enrol a second factor at the next portal sign-in (attribute
	// paddock_mfa_enrol_at_login, ADR 0053 decision 4).
	MFAEnrolAtLogin bool
	// Joined is when the identity provider created the user; zero when it did not say.
	Joined time.Time
}

// AttrMFAEnrolAtLogin is the identity provider's user attribute that lets the portal sign-in enrol a second factor once
// (ADR 0053 decision 3); the sign-in denies an administrator without one otherwise.
const AttrMFAEnrolAtLogin = "paddock_mfa_enrol_at_login"

// Authenticators are the kinds of second factor a user has registered in the identity provider.
type Authenticators struct{ WebAuthn, TOTP bool }

// NewIdentityUser is a local user to create.
type NewIdentityUser struct{ Username, Name, Email string }

// IdentityGroup is a group of the identity provider.
type IdentityGroup struct{ PK, Name string }

// IdentityGroupMembers is a group of the identity provider with the pks of its direct members.
type IdentityGroupMembers struct {
	PK      string
	Members []string
}

// UserDirectory manages the users of organizations (plan M3a decisions 2 and 7).
type UserDirectory interface {
	// CreateUser creates a Paddock-managed user without password as member of the organization's root group; it
	// returns ErrUsernameTaken if the username exists.
	CreateUser(ctx context.Context, slug string, u NewIdentityUser) (pk string, err error)
	UpdateUser(ctx context.Context, pk, name, email string) error
	// DeleteUser deletes a user; a missing user is not an error.
	DeleteUser(ctx context.Context, pk string) error
	// RecoveryLink creates a one-time link (valid 24 h) with which the user sets a password.
	RecoveryLink(ctx context.Context, pk string) (string, error)
	// UserActive reports whether the user is active (not deactivated) in the identity provider.
	UserActive(ctx context.Context, pk string) (bool, error)
	// LockUser adds the user to the organization's locked group and deletes the user's refresh tokens, access tokens
	// and authenticated sessions; both are required (PoC M1 C2). The revocation deactivates the user; reactivate
	// activates it again afterwards, so a user that was inactive before the lock stays inactive (plan M4b.1).
	LockUser(ctx context.Context, slug, pk string, reactivate bool) error
	// UnlockUser removes the membership; activate also activates the user (completing an interrupted lock).
	UnlockUser(ctx context.Context, slug, pk string, activate bool) error
	// OrganizationUsers lists the direct members of the organization's root group.
	OrganizationUsers(ctx context.Context, slug string) ([]IdentityUser, error)
	// RoleGroupsMembers lists the direct members of the role groups groupNames (organization.RoleGroup) together in one
	// settled paged listing, keyed by group (plan M8s decision 22, PDK-570); a group that does not exist has no key, a
	// group without members an empty one.
	RoleGroupsMembers(ctx context.Context, groupNames []string) (map[string][]IdentityUser, error)
	// UserMembership reads one user directly: the user named username whose UID is uid, with the names of its direct
	// groups; found is false when no such user exists (removed, or renamed meanwhile). The worker confirms with it
	// what a listing suggests before it changes an account (plan M8s decision 22).
	UserMembership(ctx context.Context, username, uid string) (u IdentityUser, groups []string, found bool, err error)
	// Superusers lists the users with the identity provider's superuser rights in one paged listing; the worker records
	// who gains or loses them (plan M8b decision 33).
	Superusers(ctx context.Context) ([]IdentityUser, error)
	// GroupReadable reports whether the group groupName itself can be read: it exists and its object is visible to the
	// service token. With UsersVisible it proves that empty role group listings are real, not a blind token (PDK-424).
	GroupReadable(ctx context.Context, groupName string) (bool, error)
	// UsersVisible reports whether a listing of users returns at least one user who is not a service account; the
	// service token's own user does not count, since a token may see itself without seeing anyone else (PDK-424).
	UsersVisible(ctx context.Context) (bool, error)
}

// GroupDirectory manages Paddock's user groups (plan M3a decisions 3 and 9).
type GroupDirectory interface {
	// EnsureGroup creates the group name as child of the organization's root group if missing and returns its pk.
	EnsureGroup(ctx context.Context, slug, name string) (string, error)
	// DeleteGroup deletes a group; a missing group is not an error.
	DeleteGroup(ctx context.Context, pk string) error
	AddMember(ctx context.Context, groupPK, userPK string) error
	RemoveMember(ctx context.Context, groupPK, userPK string) error
	// GroupMembers returns the pks of the direct members of a group.
	GroupMembers(ctx context.Context, groupPK string) ([]string, error)
	// UpstreamGroups lists the groups outside Paddock's namespace that have at least one direct member of the
	// organization's root group (candidates for an import of that organization).
	UpstreamGroups(ctx context.Context, slug string) ([]IdentityGroup, error)
	// FindGroup returns the pk of the group name, or "" if there is none.
	FindGroup(ctx context.Context, name string) (string, error)
	// DeviceLoginGroups lists the organization's per-device login groups (organization.DeviceLoginGroup) with their
	// direct members, keyed by name, in one settled paged listing (PDK-570); a group it does not list does not exist.
	DeviceLoginGroups(ctx context.Context, slug string) (map[string]IdentityGroupMembers, error)
}
