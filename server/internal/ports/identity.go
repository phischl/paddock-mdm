// Package ports declares the interfaces the application needs from external systems.
package ports

import (
	"context"
	"errors"
)

// OrgIdentityRefs are the Authentik primary keys of an organization's groups.
type OrgIdentityRefs struct{ RootGroupPK, AdminsGroupPK, OperatorsGroupPK, AuditorsGroupPK, LockedGroupPK string }

// IdentityProvider manages the identity objects of organizations (Authentik, ADR 0007).
type IdentityProvider interface {
	// EnsureOrganization creates the organization's groups (root, roles, locked) and its device login provider,
	// application, groups claim mapping and access policy if missing, and corrects them if they drifted; idempotent.
	EnsureOrganization(ctx context.Context, slug string) (OrgIdentityRefs, error)
}

// ErrUsernameTaken means the identity provider already has a user with this username (possibly of another
// organization; the caller must not reveal which).
var ErrUsernameTaken = errors.New("ports: username taken")

// IdentityUser is a user as the identity provider knows it.
type IdentityUser struct {
	PK       string
	Username string
	Name     string
	Email    string
	// Managed is true for users Paddock created (attribute paddock_managed); others are synced from upstream.
	Managed bool
}

// NewIdentityUser is a local user to create.
type NewIdentityUser struct{ Username, Name, Email string }

// IdentityGroup is a group of the identity provider.
type IdentityGroup struct{ PK, Name string }

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
}
