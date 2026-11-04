package app

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
	"github.com/phischl/paddock-mdm/server/internal/domain/statechange"
	"github.com/phischl/paddock-mdm/server/internal/domain/user"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/ports"
	"github.com/phischl/paddock-mdm/server/internal/problem"
)

// Users are the user use cases (plan M3a decisions 2 and 7).
type Users struct {
	runner *ActionRunner
	org    *db.OrgPool
	dir    ports.UserDirectory
}

// NewUsers creates the use cases.
func NewUsers(runner *ActionRunner, org *db.OrgPool, dir ports.UserDirectory) *Users {
	return &Users{runner: runner, org: org, dir: dir}
}

// Specs of the privileged user actions.
var (
	SpecUserCreate = ActionSpec{Code: audit.CodeUserCreated, AllowedRoles: RolesWrite}
	SpecUserUpdate = ActionSpec{Code: audit.CodeUserUpdated, AllowedRoles: RolesWrite}
	SpecUserDelete = ActionSpec{Code: audit.CodeUserDeleted, AllowedRoles: RolesAdmin}
	SpecUserLock   = ActionSpec{Code: audit.CodeUserLocked, AllowedRoles: RolesAdmin}
	SpecUserUnlock = ActionSpec{Code: audit.CodeUserUnlocked, AllowedRoles: RolesAdmin}
)

// UserQuery selects a page of users.
type UserQuery struct {
	Page    ListPage
	Sources []string
	Locked  *bool
	GroupID *uuid.UUID
}

// List returns one page of users.
func (u *Users) List(ctx context.Context, query UserQuery) (UserList, error) {
	var out UserList
	p, err := RequireOrg(ctx, RolesRead)
	if err != nil {
		return out, err
	}
	err = u.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		org, err := q.GetOrganization(ctx, p.OrganizationID)
		if err != nil {
			return fmt.Errorf("organization: %w", err)
		}
		out.Domains = org.Domains
		if query.GroupID != nil {
			if _, err := q.GetUserGroup(ctx, *query.GroupID); err != nil {
				return notFound(err)
			}
		}
		group := nullID(query.GroupID)
		n, err := q.CountAppUsers(ctx, pgstore.CountAppUsersParams{
			QPattern: query.Page.QPattern, Sources: query.Sources, Locked: query.Locked, GroupID: group, CountLimit: countLimit,
		})
		if err != nil {
			return fmt.Errorf("count users: %w", err)
		}
		out.Count = int(n)
		out.Items, err = q.ListAppUsers(ctx, pgstore.ListAppUsersParams{
			QPattern: query.Page.QPattern, Sources: query.Sources, Locked: query.Locked, GroupID: group,
			Sort: query.Page.Sort, SkipRows: query.Page.Offset, MaxRows: query.Page.Limit,
		})
		if err != nil {
			return fmt.Errorf("list users: %w", err)
		}
		return nil
	})
	return out, err
}

// UserList is one page of users with the domains of their organization (for User.domain_match).
type UserList struct {
	Listed[pgstore.AppUser]
	Domains []string
}

// UserDetail is a user with its groups and the domains of its organization.
type UserDetail struct {
	User    pgstore.AppUser
	Groups  []pgstore.UserGroup
	Domains []string
}

// ChangedUser is a user after a change, with the domains of its organization read in the transaction of the change
// (for User.domain_match).
type ChangedUser struct {
	User    pgstore.AppUser
	Domains []string
}

// Get returns one user; missing and foreign users are both not_found.
func (u *Users) Get(ctx context.Context, id uuid.UUID) (UserDetail, error) {
	p, err := RequireOrg(ctx, RolesRead)
	if err != nil {
		return UserDetail{}, err
	}
	var out UserDetail
	err = u.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		var err error
		if out, err = loadUserDetail(ctx, q, id); err != nil {
			return err
		}
		org, err := q.GetOrganization(ctx, p.OrganizationID)
		if err != nil {
			return fmt.Errorf("organization: %w", err)
		}
		out.Domains = org.Domains
		return nil
	})
	return out, err
}

// ListOwnedDevices returns one page of the devices a user owns (plan M8d decision 4); a missing or foreign user is
// not_found.
func (u *Users) ListOwnedDevices(ctx context.Context, id uuid.UUID, query DeviceQuery) (Listed[pgstore.ListDevicesRow], error) {
	var out Listed[pgstore.ListDevicesRow]
	if _, err := RequireOrg(ctx, RolesRead); err != nil {
		return out, err
	}
	query.OwnerID = &id
	err := u.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		if _, err := q.GetAppUser(ctx, id); err != nil {
			return notFound(err)
		}
		return listDevices(ctx, q, query, &out)
	})
	return out, err
}

func loadUserDetail(ctx context.Context, q *pgstore.Queries, id uuid.UUID) (UserDetail, error) {
	var out UserDetail
	var err error
	if out.User, err = q.GetAppUser(ctx, id); err != nil {
		return out, notFound(err)
	}
	out.Groups, err = q.ListGroupsOfUser(ctx, id)
	return out, err
}

// NewUser is a local user to create.
type NewUser struct {
	Username, DisplayName, Email string
}

// CreatedUser is a new local user with its one-time recovery link (shown once, never stored or audited).
type CreatedUser struct {
	User         pgstore.AppUser
	RecoveryLink string
	// Domains are the organization's domains the username was checked against.
	Domains []string
}

// Create creates a local user in Authentik (no password, member of paddock.<slug>, attribute paddock_managed) and
// in Paddock, and returns a one-time recovery link (audited: user.created).
func (u *Users) Create(ctx context.Context, in NewUser) (CreatedUser, error) {
	in.Username = user.NormalizeUsername(in.Username)
	in.DisplayName = strings.TrimSpace(in.DisplayName)
	in.Email = strings.TrimSpace(in.Email)
	spec := SpecUserCreate
	spec.Params = map[string]any{"username": in.Username, "display_name": in.DisplayName}
	var out CreatedUser
	var slug, pk string
	err := u.runner.RunExternal(ctx, ScopeOrg, spec,
		func(ctx context.Context, q *pgstore.Queries, rec Recorder) error {
			org, err := orgOf(ctx)
			if err != nil {
				return err
			}
			o, err := q.GetOrganization(ctx, org)
			if err != nil {
				return err
			}
			slug, out.Domains = o.Slug, o.Domains
			if err := user.ValidateLocalUsername(in.Username, o.Domains); err != nil {
				return problem.InvalidRequest.WithDetail(err.Error())
			}
			if err := user.ValidateDisplayName(in.DisplayName); err != nil {
				return problem.InvalidRequest.WithDetail(err.Error())
			}
			if err := user.ValidateEmail(in.Email); err != nil {
				return problem.InvalidRequest.WithDetail(err.Error())
			}
			// A new user receives what is granted to everyone (plan M8s decision 7g-sexies).
			guard, err := beginSubjectGuard(ctx, q)
			if err != nil {
				return err
			}
			out.User, err = q.InsertAppUser(ctx, pgstore.InsertAppUserParams{
				ID: uuid.Must(uuid.NewV7()), OrganizationID: org, Username: in.Username, DisplayName: in.DisplayName,
				Email: in.Email, Source: user.SourceLocal,
			})
			if db.IsUniqueViolation(err, "app_user_username_key") {
				return problem.UsernameTaken.WithDetail("a user with this username exists")
			}
			if err != nil {
				return err
			}
			rec.SetTarget(audit.Target{Type: "user", ID: out.User.ID.String(), Display: in.Username})
			return guard.check(ctx, q, rec)
		},
		func(ctx context.Context) error {
			var err error
			pk, err = u.dir.CreateUser(ctx, slug, ports.NewIdentityUser{Username: in.Username, Name: in.DisplayName, Email: in.Email})
			if errors.Is(err, ports.ErrUsernameTaken) {
				return problem.UsernameTaken.WithDetail("a user with this username exists")
			}
			if err != nil {
				return err
			}
			if out.RecoveryLink, err = u.dir.RecoveryLink(ctx, pk); err != nil {
				// Without a link nobody can set the password: remove the user again, the attempt failed.
				if derr := u.dir.DeleteUser(context.WithoutCancel(ctx), pk); derr != nil {
					return errors.Join(err, derr)
				}
				return err
			}
			return nil
		},
		func(ctx context.Context, q *pgstore.Queries, _ Recorder, externalErr error) error {
			if externalErr != nil {
				_, err := q.DeleteAppUser(ctx, out.User.ID)
				return err
			}
			out.User.AuthentikPk = pk
			return q.SetAppUserAuthentikPK(ctx, pgstore.SetAppUserAuthentikPKParams{ID: out.User.ID, AuthentikPk: pk})
		})
	if err != nil {
		return CreatedUser{}, err
	}
	return out, nil
}

// Update changes display name and email of a local user (audited: user.updated). The upstream attributes of synced
// users are read-only (409 attribute_owned_upstream).
func (u *Users) Update(ctx context.Context, id uuid.UUID, displayName, email *string) (ChangedUser, error) {
	spec := SpecUserUpdate
	spec.Target = &audit.Target{Type: "user", ID: id.String()}
	var out pgstore.AppUser
	var domains []string
	err := u.runner.RunExternal(ctx, ScopeOrg, spec,
		func(ctx context.Context, q *pgstore.Queries, rec Recorder) error {
			cur, err := u.localUser(ctx, q, rec, id)
			if err != nil {
				return err
			}
			o, err := q.GetOrganization(ctx, cur.OrganizationID)
			if err != nil {
				return fmt.Errorf("organization: %w", err)
			}
			out, domains = cur, o.Domains
			if displayName != nil {
				out.DisplayName = strings.TrimSpace(*displayName)
			}
			if email != nil {
				out.Email = strings.TrimSpace(*email)
			}
			rec.SetParam("display_name_changed", out.DisplayName != cur.DisplayName)
			rec.SetParam("email_changed", out.Email != cur.Email)
			if err := user.ValidateDisplayName(out.DisplayName); err != nil {
				return problem.InvalidRequest.WithDetail(err.Error())
			}
			if err := user.ValidateEmail(out.Email); err != nil {
				return problem.InvalidRequest.WithDetail(err.Error())
			}
			return nil
		},
		func(ctx context.Context) error {
			return u.dir.UpdateUser(ctx, out.AuthentikPk, out.DisplayName, out.Email)
		},
		func(ctx context.Context, q *pgstore.Queries, _ Recorder, externalErr error) error {
			if externalErr != nil {
				return nil
			}
			var err error
			out, err = q.UpdateAppUser(ctx, pgstore.UpdateAppUserParams{ID: id, DisplayName: out.DisplayName, Email: out.Email})
			return err
		})
	return ChangedUser{User: out, Domains: domains}, err
}

// Delete deletes a local user in Authentik and Paddock, with its memberships and assignments (audited:
// user.deleted). Synced users are removed upstream (409 attribute_owned_upstream).
func (u *Users) Delete(ctx context.Context, id uuid.UUID) error {
	spec := SpecUserDelete
	spec.Target = &audit.Target{Type: "user", ID: id.String()}
	var pk string
	return u.runner.RunExternal(ctx, ScopeOrg, spec,
		func(ctx context.Context, q *pgstore.Queries, rec Recorder) error {
			cur, err := u.localUser(ctx, q, rec, id)
			pk = cur.AuthentikPk
			return err
		},
		func(ctx context.Context) error { return u.dir.DeleteUser(ctx, pk) },
		func(ctx context.Context, q *pgstore.Queries, rec Recorder, externalErr error) error {
			if externalErr != nil {
				return nil
			}
			return withChangeSet(func(ctx context.Context, q *pgstore.Queries, rec Recorder) error {
				return removeUser(ctx, q, rec, id)
			})(ctx, q, rec)
		})
}

// removeUser deletes a user with its assignments and queues a recompile of the organization.
func removeUser(ctx context.Context, q *pgstore.Queries, rec Recorder, id uuid.UUID) error {
	// The assignments of the user are part of the declarative document: every writer of it holds the apply lock, taken
	// first, so a change set never records another writer's change (PDK-154).
	if err := q.LockConfigApply(ctx); err != nil {
		return err
	}
	// A cascading delete serializes with the changes the root-grant guards compare (plan M8s decision 7g-bis).
	if err := q.LockOrganizationPrivileges(ctx); err != nil {
		return err
	}
	if _, err := q.DeleteLoginAssignmentsOfSubject(ctx, id); err != nil {
		return err
	}
	if _, err := q.DeleteProfileAssignmentsOfSubject(ctx, uuid.NullUUID{UUID: id, Valid: true}); err != nil {
		return err
	}
	if _, err := q.DeleteAppUser(ctx, id); err != nil {
		return err
	}
	org, err := orgOf(ctx)
	if err != nil {
		return err
	}
	rec.StateChanged(statechange.ScopeOrg, org)
	return nil
}

// localUser loads a user for a change of its upstream attributes: synced users are refused.
func (u *Users) localUser(ctx context.Context, q *pgstore.Queries, rec Recorder, id uuid.UUID) (pgstore.AppUser, error) {
	cur, err := q.LockAppUser(ctx, id)
	if err != nil {
		return cur, notFound(err)
	}
	rec.SetTarget(audit.Target{Type: "user", ID: id.String(), Display: cur.Username})
	rec.SetParam("username", cur.Username)
	if cur.Source == user.SourceSynced {
		return cur, problem.AttributeOwnedUpstream.WithDetail("the user is synced from an upstream directory; change it there")
	}
	return cur, nil
}

// Lock locks a user (plan M3a decision 7, audited: user.locked). The user is marked locked and the affected devices
// are recompiled on the priority lane before Authentik is called, so the device path never waits for Authentik;
// then the user joins paddock.<slug>.locked and loses its tokens and sessions. The lock stays incomplete until
// Authentik succeeded; locking a locked user repeats the Authentik part (ADR 0007 amendment). The lock reactivates
// the user only if it was active before (plan M4b.1 decision 1); the retry of an incomplete lock uses the state read by
// the interrupted attempt, which may have deactivated the user already.
func (u *Users) Lock(ctx context.Context, id uuid.UUID) (ChangedUser, error) {
	spec := SpecUserLock
	spec.Target = &audit.Target{Type: "user", ID: id.String()}
	var out pgstore.AppUser
	var org pgstore.Organization
	var reactivate *bool
	read := false
	err := u.runner.RunExternal(ctx, ScopeOrg, spec,
		func(ctx context.Context, q *pgstore.Queries, rec Recorder) error {
			cur, o, err := u.lockable(ctx, q, rec, id)
			if err != nil {
				return err
			}
			org = o
			if cur.Locked && cur.LockIncomplete {
				reactivate = cur.LockReactivate
			}
			if out, err = q.SetAppUserLocked(ctx, pgstore.SetAppUserLockedParams{ID: id, Locked: true}); err != nil {
				return err
			}
			out.AuthentikPk = cur.AuthentikPk
			rec.PriorityStateChanged(statechange.ScopeUser, id)
			return nil
		},
		func(ctx context.Context) error {
			if reactivate == nil {
				active, err := u.dir.UserActive(ctx, out.AuthentikPk)
				if err != nil {
					return err
				}
				reactivate, read = &active, true
			}
			return u.dir.LockUser(ctx, org.Slug, out.AuthentikPk, *reactivate)
		},
		func(ctx context.Context, q *pgstore.Queries, _ Recorder, externalErr error) error {
			// Stored even if the lock failed afterwards: its retry must not read the state the lock left behind.
			if read {
				err := q.SetAppUserLockReactivate(ctx, pgstore.SetAppUserLockReactivateParams{ID: id, LockReactivate: reactivate})
				if err != nil {
					return err
				}
			}
			if externalErr != nil {
				return nil
			}
			var err error
			out, err = q.CompleteAppUserLock(ctx, id)
			return err
		})
	return ChangedUser{User: out, Domains: org.Domains}, err
}

// Unlock removes the user from paddock.<slug>.locked and, once that succeeded, marks it unlocked and recompiles its
// devices on the priority lane (audited: user.unlocked). It activates the user only to complete an interrupted lock of
// a user that was active before; a user deactivated elsewhere stays inactive (plan M4b.1 decision 2).
func (u *Users) Unlock(ctx context.Context, id uuid.UUID) (ChangedUser, error) {
	spec := SpecUserUnlock
	spec.Target = &audit.Target{Type: "user", ID: id.String()}
	var out pgstore.AppUser
	var org pgstore.Organization
	err := u.runner.RunExternal(ctx, ScopeOrg, spec,
		func(ctx context.Context, q *pgstore.Queries, rec Recorder) error {
			cur, o, err := u.lockable(ctx, q, rec, id)
			out, org = cur, o
			return err
		},
		func(ctx context.Context) error {
			activate := out.LockIncomplete && out.LockReactivate != nil && *out.LockReactivate
			return u.dir.UnlockUser(ctx, org.Slug, out.AuthentikPk, activate)
		},
		func(ctx context.Context, q *pgstore.Queries, rec Recorder, externalErr error) error {
			if externalErr != nil {
				return nil
			}
			var err error
			if out, err = q.SetAppUserLocked(ctx, pgstore.SetAppUserLockedParams{ID: id, Locked: false}); err != nil {
				return err
			}
			rec.PriorityStateChanged(statechange.ScopeUser, id)
			return nil
		})
	return ChangedUser{User: out, Domains: org.Domains}, err
}

func (u *Users) lockable(ctx context.Context, q *pgstore.Queries, rec Recorder, id uuid.UUID) (pgstore.AppUser, pgstore.Organization, error) {
	cur, err := q.LockAppUser(ctx, id)
	if err != nil {
		return cur, pgstore.Organization{}, notFound(err)
	}
	rec.SetTarget(audit.Target{Type: "user", ID: id.String(), Display: cur.Username})
	rec.SetParam("username", cur.Username)
	rec.SetParam("source", cur.Source)
	if cur.AuthentikPk == "" {
		return cur, pgstore.Organization{}, problem.InvalidState.WithDetail("the user is not provisioned in Authentik")
	}
	o, err := q.GetOrganization(ctx, cur.OrganizationID)
	return cur, o, err
}
