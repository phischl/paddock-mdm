package app

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"

	"github.com/paddock-mdm/paddock/server/internal/adapters/postgres/pgstore"
	"github.com/paddock-mdm/paddock/server/internal/domain/audit"
	"github.com/paddock-mdm/paddock/server/internal/domain/statechange"
	"github.com/paddock-mdm/paddock/server/internal/domain/user"
	"github.com/paddock-mdm/paddock/server/internal/platform/db"
	"github.com/paddock-mdm/paddock/server/internal/ports"
	"github.com/paddock-mdm/paddock/server/internal/problem"
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
func (u *Users) List(ctx context.Context, query UserQuery) (Listed[pgstore.AppUser], error) {
	var out Listed[pgstore.AppUser]
	if _, err := RequireOrg(ctx, RolesRead); err != nil {
		return out, err
	}
	err := u.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
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

// UserDetail is a user with its groups.
type UserDetail struct {
	User   pgstore.AppUser
	Groups []pgstore.UserGroup
}

// Get returns one user; missing and foreign users are both not_found.
func (u *Users) Get(ctx context.Context, id uuid.UUID) (UserDetail, error) {
	if _, err := RequireOrg(ctx, RolesRead); err != nil {
		return UserDetail{}, err
	}
	var out UserDetail
	err := u.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		var err error
		out, err = loadUserDetail(ctx, q, id)
		return err
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
			slug = o.Slug
			if err := user.ValidateLocalUsername(in.Username, o.Domains); err != nil {
				return problem.InvalidRequest.WithDetail(err.Error())
			}
			if err := user.ValidateDisplayName(in.DisplayName); err != nil {
				return problem.InvalidRequest.WithDetail(err.Error())
			}
			if err := user.ValidateEmail(in.Email); err != nil {
				return problem.InvalidRequest.WithDetail(err.Error())
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
			return nil
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
func (u *Users) Update(ctx context.Context, id uuid.UUID, displayName, email *string) (pgstore.AppUser, error) {
	spec := SpecUserUpdate
	spec.Target = &audit.Target{Type: "user", ID: id.String()}
	var out pgstore.AppUser
	err := u.runner.RunExternal(ctx, ScopeOrg, spec,
		func(ctx context.Context, q *pgstore.Queries, rec Recorder) error {
			cur, err := u.localUser(ctx, q, rec, id)
			if err != nil {
				return err
			}
			out = cur
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
	return out, err
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
			return removeUser(ctx, q, rec, id)
		})
}

// removeUser deletes a user with its assignments and queues a recompile of the organization.
func removeUser(ctx context.Context, q *pgstore.Queries, rec Recorder, id uuid.UUID) error {
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
// then the user joins paddock.<slug>.locked and loses its tokens and sessions. Locking a locked user repeats the
// Authentik part.
func (u *Users) Lock(ctx context.Context, id uuid.UUID) (pgstore.AppUser, error) {
	spec := SpecUserLock
	spec.Target = &audit.Target{Type: "user", ID: id.String()}
	var out pgstore.AppUser
	var slug string
	err := u.runner.RunExternal(ctx, ScopeOrg, spec,
		func(ctx context.Context, q *pgstore.Queries, rec Recorder) error {
			cur, s, err := u.lockable(ctx, q, rec, id)
			if err != nil {
				return err
			}
			slug = s
			if out, err = q.SetAppUserLocked(ctx, pgstore.SetAppUserLockedParams{ID: id, Locked: true}); err != nil {
				return err
			}
			out.AuthentikPk = cur.AuthentikPk
			rec.PriorityStateChanged(statechange.ScopeUser, id)
			return nil
		},
		func(ctx context.Context) error { return u.dir.LockUser(ctx, slug, out.AuthentikPk) },
		func(context.Context, *pgstore.Queries, Recorder, error) error { return nil })
	return out, err
}

// Unlock removes the user from paddock.<slug>.locked and, once that succeeded, marks it unlocked and recompiles its
// devices on the priority lane (audited: user.unlocked).
func (u *Users) Unlock(ctx context.Context, id uuid.UUID) (pgstore.AppUser, error) {
	spec := SpecUserUnlock
	spec.Target = &audit.Target{Type: "user", ID: id.String()}
	var out pgstore.AppUser
	var slug string
	err := u.runner.RunExternal(ctx, ScopeOrg, spec,
		func(ctx context.Context, q *pgstore.Queries, rec Recorder) error {
			cur, s, err := u.lockable(ctx, q, rec, id)
			out, slug = cur, s
			return err
		},
		func(ctx context.Context) error { return u.dir.UnlockUser(ctx, slug, out.AuthentikPk) },
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
	return out, err
}

func (u *Users) lockable(ctx context.Context, q *pgstore.Queries, rec Recorder, id uuid.UUID) (pgstore.AppUser, string, error) {
	cur, err := q.LockAppUser(ctx, id)
	if err != nil {
		return cur, "", notFound(err)
	}
	rec.SetTarget(audit.Target{Type: "user", ID: id.String(), Display: cur.Username})
	rec.SetParam("username", cur.Username)
	rec.SetParam("source", cur.Source)
	if cur.AuthentikPk == "" {
		return cur, "", problem.InvalidState.WithDetail("the user is not provisioned in Authentik")
	}
	o, err := q.GetOrganization(ctx, cur.OrganizationID)
	return cur, o.Slug, err
}
