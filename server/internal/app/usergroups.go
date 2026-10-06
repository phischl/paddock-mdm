package app

import (
	"cmp"
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
	"github.com/phischl/paddock-mdm/server/internal/domain/statechange"
	"github.com/phischl/paddock-mdm/server/internal/domain/usergroup"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/ports"
	"github.com/phischl/paddock-mdm/server/internal/problem"
)

// UserGroups are the user group use cases (plan M3a decisions 3 and 4).
type UserGroups struct {
	runner *ActionRunner
	org    *db.OrgPool
	dir    ports.GroupDirectory
}

// NewUserGroups creates the use cases.
func NewUserGroups(runner *ActionRunner, org *db.OrgPool, dir ports.GroupDirectory) *UserGroups {
	return &UserGroups{runner: runner, org: org, dir: dir}
}

// Specs of the privileged user group actions.
var (
	SpecUserGroupCreate       = ActionSpec{Code: audit.CodeUserGroupCreated, AllowedRoles: RolesWrite}
	SpecUserGroupUpdate       = ActionSpec{Code: audit.CodeUserGroupUpdated, AllowedRoles: RolesWrite}
	SpecUserGroupDelete       = ActionSpec{Code: audit.CodeUserGroupDeleted, AllowedRoles: RolesAdmin}
	SpecUserGroupMemberAdd    = ActionSpec{Code: audit.CodeUserGroupMemberAdded, AllowedRoles: RolesWrite}
	SpecUserGroupMemberRemove = ActionSpec{Code: audit.CodeUserGroupMemberRemoved, AllowedRoles: RolesWrite}
)

// List returns one page of user groups.
func (g *UserGroups) List(ctx context.Context, page ListPage, sources []string) (Listed[pgstore.UserGroup], error) {
	var out Listed[pgstore.UserGroup]
	if _, err := RequireOrg(ctx, RolesRead); err != nil {
		return out, err
	}
	err := g.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		n, err := q.CountUserGroups(ctx, pgstore.CountUserGroupsParams{QPattern: page.QPattern, Sources: sources, CountLimit: countLimit})
		if err != nil {
			return fmt.Errorf("count user groups: %w", err)
		}
		out.Count = int(n)
		out.Items, err = q.ListUserGroups(ctx, pgstore.ListUserGroupsParams{
			QPattern: page.QPattern, Sources: sources, Sort: page.Sort, SkipRows: page.Offset, MaxRows: page.Limit,
		})
		if err != nil {
			return fmt.Errorf("list user groups: %w", err)
		}
		return nil
	})
	return out, err
}

// Get returns one user group.
func (g *UserGroups) Get(ctx context.Context, id uuid.UUID) (pgstore.UserGroup, error) {
	if _, err := RequireOrg(ctx, RolesRead); err != nil {
		return pgstore.UserGroup{}, err
	}
	var out pgstore.UserGroup
	err := g.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		var err error
		out, err = q.GetUserGroup(ctx, id)
		return notFound(err)
	})
	return out, err
}

// UpstreamGroups returns one page of the Authentik groups outside Paddock's namespace with at least one member of
// the organization (the import picker, plan M3b decision 1), sorted by name and searched by name in memory.
func (g *UserGroups) UpstreamGroups(ctx context.Context, page ListPage, q *string) (Listed[ports.IdentityGroup], error) {
	var out Listed[ports.IdentityGroup]
	if _, err := RequireOrg(ctx, RolesWrite); err != nil {
		return out, err
	}
	var slug string
	err := g.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		o, err := q.GetOrganization(ctx, mustOrg(ctx))
		slug = o.Slug
		return err
	})
	if err != nil {
		return out, err
	}
	all, err := g.dir.UpstreamGroups(ctx, slug)
	if err != nil {
		return out, err
	}
	var match []ports.IdentityGroup
	for _, x := range all {
		if q == nil || strings.Contains(strings.ToLower(x.Name), strings.ToLower(*q)) {
			match = append(match, x)
		}
	}
	// Case-insensitive like the database collation of the other lists, then by name and pk for a stable order.
	slices.SortFunc(match, func(a, b ports.IdentityGroup) int {
		return cmp.Or(cmp.Compare(strings.ToLower(a.Name), strings.ToLower(b.Name)), cmp.Compare(a.Name, b.Name), cmp.Compare(a.PK, b.PK))
	})
	if page.Sort == "-name" {
		slices.Reverse(match)
	}
	out.Count = min(len(match), countLimit)
	from := min(int(page.Offset), len(match))
	out.Items = match[from:min(from+int(page.Limit), len(match))]
	return out, nil
}

// NewUserGroup is a group to create: local, or an import of the upstream group UpstreamPK.
type NewUserGroup struct {
	Slug, Name string
	UpstreamPK *string
}

// Create creates a local group paddock.<slug>.g.<group> or imports an upstream group as mirror group
// paddock.<slug>.s.<group> with its current members of the organization (audited: user_group.created).
func (g *UserGroups) Create(ctx context.Context, in NewUserGroup) (pgstore.UserGroup, error) {
	in.Slug = strings.TrimSpace(in.Slug)
	in.Name = usergroup.NormalizeName(in.Name)
	source := usergroup.SourceLocal
	if in.UpstreamPK != nil {
		source = usergroup.SourceSynced
	}
	spec := SpecUserGroupCreate
	spec.Params = map[string]any{"slug": in.Slug, "name": in.Name, "source": source}
	var out pgstore.UserGroup
	var slug string
	var users map[string]uuid.UUID // Authentik pk → user, for the mirror
	var mirrored []uuid.UUID
	err := g.runner.RunExternal(ctx, ScopeOrg, spec,
		func(ctx context.Context, q *pgstore.Queries, rec Recorder) error {
			if err := usergroup.ValidateSlug(in.Slug); err != nil {
				return problem.InvalidRequest.WithDetail(err.Error())
			}
			if err := usergroup.ValidateName(in.Name); err != nil {
				return problem.InvalidRequest.WithDetail(err.Error())
			}
			org, err := orgOf(ctx)
			if err != nil {
				return err
			}
			o, err := q.GetOrganization(ctx, org)
			if err != nil {
				return err
			}
			slug = o.Slug
			if users, err = usersByAuthentikPK(ctx, q); err != nil {
				return err
			}
			out, err = q.InsertUserGroup(ctx, pgstore.InsertUserGroupParams{
				ID: uuid.Must(uuid.NewV7()), OrganizationID: org, Slug: in.Slug, Name: in.Name, Source: source,
				UpstreamAuthentikPk: in.UpstreamPK,
			})
			if db.IsUniqueViolation(err, "user_group_organization_id_slug_key") {
				return problem.SlugTaken.WithDetail("a user group with this slug exists")
			}
			if err != nil {
				return err
			}
			rec.SetTarget(audit.Target{Type: "user_group", ID: out.ID.String(), Display: in.Name})
			return nil
		},
		func(ctx context.Context) error {
			if in.UpstreamPK != nil {
				var err error
				if mirrored, err = g.importMembers(ctx, slug, *in.UpstreamPK, users); err != nil {
					return err
				}
			}
			pk, err := g.dir.EnsureGroup(ctx, slug, AuthentikGroupName(slug, out))
			if err != nil {
				return err
			}
			out.AuthentikPk = pk
			for _, u := range mirrored {
				if err := g.dir.AddMember(ctx, pk, authentikPKOf(users, u)); err != nil {
					return err
				}
			}
			return nil
		},
		func(ctx context.Context, q *pgstore.Queries, rec Recorder, externalErr error) error {
			if externalErr != nil {
				_, err := q.DeleteUserGroup(ctx, out.ID)
				return err
			}
			if err := q.SetUserGroupAuthentikPK(ctx, pgstore.SetUserGroupAuthentikPKParams{ID: out.ID, AuthentikPk: out.AuthentikPk}); err != nil {
				return err
			}
			for _, u := range mirrored {
				if _, err := q.InsertUserGroupMember(ctx, pgstore.InsertUserGroupMemberParams{
					OrganizationID: out.OrganizationID, GroupID: out.ID, UserID: u,
				}); err != nil {
					return err
				}
			}
			rec.SetParam("members", len(mirrored))
			if len(mirrored) > 0 {
				rec.StateChanged(statechange.ScopeOrg, out.OrganizationID)
			}
			return nil
		})
	return out, err
}

// importMembers checks that upstreamPK is an upstream group the organization may see (plan M3b decision 1; any
// other group is not found) and returns its members that are users of the organization.
func (g *UserGroups) importMembers(ctx context.Context, slug, upstreamPK string, users map[string]uuid.UUID) ([]uuid.UUID, error) {
	upstream, err := g.dir.UpstreamGroups(ctx, slug)
	if err != nil {
		return nil, err
	}
	if !slices.ContainsFunc(upstream, func(x ports.IdentityGroup) bool { return x.PK == upstreamPK }) {
		return nil, problem.NotFound.WithDetail("upstream group not found")
	}
	pks, err := g.dir.GroupMembers(ctx, upstreamPK)
	if err != nil {
		return nil, err
	}
	var out []uuid.UUID
	for _, pk := range pks {
		if u, ok := users[pk]; ok {
			out = append(out, u)
		}
	}
	return out, nil
}

func usersByAuthentikPK(ctx context.Context, q *pgstore.Queries) (map[string]uuid.UUID, error) {
	all, err := q.ListAllAppUsers(ctx)
	if err != nil {
		return nil, err
	}
	out := map[string]uuid.UUID{}
	for _, u := range all {
		if u.AuthentikPk != "" {
			out[u.AuthentikPk] = u.ID
		}
	}
	return out, nil
}

func authentikPKOf(users map[string]uuid.UUID, id uuid.UUID) string {
	for pk, u := range users {
		if u == id {
			return pk
		}
	}
	return ""
}

// Rename changes the display name of a group (audited: user_group.updated).
func (g *UserGroups) Rename(ctx context.Context, id uuid.UUID, name string) (pgstore.UserGroup, error) {
	spec := SpecUserGroupUpdate
	spec.Target = &audit.Target{Type: "user_group", ID: id.String()}
	var out pgstore.UserGroup
	err := g.runner.RunTx(ctx, ScopeOrg, spec, func(ctx context.Context, q *pgstore.Queries, rec Recorder) error {
		cur, err := q.GetUserGroup(ctx, id)
		if err != nil {
			return notFound(err)
		}
		name := usergroup.NormalizeName(name)
		rec.SetTarget(audit.Target{Type: "user_group", ID: id.String(), Display: name})
		rec.SetParam("slug", cur.Slug)
		rec.SetParam("name", name)
		rec.SetParam("old_name", cur.Name)
		if err := usergroup.ValidateName(name); err != nil {
			return problem.InvalidRequest.WithDetail(err.Error())
		}
		out, err = q.UpdateUserGroupName(ctx, pgstore.UpdateUserGroupNameParams{ID: id, Name: name})
		return err
	})
	return out, err
}

// Delete deletes a group in Authentik and Paddock with its memberships, login and profile assignments (audited:
// user_group.deleted).
func (g *UserGroups) Delete(ctx context.Context, id uuid.UUID) error {
	spec := SpecUserGroupDelete
	spec.Target = &audit.Target{Type: "user_group", ID: id.String()}
	var pk string
	return g.runner.RunExternal(ctx, ScopeOrg, spec,
		func(ctx context.Context, q *pgstore.Queries, rec Recorder) error {
			cur, err := q.GetUserGroup(ctx, id)
			if err != nil {
				return notFound(err)
			}
			pk = cur.AuthentikPk
			rec.SetTarget(audit.Target{Type: "user_group", ID: id.String(), Display: cur.Name})
			rec.SetParam("slug", cur.Slug)
			rec.SetParam("name", cur.Name)
			return nil
		},
		func(ctx context.Context) error {
			if pk == "" {
				return nil
			}
			return g.dir.DeleteGroup(ctx, pk)
		},
		func(ctx context.Context, q *pgstore.Queries, rec Recorder, externalErr error) error {
			if externalErr != nil {
				return nil
			}
			if _, err := q.DeleteLoginAssignmentsOfSubject(ctx, id); err != nil {
				return err
			}
			if _, err := q.DeleteProfileAssignmentsOfSubject(ctx, uuid.NullUUID{UUID: id, Valid: true}); err != nil {
				return err
			}
			if _, err := q.DeleteUserGroup(ctx, id); err != nil {
				return err
			}
			org, err := orgOf(ctx)
			if err != nil {
				return err
			}
			rec.StateChanged(statechange.ScopeOrg, org)
			return nil
		})
}

// AddMember adds a user to a local group (audited: user_group.member_added with the user's highest effective
// class before and after). Members of imported groups are mirrored from upstream (409 attribute_owned_upstream).
func (g *UserGroups) AddMember(ctx context.Context, groupID, userID uuid.UUID) error {
	return g.changeMember(ctx, SpecUserGroupMemberAdd, groupID, userID, true)
}

// RemoveMember removes a user from a local group (audited: user_group.member_removed).
func (g *UserGroups) RemoveMember(ctx context.Context, groupID, userID uuid.UUID) error {
	return g.changeMember(ctx, SpecUserGroupMemberRemove, groupID, userID, false)
}

func (g *UserGroups) changeMember(ctx context.Context, spec ActionSpec, groupID, userID uuid.UUID, add bool) error {
	spec.Target = &audit.Target{Type: "user_group", ID: groupID.String()}
	var groupPK, userPK string
	return g.runner.RunExternal(ctx, ScopeOrg, spec,
		func(ctx context.Context, q *pgstore.Queries, rec Recorder) error {
			group, err := q.GetUserGroup(ctx, groupID)
			if err != nil {
				return notFound(err)
			}
			rec.SetTarget(audit.Target{Type: "user_group", ID: groupID.String(), Display: group.Name})
			rec.SetParam("group", group.Slug)
			u, err := q.GetAppUser(ctx, userID)
			if err != nil {
				return notFound(err)
			}
			rec.SetParam("user", u.Username)
			if group.Source == usergroup.SourceSynced {
				return problem.AttributeOwnedUpstream.WithDetail("the members of an imported group are mirrored from upstream")
			}
			if group.AuthentikPk == "" || u.AuthentikPk == "" {
				return problem.InvalidState.WithDetail("group or user is not provisioned in Authentik")
			}
			groupPK, userPK = group.AuthentikPk, u.AuthentikPk
			return recordMembershipChange(ctx, q, rec, group, userID, add)
		},
		func(ctx context.Context) error {
			if add {
				return g.dir.AddMember(ctx, groupPK, userPK)
			}
			return g.dir.RemoveMember(ctx, groupPK, userPK)
		},
		func(ctx context.Context, q *pgstore.Queries, rec Recorder, externalErr error) error {
			if externalErr == nil {
				rec.StateChanged(statechange.ScopeOrg, mustOrg(ctx))
				return nil
			}
			// Authentik refused the change: undo it in Paddock, the action failed.
			group, err := q.GetUserGroup(ctx, groupID)
			if err != nil {
				return err
			}
			return changeMembership(ctx, q, group, userID, !add)
		})
}

// recordMembershipChange applies a membership change in Paddock and records the user's highest effective class
// before and after it (plan M3a decision 4). Adding a present or removing an absent member is a no-op.
func recordMembershipChange(ctx context.Context, q *pgstore.Queries, rec Recorder, group pgstore.UserGroup, userID uuid.UUID, add bool) error {
	before, err := LoadIdentity(ctx, q)
	if err != nil {
		return err
	}
	if err := changeMembership(ctx, q, group, userID, add); err != nil {
		return err
	}
	after, err := LoadIdentity(ctx, q)
	if err != nil {
		return err
	}
	rec.SetParam("effective_class_before", string(before.HighestClass(userID)))
	rec.SetParam("effective_class_after", string(after.HighestClass(userID)))
	return nil
}

func changeMembership(ctx context.Context, q *pgstore.Queries, group pgstore.UserGroup, userID uuid.UUID, add bool) error {
	if add {
		_, err := q.InsertUserGroupMember(ctx, pgstore.InsertUserGroupMemberParams{
			OrganizationID: group.OrganizationID, GroupID: group.ID, UserID: userID,
		})
		return err
	}
	_, err := q.DeleteUserGroupMember(ctx, pgstore.DeleteUserGroupMemberParams{GroupID: group.ID, UserID: userID})
	return err
}

// mustOrg is the organization of a transaction opened by InOrg, which guarantees it.
func mustOrg(ctx context.Context) uuid.UUID {
	org, _ := orgOf(ctx)
	return org
}
