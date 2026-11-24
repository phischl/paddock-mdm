package authentik

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/phischl/paddock-mdm/server/internal/domain/organization"
	"github.com/phischl/paddock-mdm/server/internal/ports"
)

// DeleteOrganization deletes the organization's identity objects (plan M17 decision 10): the device login application
// first, so the organization's devices admit no new login while the rest goes, then its policy bindings, provider,
// access policy and groups mapping, the users Paddock created in the organization (path paddock/<slug> and attribute
// paddock_managed), and the groups paddock.<slug> and paddock.<slug>.*, children before their parent. Users synced from
// upstream stay, only their memberships go with the groups; before any user or group goes, the sign-in setup links of
// every direct member of the groups are ended and its mark paddock_password_by_link removed (PDK-1112), because once
// the groups are gone nothing ties a surviving account to the organization any more. Policies counts the access
// policy and its bindings. A failure leaves the rest for the next attempt, which finds only what is left.
func (c *Client) DeleteOrganization(ctx context.Context, slug string) (ports.OrgIdentityDeletion, error) {
	var d ports.OrgIdentityDeletion
	app := organization.DeviceLoginApp(slug)
	appPK, err := c.applicationPK(ctx, app)
	if err != nil {
		return d, err
	}
	if appPK != "" {
		n, err := c.deleteBindings(ctx, url.Values{"target": {appPK}})
		d.Policies += n
		if err != nil {
			return d, err
		}
		if d.Applications, err = c.deleteCounted(ctx, "/api/v3/core/applications/"+url.PathEscape(app)+"/"); err != nil {
			return d, err
		}
	}
	if d.Providers, err = c.deleteNamed(ctx, "/api/v3/providers/oauth2/", app); err != nil {
		return d, err
	}
	policy, err := c.findOne(ctx, "/api/v3/policies/expression/", url.Values{"name": {AccessPolicyName(slug)}})
	if err != nil {
		return d, err
	}
	if policy != "" {
		n, err := c.deleteBindings(ctx, url.Values{"policy": {policy}})
		d.Policies += n
		if err != nil {
			return d, err
		}
		n, err = c.deleteCounted(ctx, "/api/v3/policies/expression/"+url.PathEscape(policy)+"/")
		d.Policies += n
		if err != nil {
			return d, err
		}
	}
	if d.Mappings, err = c.deleteNamed(ctx, "/api/v3/propertymappings/provider/scope/", GroupsMappingName(slug)); err != nil {
		return d, err
	}
	links, err := c.endMembersLinks(ctx, slug)
	if err != nil {
		return d, err
	}
	if d.Users, err = c.deleteManagedUsers(ctx, slug); err != nil {
		return d, err
	}
	if d.Groups, err = c.deleteOrganizationGroups(ctx, slug); err != nil {
		return d, err
	}
	slog.InfoContext(ctx, "authentik organization deleted", "slug", slug, "groups", d.Groups, "users", d.Users, "links", links,
		"applications", d.Applications, "providers", d.Providers, "policies", d.Policies, "mappings", d.Mappings)
	return d, nil
}

// applicationPK returns the pk of the application with slug app, or "" when it does not exist. The application is
// read by slug: the list is filtered by the caller's own access (ensureApplication).
func (c *Client) applicationPK(ctx context.Context, app string) (string, error) {
	var existing named
	err := c.do(ctx, http.MethodGet, "/api/v3/core/applications/"+url.PathEscape(app)+"/", nil, &existing)
	var st *errStatus
	switch {
	case err == nil:
		return existing.pk(), nil
	case errors.As(err, &st) && st.code == http.StatusNotFound:
		return "", nil
	}
	return "", upstream(err)
}

// deleteBindings deletes every policy binding matching q and returns how many it deleted.
func (c *Client) deleteBindings(ctx context.Context, q url.Values) (int, error) {
	var pks []string
	if err := pages(ctx, c, "/api/v3/policies/bindings/", q, func(b named) { pks = append(pks, b.pk()) }); err != nil {
		return 0, err
	}
	deleted := 0
	for _, pk := range pks {
		n, err := c.deleteCounted(ctx, "/api/v3/policies/bindings/"+url.PathEscape(pk)+"/")
		deleted += n
		if err != nil {
			return deleted, err
		}
	}
	return deleted, nil
}

// deleteNamed deletes the object name of collection, if it exists, and returns 1 when it deleted it.
func (c *Client) deleteNamed(ctx context.Context, collection, name string) (int, error) {
	pk, err := c.findOne(ctx, collection, url.Values{"name": {name}})
	if err != nil || pk == "" {
		return 0, err
	}
	return c.deleteCounted(ctx, collection+url.PathEscape(pk)+"/")
}

// deleteManagedUsers deletes the users Paddock created in the organization: path paddock/<slug> (CreateUser) and the
// attribute paddock_managed. The path alone does not decide: an administrator may have moved a synced user there.
func (c *Client) deleteManagedUsers(ctx context.Context, slug string) (int, error) {
	var pks []string
	err := pages(ctx, c, "/api/v3/core/users/", url.Values{"path": {"paddock/" + slug}, "include_groups": {"false"}},
		func(u user) {
			if managed, _ := u.Attributes[attrManaged].(bool); managed {
				pks = append(pks, strconv.Itoa(u.PK))
			}
		})
	if err != nil {
		return 0, err
	}
	deleted := 0
	for _, pk := range pks {
		n, err := c.deleteCounted(ctx, userPath(pk))
		deleted += n
		if err != nil {
			return deleted, err
		}
	}
	return deleted, nil
}

// endMembersLinks ends the sign-in setup links of every direct member of paddock.<slug> and paddock.<slug>.* and
// removes its mark paddock_password_by_link, and returns how many unexpired links it ended. A member gone meanwhile is
// skipped and a link or mark already gone is no error, so a retried deletion finds only what is left.
func (c *Client) endMembersLinks(ctx context.Context, slug string) (int, error) {
	groups, err := c.organizationGroups(ctx, slug)
	if err != nil || len(groups) == 0 {
		return 0, err
	}
	names := make([]string, 0, len(groups))
	for _, g := range groups {
		names = append(names, g.Name)
	}
	members, err := c.RoleGroupsUsers(ctx, names)
	if err != nil {
		return 0, err
	}
	ended := 0
	seen := make(map[string]bool, len(members))
	for _, m := range members {
		if seen[m.PK] {
			continue
		}
		seen[m.PK] = true
		n, err := c.RevokeRecoveryLinks(ctx, m.PK)
		ended += n
		var st *errStatus
		if errors.As(err, &st) && st.code == http.StatusNotFound {
			continue
		}
		if err != nil {
			return ended, err
		}
		err = c.SetUserAttribute(ctx, m.PK, ports.AttrPasswordByLink, nil)
		if errors.As(err, &st) && st.code == http.StatusNotFound {
			continue
		}
		if err != nil {
			return ended, err
		}
	}
	return ended, nil
}

// organizationGroups lists paddock.<slug> and every group whose name starts with paddock.<slug>.. Slugs contain no
// ".", so the prefix matches no other organization's groups.
func (c *Client) organizationGroups(ctx context.Context, slug string) ([]group, error) {
	root := organization.RootGroup(slug)
	var groups []group
	err := pages(ctx, c, "/api/v3/core/groups/", url.Values{"search": {root}, "include_users": {"false"}}, func(g group) {
		if g.Name == root || strings.HasPrefix(g.Name, root+".") {
			groups = append(groups, g)
		}
	})
	return groups, err
}

// deleteOrganizationGroups deletes the organization's groups (organizationGroups), deepest first, so no group is
// deleted while it is still a parent.
func (c *Client) deleteOrganizationGroups(ctx context.Context, slug string) (int, error) {
	groups, err := c.organizationGroups(ctx, slug)
	if err != nil {
		return 0, err
	}
	slices.SortFunc(groups, func(a, b group) int {
		if d := strings.Count(b.Name, ".") - strings.Count(a.Name, "."); d != 0 {
			return d
		}
		return strings.Compare(a.Name, b.Name)
	})
	deleted := 0
	for _, g := range groups {
		n, err := c.deleteCounted(ctx, "/api/v3/core/groups/"+url.PathEscape(g.PK)+"/")
		deleted += n
		if err != nil {
			return deleted, err
		}
	}
	return deleted, nil
}

// deleteCounted deletes an object and returns 1, or 0 when it no longer existed.
func (c *Client) deleteCounted(ctx context.Context, path string) (int, error) {
	err := c.do(ctx, http.MethodDelete, path, nil, nil)
	var st *errStatus
	switch {
	case err == nil:
		return 1, nil
	case errors.As(err, &st) && st.code == http.StatusNotFound:
		return 0, nil
	}
	return 0, upstream(err)
}
