package authentik

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/phischl/paddock-mdm/server/internal/domain/organization"
	"github.com/phischl/paddock-mdm/server/internal/ports"
	"github.com/phischl/paddock-mdm/server/internal/problem"
)

// Attributes Paddock sets on the users it creates; users without paddock_managed are synced from upstream.
const (
	attrManaged = "paddock_managed"
	attrOrg     = "paddock_org"
)

// RecoveryLinkValidity is the validity of the one-time links of new local users (plan M3a decision 18).
const RecoveryLinkValidity = "hours=24"

type user struct {
	PK         int            `json:"pk"`
	Username   string         `json:"username"`
	Name       string         `json:"name"`
	Email      string         `json:"email"`
	Attributes map[string]any `json:"attributes"`
	IsActive   bool           `json:"is_active"`
	UID        string         `json:"uid"`
	// GroupsObj are the direct groups of the user (only with include_groups=true).
	GroupsObj []group `json:"groups_obj"`
}

func (u user) identity() ports.IdentityUser {
	managed, _ := u.Attributes[attrManaged].(bool)
	return ports.IdentityUser{PK: strconv.Itoa(u.PK), Username: u.Username, Name: u.Name, Email: u.Email, Managed: managed,
		Active: u.IsActive, UID: u.UID}
}

// CreateUser creates a Paddock-managed internal user without password in the organization's root group (path
// paddock/<slug>). Authentik refuses duplicate usernames with 400 on the username field: ErrUsernameTaken.
func (c *Client) CreateUser(ctx context.Context, slug string, nu ports.NewIdentityUser) (string, error) {
	rootPK, err := c.findGroup(ctx, organization.RootGroup(slug))
	if err != nil {
		return "", err
	}
	if rootPK == "" {
		return "", upstream(fmt.Errorf("group %s missing", organization.RootGroup(slug)))
	}
	body := map[string]any{
		"username": nu.Username, "name": nu.Name, "email": nu.Email, "type": "internal", "is_active": true,
		"path": "paddock/" + slug, "groups": []string{rootPK},
		"attributes": map[string]any{attrManaged: true, attrOrg: slug},
	}
	var created user
	if err := c.do(ctx, http.MethodPost, "/api/v3/core/users/", body, &created); err != nil {
		var st *errStatus
		if errors.As(err, &st) && st.code == http.StatusBadRequest && strings.Contains(st.body, `"username"`) {
			return "", ports.ErrUsernameTaken
		}
		return "", upstream(err)
	}
	return strconv.Itoa(created.PK), nil
}

// UpdateUser changes display name and email.
func (c *Client) UpdateUser(ctx context.Context, pk, name, email string) error {
	if err := c.do(ctx, http.MethodPatch, userPath(pk), map[string]string{"name": name, "email": email}, nil); err != nil {
		return upstream(err)
	}
	return nil
}

// DeleteUser deletes a user; a missing user is not an error.
func (c *Client) DeleteUser(ctx context.Context, pk string) error {
	return c.deleteIgnoringMissing(ctx, userPath(pk))
}

// RecoveryLink creates a recovery link for the brand's recovery flow (paddock-recovery), valid 24 h.
func (c *Client) RecoveryLink(ctx context.Context, pk string) (string, error) {
	var res struct {
		Link string `json:"link"`
	}
	if err := c.do(ctx, http.MethodPost, userPath(pk)+"recovery/", map[string]string{"token_duration": RecoveryLinkValidity}, &res); err != nil {
		return "", upstream(err)
	}
	if res.Link == "" {
		return "", upstream(errors.New("recovery link missing in the response"))
	}
	return res.Link, nil
}

// UserMembership reads the user username directly, with its groups, and requires its UID: a username can be reused.
func (c *Client) UserMembership(ctx context.Context, username, uid string) (ports.IdentityUser, []string, bool, error) {
	q := url.Values{"username": {username}, "include_groups": {"true"}, "page": {"1"}, "page_size": {strconv.Itoa(pageSize)}}
	var page struct {
		Results []user `json:"results"`
	}
	if err := c.do(ctx, http.MethodGet, "/api/v3/core/users/?"+q.Encode(), nil, &page); err != nil {
		return ports.IdentityUser{}, nil, false, upstream(err)
	}
	for _, u := range page.Results {
		if u.UID != uid {
			continue
		}
		groups := make([]string, 0, len(u.GroupsObj))
		for _, g := range u.GroupsObj {
			groups = append(groups, g.Name)
		}
		return u.identity(), groups, true, nil
	}
	return ports.IdentityUser{}, nil, false, nil
}

// UserActive reports the user's is_active.
func (c *Client) UserActive(ctx context.Context, pk string) (bool, error) {
	var u struct {
		IsActive bool `json:"is_active"`
	}
	if err := c.do(ctx, http.MethodGet, userPath(pk), nil, &u); err != nil {
		return false, upstream(err)
	}
	return u.IsActive, nil
}

// LockUser adds the user to paddock.<slug>.locked and revokes the user's refresh tokens, access tokens and sessions.
// The group alone does not stop Hello PIN logins: the refresh grant does not evaluate application policies (PoC M1
// C2). Authentik lists other users' tokens only to superusers, so the revocation uses its deactivation cleanup: the
// user is deactivated (Authentik deletes all of the user's tokens and sessions) and, if reactivate is set, activated
// again at once — the lock itself stays the group membership, which survives upstream attribute syncs (architecture
// §9.2). Without reactivate a user deactivated elsewhere stays inactive (plan M4b.1 decision 1).
func (c *Client) LockUser(ctx context.Context, slug, pk string, reactivate bool) error {
	lockedPK, err := c.EnsureGroup(ctx, slug, organization.LockedGroup(slug))
	if err != nil {
		return err
	}
	if err := c.AddMember(ctx, lockedPK, pk); err != nil {
		return err
	}
	if err := c.setActive(ctx, pk, false); err != nil {
		return err
	}
	if !reactivate {
		return nil
	}
	return c.setActive(ctx, pk, true)
}

// UnlockUser removes the user from paddock.<slug>.locked; with activate it first activates the user again, which
// completes a lock that stopped between deactivation and reactivation. The user then signs in with the device code
// flow again.
func (c *Client) UnlockUser(ctx context.Context, slug, pk string, activate bool) error {
	lockedPK, err := c.EnsureGroup(ctx, slug, organization.LockedGroup(slug))
	if err != nil {
		return err
	}
	if activate {
		if err := c.setActive(ctx, pk, true); err != nil {
			return err
		}
	}
	return c.RemoveMember(ctx, lockedPK, pk)
}

func (c *Client) setActive(ctx context.Context, pk string, active bool) error {
	if err := c.do(ctx, http.MethodPatch, userPath(pk), map[string]bool{"is_active": active}, nil); err != nil {
		return upstream(err)
	}
	return nil
}

// OrganizationUsers lists the direct members of paddock.<slug>.
func (c *Client) OrganizationUsers(ctx context.Context, slug string) ([]ports.IdentityUser, error) {
	q := url.Values{"groups_by_name": {organization.RootGroup(slug)}, "include_groups": {"false"}}
	var out []ports.IdentityUser
	err := pages(ctx, c, "/api/v3/core/users/", q, func(u user) { out = append(out, u.identity()) })
	return out, err
}

// roleGroupAttempts is how often a role group is listed again when its membership changed during a listing.
const roleGroupAttempts = 3

// RoleGroupUsers lists the direct members of the role group groupName. Authentik refuses a filter on a group name it
// does not know with 400 on groups_by_name: ports.ErrGroupNotFound. Pages are numbered, so a member that leaves during
// the listing shifts the next page and another member could be skipped: the listing is ordered by pk and repeated when
// the total changed between pages or does not match what was read, and fails if it never settles.
func (c *Client) RoleGroupUsers(ctx context.Context, groupName string) ([]ports.IdentityUser, error) {
	return c.groupMembers(ctx, []string{groupName}, groupName)
}

// roleGroupsQueryBytes bounds the encoded group names of one listing of RoleGroupsUsers, so the request line stays
// far below the limits of proxies and of Authentik's HTTP server (16 KiB for the request head).
const roleGroupsQueryBytes = 4096

// RoleGroupsUsers lists the direct members of the groups groupNames with one settled listing per batch of names
// instead of one per group, so ending all sessions does not grow by a call per role group (PDK-501). Authentik
// filters by several names at once and refuses the whole batch when it does not know one of them; the groups that do
// not exist are skipped (existingGroupsMembers). A user in groups of several batches is listed once per batch.
func (c *Client) RoleGroupsUsers(ctx context.Context, groupNames []string) ([]ports.IdentityUser, error) {
	var out []ports.IdentityUser
	for len(groupNames) > 0 {
		n, size := 0, 0
		for n < len(groupNames) {
			param := len("&groups_by_name=") + len(url.QueryEscape(groupNames[n]))
			if n > 0 && size+param > roleGroupsQueryBytes {
				break
			}
			size += param
			n++
		}
		users, err := c.existingGroupsMembers(ctx, groupNames[:n])
		if err != nil {
			return nil, err
		}
		out = append(out, users...)
		groupNames = groupNames[n:]
	}
	return out, nil
}

// existingGroupsMembers lists the direct members of the groups names, skipping the groups that do not exist. Authentik
// names the first unknown group in its refusal: that group is dropped and the rest listed again, so each missing group
// costs one listing. A refusal that names none of them (a changed message) halves the batch instead.
func (c *Client) existingGroupsMembers(ctx context.Context, names []string) ([]ports.IdentityUser, error) {
	for len(names) > 0 {
		users, err := c.groupMembers(ctx, names, fmt.Sprintf("%d role groups from %s", len(names), names[0]))
		var missing *missingGroup
		if !errors.As(err, &missing) {
			return users, err
		}
		if len(names) == 1 {
			return nil, nil
		}
		if i := slices.IndexFunc(names, func(n string) bool { return strings.Contains(missing.body, " "+n+" ") }); i >= 0 {
			names = slices.Delete(slices.Clone(names), i, i+1)
			continue
		}
		first, err := c.existingGroupsMembers(ctx, names[:len(names)/2])
		if err != nil {
			return nil, err
		}
		second, err := c.existingGroupsMembers(ctx, names[len(names)/2:])
		if err != nil {
			return nil, err
		}
		return append(first, second...), nil
	}
	return nil, nil
}

// missingGroup is Authentik's refusal of a group name it does not know; body is the refusal, which names the group.
type missingGroup struct{ what, body string }

func (e *missingGroup) Error() string { return e.what + ": " + ports.ErrGroupNotFound.Error() }

func (e *missingGroup) Unwrap() error { return ports.ErrGroupNotFound }

// groupMembers lists the direct members of any of the groups names in one settled listing; what names them in an
// error. Authentik refuses a filter on a group name it does not know with 400 on groups_by_name: ErrGroupNotFound.
func (c *Client) groupMembers(ctx context.Context, names []string, what string) ([]ports.IdentityUser, error) {
	out, err := c.settledUsers(ctx, url.Values{"groups_by_name": names}, what)
	var st *errStatus
	if errors.As(err, &st) && st.code == http.StatusBadRequest && strings.Contains(st.body, `"groups_by_name"`) {
		return nil, &missingGroup{what: what, body: st.body}
	}
	return out, err
}

// Superusers lists the users with Authentik superuser rights (is_superuser=true: a member of a group with superuser
// rights), with the same settled listing as RoleGroupUsers (plan M8b decision 33).
func (c *Client) Superusers(ctx context.Context) ([]ports.IdentityUser, error) {
	return c.settledUsers(ctx, url.Values{"is_superuser": {"true"}}, "the superusers")
}

// GroupReadable reads the group groupName by name. Authentik validates the groups_by_name filter of a user listing
// against every group, whatever the token may see, so an empty role group listing alone does not show that the token
// can read the group (PDK-424).
func (c *Client) GroupReadable(ctx context.Context, groupName string) (bool, error) {
	pk, err := c.findGroup(ctx, groupName)
	return pk != "", err
}

// UsersVisible lists one page of internal and external users. Authentik filters a user listing by the token's
// permissions and answers an empty page, not an error, to a token that may no longer see users; the paddock-service
// account is a service account and does not count (PDK-424).
func (c *Client) UsersVisible(ctx context.Context) (bool, error) {
	q := url.Values{"type": {"internal", "external"}, "include_groups": {"false"}, "ordering": {"pk"}, "page": {"1"}, "page_size": {"1"}}
	var page struct {
		Results []struct {
			Type string `json:"type"`
		} `json:"results"`
	}
	if err := c.do(ctx, http.MethodGet, "/api/v3/core/users/?"+q.Encode(), nil, &page); err != nil {
		return false, upstream(err)
	}
	// The type is checked again in case a later Authentik ignores the filter: a service account never proves sight.
	for _, u := range page.Results {
		if u.Type == "internal" || u.Type == "external" {
			return true, nil
		}
	}
	return false, nil
}

// settledUsers lists the users matching filter, repeating the listing when it did not settle; what names the listing
// in the error.
func (c *Client) settledUsers(ctx context.Context, filter url.Values, what string) ([]ports.IdentityUser, error) {
	for range roleGroupAttempts {
		out, settled, err := c.listSettled(ctx, filter, what)
		if err != nil || settled {
			return out, err
		}
	}
	return nil, fmt.Errorf("%w: the members of %s changed during every listing", problem.UpstreamUnavailable, what)
}

// listSettled reads every page of the users matching filter; settled is false when the total changed between pages or
// differs from the members read.
func (c *Client) listSettled(ctx context.Context, filter url.Values, what string) (out []ports.IdentityUser, settled bool, err error) {
	q := url.Values{"include_groups": {"false"}, "ordering": {"pk"}, "page_size": {strconv.Itoa(pageSize)}}
	maps.Copy(q, filter)
	total := -1
	for page := 1; page <= maxPages; page++ {
		q.Set("page", strconv.Itoa(page))
		var res struct {
			Pagination struct {
				Next  int `json:"next"`
				Count int `json:"count"`
			} `json:"pagination"`
			Results []user `json:"results"`
		}
		if err := c.do(ctx, http.MethodGet, "/api/v3/core/users/?"+q.Encode(), nil, &res); err != nil {
			return nil, false, upstream(err)
		}
		if total >= 0 && res.Pagination.Count != total {
			return nil, false, nil
		}
		total = res.Pagination.Count
		for _, u := range res.Results {
			out = append(out, u.identity())
		}
		if res.Pagination.Next == 0 {
			return out, len(out) == total, nil
		}
	}
	return nil, false, fmt.Errorf("authentik: %s has more than %d pages of members", what, maxPages)
}

// EndUserSessions deletes every Authentik authenticated session of the users userPKs in one bulk delete and returns
// how many it deleted; Authentik deletes the browser's Django session with each, which signs the browser out (plan
// M8f decision 17). The caller chunks the users. A bulk delete repeated after a timeout or a 5xx reports only what its
// last attempt found left, so the caller counts the sessions first (CountUserSessions, PDK-342).
func (c *Client) EndUserSessions(ctx context.Context, userPKs []string) (int, error) {
	if len(userPKs) == 0 {
		return 0, nil
	}
	q := url.Values{}
	for _, pk := range userPKs {
		if _, err := strconv.Atoi(pk); err != nil {
			return 0, fmt.Errorf("authentik: user pk %q is not an integer", pk)
		}
		q.Add("user_pks", pk)
	}
	var res struct {
		Deleted int `json:"deleted"`
	}
	if err := c.do(ctx, http.MethodDelete, "/api/v3/core/authenticated_sessions/bulk_delete/?"+q.Encode(), nil, &res); err != nil {
		return 0, upstream(err)
	}
	return res.Deleted, nil
}

// CountUserSessions counts the Authentik authenticated sessions of the users userPKs in one listing of every session;
// the listing has no filter by user pk.
func (c *Client) CountUserSessions(ctx context.Context, userPKs []string) (int, error) {
	users := make(map[int]bool, len(userPKs))
	for _, pk := range userPKs {
		n, err := strconv.Atoi(pk)
		if err != nil {
			return 0, fmt.Errorf("authentik: user pk %q is not an integer", pk)
		}
		users[n] = true
	}
	if len(users) == 0 {
		return 0, nil
	}
	n := 0
	err := pages(ctx, c, "/api/v3/core/authenticated_sessions/", url.Values{}, func(s struct {
		User int `json:"user"`
	}) {
		if users[s.User] {
			n++
		}
	})
	if err != nil {
		return 0, err
	}
	return n, nil
}

func userPath(pk string) string { return "/api/v3/core/users/" + url.PathEscape(pk) + "/" }
