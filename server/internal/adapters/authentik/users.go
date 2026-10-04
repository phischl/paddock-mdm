package authentik

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/paddock-mdm/paddock/server/internal/domain/organization"
	"github.com/paddock-mdm/paddock/server/internal/ports"
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
}

func (u user) identity() ports.IdentityUser {
	managed, _ := u.Attributes[attrManaged].(bool)
	return ports.IdentityUser{PK: strconv.Itoa(u.PK), Username: u.Username, Name: u.Name, Email: u.Email, Managed: managed}
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

// LockUser adds the user to paddock.<slug>.locked and deletes the user's refresh tokens, access tokens and
// authenticated sessions. The group alone does not stop Hello PIN logins: the refresh grant does not evaluate
// application policies (PoC M1 C2).
func (c *Client) LockUser(ctx context.Context, slug, pk string) error {
	lockedPK, err := c.EnsureGroup(ctx, slug, organization.LockedGroup(slug))
	if err != nil {
		return err
	}
	if err := c.AddMember(ctx, lockedPK, pk); err != nil {
		return err
	}
	for _, kind := range []string{"refresh_tokens", "access_tokens"} {
		var ids []int
		err := pages(ctx, c, "/api/v3/oauth2/"+kind+"/", url.Values{"user": {pk}}, func(t struct {
			PK int `json:"pk"`
		}) {
			ids = append(ids, t.PK)
		})
		if err != nil {
			return err
		}
		for _, id := range ids {
			if err := c.deleteIgnoringMissing(ctx, "/api/v3/oauth2/"+kind+"/"+strconv.Itoa(id)+"/"); err != nil {
				return err
			}
		}
	}
	if err := c.do(ctx, http.MethodDelete, "/api/v3/core/authenticated_sessions/bulk_delete/?"+url.Values{"user_pks": {pk}}.Encode(), nil, nil); err != nil {
		return upstream(err)
	}
	return nil
}

// UnlockUser removes the user from paddock.<slug>.locked; the user then signs in with the device code flow again.
func (c *Client) UnlockUser(ctx context.Context, slug, pk string) error {
	lockedPK, err := c.EnsureGroup(ctx, slug, organization.LockedGroup(slug))
	if err != nil {
		return err
	}
	return c.RemoveMember(ctx, lockedPK, pk)
}

// OrganizationUsers lists the direct members of paddock.<slug>.
func (c *Client) OrganizationUsers(ctx context.Context, slug string) ([]ports.IdentityUser, error) {
	q := url.Values{"groups_by_name": {organization.RootGroup(slug)}, "include_groups": {"false"}}
	var out []ports.IdentityUser
	err := pages(ctx, c, "/api/v3/core/users/", q, func(u user) { out = append(out, u.identity()) })
	return out, err
}

func userPath(pk string) string { return "/api/v3/core/users/" + url.PathEscape(pk) + "/" }
