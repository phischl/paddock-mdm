package acceptance

import (
	"context"
	"net/http"
	"net/url"
	"slices"
	"testing"
	"time"

	"github.com/paddock-mdm/paddock/test/acceptance/internal/env"
)

// syncRound bounds the wait for one identity sync round of the worker (60 s in the development stack) plus the
// round's own duration.
const syncRound = 3 * time.Minute

// waitSyncedUser polls the user list until username is listed as synced and returns its ID.
func waitSyncedUser(t *testing.T, p *env.Portal, username string) string {
	t.Helper()
	deadline := time.Now().Add(syncRound)
	for {
		res := call(t, p, http.MethodGet, "/api/v1/users?"+url.Values{"q": {username}, "source": {"synced"}}.Encode(), nil)
		expectStatus(t, res, http.StatusOK, "")
		var page struct {
			Items []struct {
				ID       string `json:"id"`
				Username string `json:"username"`
			} `json:"items"`
		}
		if err := res.JSON(&page); err != nil {
			t.Fatal(err)
		}
		for _, u := range page.Items {
			if u.Username == username {
				return u.ID
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("synced user %s not listed within %s", username, syncRound)
		}
		time.Sleep(5 * time.Second)
	}
}

// TestIdentitySync is gate I4 (plan M3a §6): an Authentik user put into paddock.acme (as an upstream source's
// property mapping would) appears as synced within one sync round; its upstream attributes are read-only in
// Paddock; importing an upstream group creates paddock.acme.s.<slug> with the group's members of acme.
func TestIdentitySync(t *testing.T) {
	alice := login(t, env.Alice)
	ak, err := env.NewAuthentik()
	if err != nil {
		t.Fatal(err)
	}
	ctx := testContext(t, 10*time.Minute)
	upstream := newDeviceUser(t, ak, "i4", "upstream-i4.test", env.RootGroup("acme"))
	id := waitSyncedUser(t, alice, upstream.name)

	for _, c := range []struct{ method, path string }{
		{http.MethodPatch, "/api/v1/users/" + id},
		{http.MethodDelete, "/api/v1/users/" + id},
	} {
		var body any
		if c.method == http.MethodPatch {
			body = map[string]string{"display_name": "changed in Paddock"}
		}
		res := call(t, alice, c.method, c.path, body)
		expectStatus(t, res, http.StatusConflict, "attribute_owned_upstream")
	}

	// An upstream group (a name Himmelblau would drop) with the synced user and a user of no organization.
	groupName := "I4 Upstream: " + uniqueSuffix()
	groupPK, err := ak.EnsureGroup(ctx, groupName)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ak.Delete(context.Background(), "/core/groups/"+groupPK+"/") })
	stranger := newDeviceUser(t, ak, "i4-stranger", "upstream-i4.test")
	for _, u := range []string{upstream.name, stranger.name} {
		if err := ak.AddToGroup(ctx, u, groupName); err != nil {
			t.Fatal(err)
		}
	}
	slug := "i4-" + uniqueSuffix()
	res := call(t, alice, http.MethodPost, "/api/v1/user-groups", map[string]string{"slug": slug, "name": groupName, "upstream_group_id": groupPK})
	expectStatus(t, res, http.StatusCreated, "")
	group := createdID(t, alice, "/api/v1/user-groups", res)
	expectOneEvent(t, alice, res.RequestID, "user_group.created", "success")

	mirror := env.RootGroup("acme") + ".s." + slug
	members, err := ak.GroupMembers(ctx, mirror)
	if err != nil || !slices.Equal(members, []string{upstream.name}) {
		t.Fatalf("mirror group %s members %v (%v), want only the synced acme user", mirror, members, err)
	}
	res = call(t, alice, http.MethodGet, "/api/v1/user-groups/"+group+"/members", nil)
	expectStatus(t, res, http.StatusOK, "")
	var page struct {
		Items []struct {
			Username string `json:"username"`
		} `json:"items"`
	}
	if err := res.JSON(&page); err != nil || len(page.Items) != 1 || page.Items[0].Username != upstream.name {
		t.Fatalf("Paddock members %s (%v)", res.Body, err)
	}
	// The members of an imported group follow upstream only.
	res = call(t, alice, http.MethodPost, "/api/v1/user-groups/"+group+"/members", map[string]string{"user_id": id})
	expectStatus(t, res, http.StatusConflict, "attribute_owned_upstream")
}
