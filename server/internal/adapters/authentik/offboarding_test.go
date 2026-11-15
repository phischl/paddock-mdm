package authentik_test

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/phischl/paddock-mdm/server/internal/adapters/authentik"
	"github.com/phischl/paddock-mdm/server/internal/domain/organization"
	"github.com/phischl/paddock-mdm/server/internal/ports"
	"github.com/phischl/paddock-mdm/server/internal/problem"
)

// remains lists what the fake still holds of the organization slug: groups paddock.<slug> and paddock.<slug>.*, the
// device login application, provider, groups mapping, access policy, any binding of them, and Paddock-created users.
func (f *fakeAuthentik) remains(slug string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	root := organization.RootGroup(slug)
	for _, g := range f.groups {
		if g.name == root || strings.HasPrefix(g.name, root+".") {
			out = append(out, "group "+g.name)
		}
	}
	app := organization.DeviceLoginApp(slug)
	appPK := ""
	if a, ok := f.objects["applications"][app]; ok {
		out = append(out, "application "+app)
		appPK = key(a["pk"])
	}
	policyPK := ""
	for coll, name := range map[string]string{"providers": app, "scopemappings": authentik.GroupsMappingName(slug),
		"policies": authentik.AccessPolicyName(slug)} {
		for _, obj := range f.objects[coll] {
			if obj["name"] == name {
				out = append(out, coll+" "+name)
				if coll == "policies" {
					policyPK = key(obj["pk"])
				}
			}
		}
	}
	for _, b := range f.objects["bindings"] {
		if (appPK != "" && key(b["target"]) == appPK) || (policyPK != "" && key(b["policy"]) == policyPK) {
			out = append(out, "binding")
		}
	}
	for _, u := range f.users {
		if managed, _ := u.attributes["paddock_managed"].(bool); managed && u.path == "paddock/"+slug {
			out = append(out, "user "+u.username)
		}
	}
	return out
}

// TestDeleteOrganization (plan M17 decision 10, PDK-1015): the organization's groups (children before the root),
// device login application, provider, groups mapping, access policy and its binding, and the users Paddock created
// there are gone; a synced user, a user Paddock did not create on that path, and every object of another organization
// stay. A second call finds nothing and counts nothing.
func TestDeleteOrganization(t *testing.T) {
	f, srv := newFake(t)
	c := client(srv)
	ctx := context.Background()
	for _, slug := range []string{"acme", "acme-x"} {
		if _, err := c.EnsureOrganization(ctx, slug); err != nil {
			t.Fatal(err)
		}
		if _, err := c.EnsureGroup(ctx, slug, organization.RootGroup(slug)+".login.device"); err != nil {
			t.Fatal(err)
		}
		if _, err := c.CreateUser(ctx, slug, ports.NewIdentityUser{Username: "local-" + slug, Name: "Local", Email: "l@example.org"}); err != nil {
			t.Fatal(err)
		}
	}
	root := f.groupByName("paddock.acme")
	f.users[900] = &fakeUser{pk: 900, username: "synced", attributes: map[string]any{}, groups: []string{root.pk}}
	f.users[901] = &fakeUser{pk: 901, username: "moved", path: "paddock/acme", attributes: map[string]any{}, groups: []string{root.pk}}
	otherBefore := f.remains("acme-x")
	if len(f.remains("acme")) == 0 || len(otherBefore) == 0 {
		t.Fatal("the fixture has no objects")
	}

	got, err := c.DeleteOrganization(ctx, "acme")
	if err != nil {
		t.Fatal(err)
	}
	want := ports.OrgIdentityDeletion{Groups: 6, Users: 1, Applications: 1, Providers: 1, Policies: 2, Mappings: 1}
	if got != want || got.Total() != 12 {
		t.Fatalf("deleted %+v, want %+v", got, want)
	}
	if left := f.remains("acme"); len(left) != 0 {
		t.Fatalf("left in Authentik: %v", left)
	}
	if len(f.deletingParent) != 0 {
		t.Fatalf("groups deleted while still a parent: %v", f.deletingParent)
	}
	if f.deletedGroups[len(f.deletedGroups)-1] != "paddock.acme" {
		t.Fatalf("deletion order %v, want the root last", f.deletedGroups)
	}
	for _, pk := range []int{900, 901} {
		if _, ok := f.users[pk]; !ok {
			t.Fatalf("user %d was deleted", pk)
		}
	}
	if after := f.remains("acme-x"); len(after) != len(otherBefore) {
		t.Fatalf("another organization lost objects: before %v, after %v", otherBefore, after)
	}

	again, err := c.DeleteOrganization(ctx, "acme")
	if err != nil || again.Total() != 0 {
		t.Fatalf("second deletion: %+v, %v", again, err)
	}
}

// TestDeleteOrganizationUnavailable: an unreachable Authentik is upstream_unavailable; the next call deletes the rest.
func TestDeleteOrganizationUnavailable(t *testing.T) {
	f, srv := newFake(t)
	c := client(srv)
	ctx := context.Background()
	if _, err := c.EnsureOrganization(ctx, "acme"); err != nil {
		t.Fatal(err)
	}
	f.failNext, f.failStatus = 10, http.StatusServiceUnavailable
	if _, err := c.DeleteOrganization(ctx, "acme"); !errors.Is(err, problem.UpstreamUnavailable) {
		t.Fatalf("Authentik down: %v", err)
	}
	f.failNext = 0
	if _, err := c.DeleteOrganization(ctx, "acme"); err != nil {
		t.Fatal(err)
	}
	if left := f.remains("acme"); len(left) != 0 {
		t.Fatalf("left in Authentik after recovery: %v", left)
	}
}
