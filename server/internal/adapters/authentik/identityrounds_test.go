package authentik_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"testing"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/domain/organization"
	"github.com/phischl/paddock-mdm/server/internal/ports"
	"github.com/phischl/paddock-mdm/server/internal/problem"
)

// addGroup puts the group name with the users members into the fake and returns its pk.
func (f *fakeAuthentik) addGroup(name string, members ...int) string {
	pk := uuid.NewString()
	f.groups[pk] = &fakeGroup{pk: pk, name: name, parents: []string{}}
	for _, m := range members {
		if f.users[m] == nil {
			f.users[m] = &fakeUser{pk: m, username: "u" + strconv.Itoa(m)}
		}
		f.users[m].groups = append(f.users[m].groups, pk)
	}
	return pk
}

func pksOf(users []ports.IdentityUser) []string {
	out := make([]string, 0, len(users))
	for _, u := range users {
		out = append(out, u.PK)
	}
	slices.Sort(out)
	return out
}

// TestRoleGroupsMembers (PDK-570): an organization's three role groups come from one settled listing, keyed by group;
// a user in several groups is a member of each, a group without members has an empty key and a missing group none.
func TestRoleGroupsMembers(t *testing.T) {
	f, srv := newFake(t)
	c := client(srv)
	ctx := context.Background()
	admins, operators, auditors := "paddock.acme.admins", "paddock.acme.operators", "paddock.acme.auditors"
	f.addGroup(admins, 10, 11)
	f.addGroup(operators)
	audPK := f.addGroup(auditors, 12)
	f.users[10].groups = append(f.users[10].groups, audPK)
	f.addGroup("paddock.acme.locked", 13)
	f.requests = nil
	got, err := c.RoleGroupsMembers(ctx, []string{admins, operators, auditors})
	if err != nil {
		t.Fatal(err)
	}
	if n := f.count("GET /api/v3/core/users/"); n != 1 {
		t.Fatalf("%d listings for the three role groups, want 1", n)
	}
	if len(got) != 3 || !slices.Equal(pksOf(got[admins]), []string{"10", "11"}) || got[operators] == nil ||
		len(got[operators]) != 0 || !slices.Equal(pksOf(got[auditors]), []string{"10", "12"}) {
		t.Fatalf("members %v", got)
	}
	// A missing group has no key and costs one refused listing; the others are still listed.
	f.requests = nil
	got, err = c.RoleGroupsMembers(ctx, []string{admins, "paddock.globex.admins", auditors})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := got["paddock.globex.admins"]; ok || len(got) != 2 || !slices.Equal(pksOf(got[auditors]), []string{"10", "12"}) {
		t.Fatalf("members with a missing group %v", got)
	}
	if n := f.count("GET /api/v3/core/users/"); n != 2 {
		t.Fatalf("%d listings with a missing group, want 2", n)
	}
	if got, err := c.RoleGroupsMembers(ctx, []string{"paddock.globex.admins"}); err != nil || len(got) != 0 {
		t.Fatalf("only a missing group: %v %v", got, err)
	}
}

// TestRoleGroupsMembersPaging (PDK-570): exactly one page, a page boundary and an error in the middle of the listing.
// A failed page fails the whole listing: no group comes back, so none reads as empty or short.
func TestRoleGroupsMembersPaging(t *testing.T) {
	for _, tc := range []struct{ members, pages int }{{0, 1}, {500, 1}, {501, 2}, {1000, 2}, {1001, 3}} {
		t.Run(strconv.Itoa(tc.members), func(t *testing.T) {
			f, srv := newFake(t)
			c := client(srv)
			members := make([]int, 0, tc.members)
			for i := range tc.members {
				members = append(members, 1000+i)
			}
			f.addGroup("paddock.acme.admins", members...)
			f.addGroup("paddock.acme.operators", members[:min(len(members), 3)]...)
			f.addGroup("paddock.acme.auditors")
			names := []string{"paddock.acme.admins", "paddock.acme.operators", "paddock.acme.auditors"}
			got, err := c.RoleGroupsMembers(context.Background(), names)
			if err != nil {
				t.Fatal(err)
			}
			if len(got["paddock.acme.admins"]) != tc.members || len(got["paddock.acme.operators"]) != min(tc.members, 3) {
				t.Fatalf("%d admins, %d operators", len(got["paddock.acme.admins"]), len(got["paddock.acme.operators"]))
			}
			if n := f.count("GET /api/v3/core/users/"); n != tc.pages {
				t.Fatalf("%d pages, want %d", n, tc.pages)
			}
		})
	}
	f, srv := newFake(t)
	c := client(srv)
	members := make([]int, 0, 700)
	for i := range 700 {
		members = append(members, 1000+i)
	}
	f.addGroup("paddock.acme.admins", members...)
	pages := 0
	f.afterUserPage = func() {
		if pages++; pages == 1 {
			f.failNext, f.failStatus = 10, http.StatusServiceUnavailable
		}
	}
	got, err := c.RoleGroupsMembers(context.Background(), []string{"paddock.acme.admins"})
	if !errors.Is(err, problem.UpstreamUnavailable) || got != nil {
		t.Fatalf("a listing failing on its second page: %v %v", len(got), err)
	}
}

// TestRoleGroupsMembersWithoutGroupsObj (PDK-570): an Authentik that answers the role listing without the users'
// direct groups fails the listing, so ListRoleGroups keeps the error for every group and none reads as empty.
func TestRoleGroupsMembersWithoutGroupsObj(t *testing.T) {
	f, srv := newFake(t)
	c := client(srv)
	ctx := context.Background()
	names := []string{"paddock.acme.admins", "paddock.acme.operators", "paddock.acme.auditors"}
	f.addGroup(names[0], 10)
	f.addGroup(names[1], 11)
	f.addGroup(names[2])
	f.dropGroupsObj = true
	got, err := c.RoleGroupsMembers(ctx, names)
	if !errors.Is(err, problem.UpstreamUnavailable) || got != nil {
		t.Fatalf("a listing without groups_obj: %v %v", got, err)
	}
	groups := app.ListRoleGroups(ctx, c, names...)
	for _, name := range names {
		if m, err := groups.Members(name); !errors.Is(err, problem.UpstreamUnavailable) || m != nil {
			t.Fatalf("role group %s: %v %v", name, m, err)
		}
	}
}

// TestRoleGroupsMembersHalvedBatch (PDK-570): a refusal that names no group halves the batch; a user in groups of both
// halves is listed by both, and is still a member of each group once.
func TestRoleGroupsMembersHalvedBatch(t *testing.T) {
	f, srv := newFake(t)
	c := client(srv)
	admins, operators, auditors := "paddock.acme.admins", "paddock.acme.operators", "paddock.acme.auditors"
	f.addGroup(admins, 10, 11)
	f.addGroup(operators)
	audPK := f.addGroup(auditors, 12)
	f.users[10].groups = append(f.users[10].groups, audPK)
	f.unnamedGroupRefusal = true
	got, err := c.RoleGroupsMembers(context.Background(), []string{admins, operators, "paddock.globex.admins", auditors})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || !slices.Equal(pksOf(got[admins]), []string{"10", "11"}) || len(got[operators]) != 0 ||
		!slices.Equal(pksOf(got[auditors]), []string{"10", "12"}) {
		t.Fatalf("members of a halved batch %v", got)
	}
}

// TestDeviceLoginGroups (PDK-570): the organization's per-device groups with their members in one listing; groups of
// other organizations and names that only contain the prefix are left out.
func TestDeviceLoginGroups(t *testing.T) {
	f, srv := newFake(t)
	c := client(srv)
	ctx := context.Background()
	if got, err := c.DeviceLoginGroups(ctx, "acme"); err != nil || len(got) != 0 {
		t.Fatalf("no device groups: %v %v", got, err)
	}
	d1, d2, d3 := uuid.New(), uuid.New(), uuid.New()
	g1 := f.addGroup(organization.DeviceLoginGroup("acme", d1), 21, 22)
	g2 := f.addGroup(organization.DeviceLoginGroup("acme", d2))
	g3 := f.addGroup(organization.DeviceLoginGroup("acme", d3), 21)
	f.addGroup(organization.DeviceLoginGroup("acme2", d1), 21)
	f.addGroup("upstream "+organization.DeviceLoginGroup("acme", d2), 21)
	f.addGroup(organization.RoleGroup("acme", organization.GroupAdmins), 21)
	f.requests = nil
	got, err := c.DeviceLoginGroups(ctx, "acme")
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]ports.IdentityGroupMembers{
		organization.DeviceLoginGroup("acme", d1): {PK: g1, Members: []string{"21", "22"}},
		organization.DeviceLoginGroup("acme", d2): {PK: g2, Members: []string{}},
		organization.DeviceLoginGroup("acme", d3): {PK: g3, Members: []string{"21"}},
	}
	if len(got) != len(want) {
		t.Fatalf("groups %v, want %v", got, want)
	}
	for name, w := range want {
		if g := got[name]; g.PK != w.PK || !slices.Equal(g.Members, w.Members) {
			t.Fatalf("group %s: %+v, want %+v", name, g, w)
		}
	}
	if n := f.count("GET /api/v3/core/groups/"); n != 1 || len(f.requests) != 1 {
		t.Fatalf("%d requests, want one group listing", len(f.requests))
	}
	// A group without its member list fails the listing instead of reading as a group without members.
	f.groupsWithoutUsers = true
	if got, err := c.DeviceLoginGroups(ctx, "acme"); err == nil || got != nil {
		t.Fatalf("groups without members: %v %v", got, err)
	}
}

// TestDeviceLoginGroupsPaging (PDK-570): exactly one page, a page boundary, a group deleted during the listing, a
// listing that never settles and an error in the middle of the listing; the last two return no groups at all.
func TestDeviceLoginGroupsPaging(t *testing.T) {
	fill := func(f *fakeAuthentik, n int) []string {
		var names []string
		for i := range n {
			name := organization.DeviceLoginGroup("acme", uuid.New())
			f.addGroup(name, 3000+i)
			names = append(names, name)
		}
		return names
	}
	for _, tc := range []struct{ groups, pages int }{{1, 1}, {500, 1}, {501, 2}, {1000, 2}} {
		t.Run(strconv.Itoa(tc.groups), func(t *testing.T) {
			f, srv := newFake(t)
			fill(f, tc.groups)
			got, err := client(srv).DeviceLoginGroups(context.Background(), "acme")
			if err != nil || len(got) != tc.groups {
				t.Fatalf("%d groups, %v", len(got), err)
			}
			if n := f.count("GET /api/v3/core/groups/"); n != tc.pages {
				t.Fatalf("%d pages, want %d", n, tc.pages)
			}
		})
	}
	f, srv := newFake(t)
	c := client(srv)
	ctx := context.Background()
	names := fill(f, 700)
	// The first group by name is on page 1, so its deletion always shifts page 2.
	first := slices.Min(names)
	gone := f.groupByName(first)
	deleted := false
	f.afterGroupPage = func() {
		if !deleted {
			deleted = true
			delete(f.groups, gone.pk)
		}
	}
	got, err := c.DeviceLoginGroups(ctx, "acme")
	if _, ok := got[first]; err != nil || len(got) != 699 || ok {
		t.Fatalf("a group deleted during the listing: %d groups, %v", len(got), err)
	}
	f.afterGroupPage = func() { f.addGroup(organization.DeviceLoginGroup("acme", uuid.New())) }
	if got, err := c.DeviceLoginGroups(ctx, "acme"); !errors.Is(err, problem.UpstreamUnavailable) || got != nil {
		t.Fatalf("a listing that never settles: %d groups, %v", len(got), err)
	}
	pages := 0
	f.afterGroupPage = func() {
		if pages++; pages == 1 {
			f.failNext, f.failStatus = 10, http.StatusServiceUnavailable
		}
	}
	if got, err := c.DeviceLoginGroups(ctx, "acme"); !errors.Is(err, problem.UpstreamUnavailable) || got != nil {
		t.Fatalf("a listing failing on its second page: %d groups, %v", len(got), err)
	}
}

// TestIdentityRoundRequestCounts (PDK-570) measures the Authentik requests of the rounds admin-accounts and
// identity-reconcile against the fake at 10 and 200 organizations in steady state (every group exists with the
// members it should have): before, three role group listings per organization and a lookup of the organization's root
// group, a lookup of the device's group and a member listing per device; after, one role group listing and one device
// group listing per organization. EnsureOrganization, unchanged, is part of both reconcile counts.
func TestIdentityRoundRequestCounts(t *testing.T) {
	const devices = 5
	for _, orgs := range []int{10, 200} {
		t.Run(strconv.Itoa(orgs), func(t *testing.T) {
			f, srv := newFake(t)
			c := client(srv)
			ctx := context.Background()
			type org struct {
				slug    string
				roles   []string
				devices map[uuid.UUID][]string
			}
			var all []org
			next := 10000
			for i := range orgs {
				o := org{slug: fmt.Sprintf("org-%03d", i), devices: map[uuid.UUID][]string{}}
				if _, err := c.EnsureOrganization(ctx, o.slug); err != nil {
					t.Fatal(err)
				}
				for _, role := range []organization.GroupRole{organization.GroupAdmins, organization.GroupOperators, organization.GroupAuditors} {
					name := organization.RoleGroup(o.slug, role)
					o.roles = append(o.roles, name)
					for range 2 {
						next++
						f.users[next] = &fakeUser{pk: next, username: "u" + strconv.Itoa(next), groups: []string{f.groupByName(name).pk}}
					}
				}
				for range devices {
					d := uuid.New()
					next++
					f.addGroup(organization.DeviceLoginGroup(o.slug, d), next)
					o.devices[d] = []string{strconv.Itoa(next)}
				}
				all = append(all, o)
			}
			measure := func(round func(o org) error) int {
				f.requests = nil
				for _, o := range all {
					if err := round(o); err != nil {
						t.Fatal(err)
					}
				}
				return len(f.requests)
			}
			adminBefore := measure(func(o org) error {
				for _, name := range o.roles {
					if _, err := roleGroupUsers(ctx, c, name); err != nil {
						return err
					}
				}
				return nil
			})
			adminAfter := measure(func(o org) error {
				_, err := c.RoleGroupsMembers(ctx, o.roles)
				return err
			})
			reconcileBefore := measure(func(o org) error {
				if _, err := c.EnsureOrganization(ctx, o.slug); err != nil {
					return err
				}
				for d, members := range o.devices {
					if err := app.SyncDeviceLoginGroup(ctx, c, o.slug, d, members); err != nil {
						return err
					}
				}
				return nil
			})
			reconcileAfter := measure(func(o org) error {
				if _, err := c.EnsureOrganization(ctx, o.slug); err != nil {
					return err
				}
				listed, err := c.DeviceLoginGroups(ctx, o.slug)
				if err != nil {
					return err
				}
				// Steady state: every listed group already has its members, so the round writes nothing.
				for d, members := range o.devices {
					if g := listed[organization.DeviceLoginGroup(o.slug, d)]; !slices.Equal(g.Members, members) {
						return fmt.Errorf("device %s: members %v, want %v", d, g.Members, members)
					}
				}
				return nil
			})
			ensure := measure(func(o org) error {
				_, err := c.EnsureOrganization(ctx, o.slug)
				return err
			})
			t.Logf("%d organizations, %d devices each: admin-accounts %d → %d requests, identity-reconcile %d → %d requests "+
				"(of which EnsureOrganization %d)", orgs, devices, adminBefore, adminAfter, reconcileBefore, reconcileAfter, ensure)
			if adminBefore != 3*orgs || adminAfter != orgs {
				t.Errorf("admin-accounts %d → %d requests, want %d → %d", adminBefore, adminAfter, 3*orgs, orgs)
			}
			if reconcileBefore != ensure+3*devices*orgs || reconcileAfter != ensure+orgs {
				t.Errorf("identity-reconcile %d → %d requests, want %d → %d", reconcileBefore, reconcileAfter,
					ensure+3*devices*orgs, ensure+orgs)
			}
		})
	}
}
