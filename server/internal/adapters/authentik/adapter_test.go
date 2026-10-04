package authentik_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/paddock-mdm/paddock/server/internal/adapters/authentik"
	"github.com/paddock-mdm/paddock/server/internal/domain/organization"
	"github.com/paddock-mdm/paddock/server/internal/ports"
	"github.com/paddock-mdm/paddock/server/internal/problem"
)

func client(srv *httptest.Server) *authentik.Client {
	return authentik.New(srv.URL, "test-token").WithBackoff(time.Millisecond)
}

func (f *fakeAuthentik) count(prefix string) int {
	n := 0
	for _, r := range f.requests {
		if strings.HasPrefix(r, prefix) {
			n++
		}
	}
	return n
}

func TestEnsureOrganizationIsIdempotent(t *testing.T) {
	f, srv := newFake(t)
	c := client(srv)
	first, err := c.EnsureOrganization(context.Background(), "acme")
	if err != nil {
		t.Fatal(err)
	}
	root := f.groupByName(organization.RootGroup("acme"))
	for _, name := range []string{
		organization.RoleGroup("acme", organization.GroupAdmins), organization.RoleGroup("acme", organization.GroupOperators),
		organization.RoleGroup("acme", organization.GroupAuditors), organization.LockedGroup("acme"),
	} {
		g := f.groupByName(name)
		if g == nil || !slices.Equal(g.parents, []string{root.pk}) {
			t.Errorf("group %s missing or not a child of the root group: %+v", name, g)
		}
	}
	if len(f.objects["providers"]) != 1 || len(f.objects["applications"]) != 1 || len(f.objects["policies"]) != 1 ||
		len(f.objects["bindings"]) != 1 || len(f.objects["scopemappings"]) != 5 {
		t.Fatalf("device login objects: %v", f.objects)
	}
	posts := f.count("POST")
	second, err := c.EnsureOrganization(context.Background(), "acme")
	if err != nil {
		t.Fatal(err)
	}
	if f.count("POST") != posts {
		t.Fatalf("second call created objects: %v", f.requests)
	}
	if first != second || first.LockedGroupPK != f.groupByName(organization.LockedGroup("acme")).pk {
		t.Fatalf("refs differ: %+v vs %+v", first, second)
	}
}

func TestDeviceLoginSettings(t *testing.T) {
	f, srv := newFake(t)
	if _, err := client(srv).EnsureOrganization(context.Background(), "acme"); err != nil {
		t.Fatal(err)
	}
	var provider map[string]any
	for _, p := range f.objects["providers"] {
		provider = p
	}
	authFlow, authzFlow := "", ""
	for _, fl := range f.objects["flows"] {
		switch fl["slug"] {
		case "paddock-device-authentication":
			authFlow = fl["pk"].(string)
		case "paddock-device-authorization":
			authzFlow = fl["pk"].(string)
		}
	}
	grants := provider["grant_types"].([]any)
	if provider["name"] != "paddock-device-acme" || provider["client_id"] != "paddock-device-acme" || provider["client_type"] != "public" ||
		provider["authentication_flow"] != authFlow || provider["authorization_flow"] != authzFlow || provider["issuer_mode"] != "per_provider" ||
		provider["sub_mode"] != "hashed_user_id" || provider["access_token_validity"] != "minutes=10" ||
		provider["refresh_token_validity"] != "days=30" || len(grants) != 3 || len(provider["property_mappings"].([]any)) != 4 {
		t.Fatalf("provider %v", provider)
	}
	if uris := provider["redirect_uris"].([]any); uris[0].(map[string]any)["url"] != authentik.DeviceRedirectURI {
		t.Fatalf("redirect uris %v", uris)
	}
	app := f.objects["applications"]["paddock-device-acme"]
	if app["policy_engine_mode"] != "all" || app["provider"] != float64(intOf(provider["pk"])) {
		t.Fatalf("application %v", app)
	}
	for _, p := range f.objects["policies"] {
		if p["expression"] != authentik.AccessExpression("acme") {
			t.Fatalf("policy %v", p)
		}
	}
}

func TestEnsureOrganizationCorrectsDrift(t *testing.T) {
	f, srv := newFake(t)
	c := client(srv)
	if _, err := c.EnsureOrganization(context.Background(), "acme"); err != nil {
		t.Fatal(err)
	}
	for _, m := range f.objects["scopemappings"] {
		if m["name"] == authentik.GroupsMappingName("acme") {
			m["expression"] = `return {"groups": [g.name for g in request.user.all_groups()]}` // every group: a leak
		}
	}
	if _, err := c.EnsureOrganization(context.Background(), "acme"); err != nil {
		t.Fatal(err)
	}
	for _, m := range f.objects["scopemappings"] {
		if m["name"] == authentik.GroupsMappingName("acme") && m["expression"] != authentik.GroupsExpression("acme") {
			t.Fatalf("mapping not corrected: %v", m["expression"])
		}
	}
}

func TestGroupsExpressionOnlyEmitsTheOrganization(t *testing.T) {
	e := authentik.GroupsExpression("acme")
	for _, want := range []string{`root = "paddock.acme"`, `n.startswith(root + ".")`, `[root] if root in names`, `"preferred_username"`} {
		if !strings.Contains(e, want) {
			t.Errorf("expression lacks %q:\n%s", want, e)
		}
	}
	if a := authentik.AccessExpression("acme"); !strings.Contains(a, `"paddock.acme" in names and "paddock.acme.locked" not in names`) {
		t.Errorf("access expression:\n%s", a)
	}
}

func TestEnsureOrganizationNeedsTheDeviceBlueprint(t *testing.T) {
	f, srv := newFake(t)
	for pk, fl := range f.objects["flows"] {
		if fl["slug"] == "paddock-device-authentication" {
			delete(f.objects["flows"], pk)
		}
	}
	_, err := client(srv).EnsureOrganization(context.Background(), "acme")
	if !errors.Is(err, problem.UpstreamUnavailable) || !strings.Contains(err.Error(), "paddock-device.yaml") {
		t.Fatalf("error %v", err)
	}
}

func TestUsers(t *testing.T) {
	f, srv := newFake(t)
	c := client(srv)
	ctx := context.Background()
	if _, err := c.EnsureOrganization(ctx, "acme"); err != nil {
		t.Fatal(err)
	}
	pk, err := c.CreateUser(ctx, "acme", ports.NewIdentityUser{Username: "dave@acme.test", Name: "Dave", Email: "dave@acme.test"})
	if err != nil {
		t.Fatal(err)
	}
	u := f.users[mustAtoi(t, pk)]
	if u.attributes["paddock_managed"] != true || u.attributes["paddock_org"] != "acme" ||
		!slices.Equal(u.groups, []string{f.groupByName("paddock.acme").pk}) {
		t.Fatalf("created user %+v", u)
	}
	if _, err := c.CreateUser(ctx, "acme", ports.NewIdentityUser{Username: "dave@acme.test"}); !errors.Is(err, ports.ErrUsernameTaken) {
		t.Fatalf("duplicate: %v", err)
	}
	link, err := c.RecoveryLink(ctx, pk)
	if err != nil || !strings.Contains(link, "paddock-recovery") || !strings.HasSuffix(link, "d=hours=24") {
		t.Fatalf("recovery link %q %v", link, err)
	}
	if err := c.UpdateUser(ctx, pk, "Dave D.", "d@acme.test"); err != nil || u.name != "Dave D." || u.email != "d@acme.test" {
		t.Fatalf("update: %v %+v", err, u)
	}

	// A synced user (no paddock_managed) and a member of another organization.
	synced := &fakeUser{pk: 900, username: "erin@acme.test", groups: []string{f.groupByName("paddock.acme").pk}}
	other := &fakeUser{pk: 901, username: "frank@globex.test", groups: []string{"elsewhere"}}
	f.users[synced.pk], f.users[other.pk] = synced, other
	users, err := c.OrganizationUsers(ctx, "acme")
	if err != nil || len(users) != 2 || !users[0].Managed || users[1].Managed || users[1].Username != "erin@acme.test" {
		t.Fatalf("organization users %+v %v", users, err)
	}

	if err := c.DeleteUser(ctx, pk); err != nil {
		t.Fatal(err)
	}
	if err := c.DeleteUser(ctx, pk); err != nil {
		t.Fatalf("deleting a missing user: %v", err)
	}
}

func TestOrganizationUsersPaginates(t *testing.T) {
	f, srv := newFake(t)
	c := client(srv)
	if _, err := c.EnsureOrganization(context.Background(), "acme"); err != nil {
		t.Fatal(err)
	}
	root := f.groupByName("paddock.acme").pk
	for i := range 1203 {
		f.users[1000+i] = &fakeUser{pk: 1000 + i, username: "u" + strconv.Itoa(i), groups: []string{root}}
	}
	users, err := c.OrganizationUsers(context.Background(), "acme")
	if err != nil || len(users) != 1203 {
		t.Fatalf("%d users, %v", len(users), err)
	}
}

// TestLockRevokesTokensAndSessions: a lock is the group membership AND the revocation (PoC M1 C2).
func TestLockRevokesTokensAndSessions(t *testing.T) {
	f, srv := newFake(t)
	c := client(srv)
	ctx := context.Background()
	if _, err := c.EnsureOrganization(ctx, "acme"); err != nil {
		t.Fatal(err)
	}
	pk, err := c.CreateUser(ctx, "acme", ports.NewIdentityUser{Username: "bob@acme.test", Name: "Bob"})
	if err != nil {
		t.Fatal(err)
	}
	n := mustAtoi(t, pk)
	f.tokens["refresh_tokens"] = []int{n, 77, n}
	f.tokens["access_tokens"] = []int{n}
	f.sessions[n], f.sessions[77] = 2, 1
	if err := c.LockUser(ctx, "acme", pk); err != nil {
		t.Fatal(err)
	}
	locked := f.groupByName("paddock.acme.locked").pk
	if !slices.Contains(f.users[n].groups, locked) {
		t.Fatal("user not in the locked group")
	}
	if !slices.Equal(f.tokens["refresh_tokens"], []int{0, 77, 0}) || !slices.Equal(f.tokens["access_tokens"], []int{0}) {
		t.Fatalf("tokens after the lock: %v", f.tokens)
	}
	if f.sessions[n] != 0 || f.sessions[77] != 1 {
		t.Fatalf("sessions after the lock: %v", f.sessions)
	}
	if f.deactivations != 1 || f.users[n].inactive {
		t.Fatalf("the user must be deactivated once and active again (%d, inactive %v)", f.deactivations, f.users[n].inactive)
	}
	if err := c.UnlockUser(ctx, "acme", pk); err != nil {
		t.Fatal(err)
	}
	if slices.Contains(f.users[n].groups, locked) {
		t.Fatal("user still locked")
	}
}

func TestGroupsAndMembers(t *testing.T) {
	f, srv := newFake(t)
	c := client(srv)
	ctx := context.Background()
	pk, err := c.EnsureGroup(ctx, "acme", "paddock.acme.g.ops")
	if err != nil {
		t.Fatal(err)
	}
	if again, _ := c.EnsureGroup(ctx, "acme", "paddock.acme.g.ops"); again != pk {
		t.Fatal("EnsureGroup is not idempotent")
	}
	if g := f.groups[pk]; !slices.Equal(g.parents, []string{f.groupByName("paddock.acme").pk}) {
		t.Fatalf("parents %v", g.parents)
	}
	f.users[5] = &fakeUser{pk: 5, username: "dave@acme.test"}
	if err := c.AddMember(ctx, pk, "5"); err != nil {
		t.Fatal(err)
	}
	if members, err := c.GroupMembers(ctx, pk); err != nil || !slices.Equal(members, []string{"5"}) {
		t.Fatalf("members %v %v", members, err)
	}
	if err := c.RemoveMember(ctx, pk, "5"); err != nil {
		t.Fatal(err)
	}
	if members, _ := c.GroupMembers(ctx, pk); len(members) != 0 {
		t.Fatalf("members %v", members)
	}
	f.groups["up-1"] = &fakeGroup{pk: "up-1", name: "Engineering: Linux"}
	upstream, err := c.UpstreamGroups(ctx)
	if err != nil || len(upstream) != 1 || upstream[0].Name != "Engineering: Linux" {
		t.Fatalf("upstream groups %+v %v", upstream, err)
	}
	if err := c.DeleteGroup(ctx, pk); err != nil {
		t.Fatal(err)
	}
	if err := c.DeleteGroup(ctx, pk); err != nil {
		t.Fatalf("deleting a missing group: %v", err)
	}
	if found, err := c.FindGroup(ctx, "paddock.acme.g.ops"); err != nil || found != "" {
		t.Fatalf("FindGroup after delete: %q %v", found, err)
	}
}

func TestRetryOn5xx(t *testing.T) {
	f, srv := newFake(t)
	f.failNext, f.failStatus = 2, http.StatusBadGateway
	if _, err := client(srv).EnsureOrganization(context.Background(), "globex"); err != nil {
		t.Fatalf("EnsureOrganization after two 502s: %v", err)
	}
	if len(f.groups) != 5 {
		t.Fatalf("%d groups, want 5", len(f.groups))
	}
}

func TestGiveUpAfterThreeRetries(t *testing.T) {
	f, srv := newFake(t)
	f.failNext, f.failStatus = 100, http.StatusServiceUnavailable
	_, err := client(srv).EnsureOrganization(context.Background(), "globex")
	if !errors.Is(err, problem.UpstreamUnavailable) {
		t.Fatalf("error = %v, want upstream_unavailable", err)
	}
	if used := 100 - f.failNext; used != 4 {
		t.Fatalf("%d attempts, want 1 + 3 retries", used)
	}
}

func TestNoRetryOn4xx(t *testing.T) {
	f, srv := newFake(t)
	f.failNext, f.failStatus = 1, http.StatusForbidden
	_, err := client(srv).EnsureOrganization(context.Background(), "initech")
	if !errors.Is(err, problem.UpstreamUnavailable) || !strings.Contains(err.Error(), "403") {
		t.Fatalf("error = %v, want upstream_unavailable wrapping HTTP 403", err)
	}
	if len(f.requests) != 0 || f.failNext != 0 {
		t.Fatalf("a 4xx was retried (%d further requests)", len(f.requests))
	}
}

func TestNetworkErrorIsRetriedThenUpstream(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	srv.Close() // connection refused
	_, err := authentik.New(srv.URL, "test-token").WithBackoff(time.Millisecond).EnsureOrganization(context.Background(), "acme")
	if !errors.Is(err, problem.UpstreamUnavailable) {
		t.Fatalf("error = %v, want upstream_unavailable", err)
	}
}

func mustAtoi(t *testing.T, s string) int {
	t.Helper()
	n, err := strconv.Atoi(s)
	if err != nil {
		t.Fatal(err)
	}
	return n
}
