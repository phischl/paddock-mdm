package authentik_test

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/adapters/authentik"
	"github.com/phischl/paddock-mdm/server/internal/domain/organization"
	"github.com/phischl/paddock-mdm/server/internal/ports"
	"github.com/phischl/paddock-mdm/server/internal/problem"
	"github.com/phischl/paddock-mdm/server/internal/worker"
)

func providerPK(f *fakeAuthentik) string {
	for pk := range f.objects["providers"] {
		return pk
	}
	return ""
}

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

// Authentik committed a create but its answer was lost (a client timeout under load): the retried POST meets the
// unique constraint, and the step finds the object instead of failing or duplicating it (PDK-351).
func TestEnsureOrganizationSurvivesLostCreateAnswers(t *testing.T) {
	f, srv := newFake(t)
	f.loseCreateAnswers = true
	c := client(srv).WithHTTPClient(&http.Client{Timeout: 500 * time.Millisecond})
	refs, err := c.EnsureOrganization(context.Background(), "acme")
	if err != nil {
		t.Fatal(err)
	}
	if len(f.lostCreates) != 6 {
		t.Fatalf("lost answers on %v, want every created collection", f.lostCreates)
	}
	if len(f.groups) != 5 || refs.LockedGroupPK != f.groupByName(organization.LockedGroup("acme")).pk {
		t.Fatalf("groups %d, refs %+v", len(f.groups), refs)
	}
	if len(f.objects["providers"]) != 1 || len(f.objects["applications"]) != 1 || len(f.objects["policies"]) != 1 ||
		len(f.objects["bindings"]) != 1 || len(f.objects["scopemappings"]) != 5 {
		t.Fatalf("device login objects: %v", f.objects)
	}
}

// Under load every Authentik answer is slow. The independent steps run concurrently, so a create takes about ten
// round trips instead of one per request (PDK-351).
func TestEnsureOrganizationOnSlowAuthentik(t *testing.T) {
	f, srv := newFake(t)
	const latency = 200 * time.Millisecond
	f.latency.Store(int64(latency))
	for _, run := range []string{"create", "correct"} {
		f.mu.Lock()
		f.requests = nil
		f.mu.Unlock()
		start := time.Now()
		if _, err := client(srv).EnsureOrganization(context.Background(), "acme"); err != nil {
			t.Fatal(err)
		}
		took := time.Since(start)
		f.mu.Lock()
		n := len(f.requests)
		f.mu.Unlock()
		if n < 20 || took > 14*latency {
			t.Fatalf("%s: %d requests took %s at %s each, want at most %s", run, n, took, latency, 14*latency)
		}
	}
}

// A client with a bound never has more requests in flight than the bound, although EnsureOrganization fans out.
func TestMaxConcurrentBoundsRequestsInFlight(t *testing.T) {
	f, srv := newFake(t)
	f.latency.Store(int64(20 * time.Millisecond))
	if _, err := client(srv).EnsureOrganization(context.Background(), "acme"); err != nil {
		t.Fatal(err)
	}
	if p := f.peak.Load(); p <= 2 {
		t.Fatalf("unbounded client: peak %d requests in flight, want the fan-out above 2", p)
	}
	f.peak.Store(0)
	if _, err := client(srv).WithMaxConcurrent(2).EnsureOrganization(context.Background(), "globex"); err != nil {
		t.Fatal(err)
	}
	if p := f.peak.Load(); p != 2 {
		t.Fatalf("bounded client: peak %d requests in flight, want 2", p)
	}
}

// A waiting request gives up with its context instead of waiting for a slot forever.
func TestMaxConcurrentWaitEndsWithContext(t *testing.T) {
	f, srv := newFake(t)
	f.latency.Store(int64(time.Second))
	c := client(srv).WithMaxConcurrent(1)
	go func() { _, _ = c.FindGroup(context.Background(), "paddock.acme") }()
	for f.inFlight.Load() == 0 {
		time.Sleep(time.Millisecond)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := c.FindGroup(ctx, "paddock.globex"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want deadline exceeded", err)
	}
	if n := f.inFlight.Load(); n != 1 {
		t.Fatalf("%d requests reached Authentik, want only the first", n)
	}
}

// The worker's reconcile round runs while an administrator creates an organization (PDK-392: in CI the round ten
// minutes after start coincided with the e2e create, and the create waited 2–6 s per request behind the round's
// fan-out). Authentik serves requests in arrival order, a few at once. With the worker bounded, the round never has
// more than one request at Authentik during the create, so each request of the create waits behind at most one of
// the round's (unbounded: about a dozen).
func TestCreateDuringReconcileRound(t *testing.T) {
	f, apiSrv := newFake(t)
	for _, slug := range []string{"acme", "globex", "initech"} {
		if _, err := client(apiSrv).EnsureOrganization(context.Background(), slug); err != nil {
			t.Fatal(err)
		}
	}
	// The round's client talks to its own listener of the same fake, so its requests can be told apart.
	roundSrv := httptest.NewServer(f)
	t.Cleanup(roundSrv.Close)
	f.latency.Store(int64(20 * time.Millisecond))
	f.slots = make(chan struct{}, 2)
	ctx, stop := context.WithCancel(context.Background())
	round := make(chan struct{})
	background := client(roundSrv).WithMaxConcurrent(worker.ReconcileAuthentikConcurrency)
	go func() {
		defer close(round)
		for ctx.Err() == nil {
			for _, slug := range []string{"acme", "globex", "initech"} {
				_, _ = background.EnsureOrganization(ctx, slug)
			}
		}
	}()
	for f.inFlight.Load() == 0 {
		time.Sleep(time.Millisecond)
	}
	f.resetPeaks()
	_, err := client(apiSrv).EnsureOrganization(context.Background(), "e2e")
	roundPeak := f.hostPeakOf(roundSrv)
	stop()
	<-round
	if err != nil {
		t.Fatal(err)
	}
	if roundPeak == 0 {
		t.Fatal("the round sent no request during the create")
	}
	if roundPeak > worker.ReconcileAuthentikConcurrency {
		t.Fatalf("the round had %d requests at Authentik during the create, want at most %d", roundPeak,
			worker.ReconcileAuthentikConcurrency)
	}
}

// The platform-wide objects are looked up once per client, not by every create (PDK-392: the flow lookups were the
// most expensive requests of a loaded Authentik).
func TestPlatformObjectsAreReused(t *testing.T) {
	f, srv := newFake(t)
	c := client(srv)
	if _, err := c.EnsureOrganization(context.Background(), "acme"); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.requests = nil
	f.mu.Unlock()
	if _, err := c.EnsureOrganization(context.Background(), "globex"); err != nil {
		t.Fatal(err)
	}
	for _, prefix := range []string{"GET /api/v3/flows/", "GET /api/v3/crypto/"} {
		if n := f.count(prefix); n != 0 {
			t.Fatalf("%d requests %s for the second organization, want 0", n, prefix)
		}
	}
}

// The platform-wide pks are looked up again once platformTTL has passed, and after a failed provider write.
func TestPlatformObjectsExpireAndAreForgotten(t *testing.T) {
	f, srv := newFake(t)
	now := time.Now()
	c := client(srv).WithClock(func() time.Time { return now })
	lookups := func(slug string) int {
		t.Helper()
		f.mu.Lock()
		f.requests = nil
		f.mu.Unlock()
		if _, err := c.EnsureOrganization(context.Background(), slug); err != nil {
			t.Fatal(err)
		}
		return f.count("GET /api/v3/flows/")
	}
	if n := lookups("acme"); n != 3 {
		t.Fatalf("first run: %d flow lookups, want 3", n)
	}
	now = now.Add(59 * time.Minute)
	if n := lookups("acme"); n != 0 {
		t.Fatalf("within the TTL: %d flow lookups, want 0", n)
	}
	now = now.Add(2 * time.Minute)
	if n := lookups("acme"); n != 3 {
		t.Fatalf("after the TTL: %d flow lookups, want 3", n)
	}
	f.mu.Lock()
	f.failOnce = map[string]int{"PUT /api/v3/providers/oauth2/" + providerPK(f) + "/": http.StatusForbidden}
	f.mu.Unlock()
	if _, err := c.EnsureOrganization(context.Background(), "acme"); err == nil {
		t.Fatal("provider write failure not reported")
	}
	if n := lookups("acme"); n != 3 {
		t.Fatalf("after a failed provider write: %d flow lookups, want 3", n)
	}
}

// A failure between creating the application and binding its access policy leaves an application without provider,
// which no one can sign in to; the next run binds the policy and only then attaches the provider.
func TestApplicationWithoutBindingHasNoProvider(t *testing.T) {
	f, srv := newFake(t)
	f.failOnce = map[string]int{"POST /api/v3/policies/bindings/": http.StatusBadRequest}
	if _, err := client(srv).EnsureOrganization(context.Background(), "acme"); err == nil {
		t.Fatal("binding failure not reported")
	}
	f.mu.Lock()
	app := f.objects["applications"]["paddock-device-acme"]
	bindings := len(f.objects["bindings"])
	f.mu.Unlock()
	if app == nil || app["provider"] != nil || bindings != 0 {
		t.Fatalf("after the failure: application %v, %d bindings; want an application without provider", app, bindings)
	}
	if _, err := client(srv).EnsureOrganization(context.Background(), "acme"); err != nil {
		t.Fatal(err)
	}
	if app["provider"] == nil || len(f.objects["bindings"]) != 1 || len(f.objects["applications"]) != 1 {
		t.Fatalf("after the retry: application %v, %d bindings", app, len(f.objects["bindings"]))
	}
}

// A platform-wide object recreated with a new pk within the cache's lifetime makes the provider write fail; the
// objects are looked up again and the provider is written with the new pk in the same call.
func TestRecreatedFlowIsLookedUpAgain(t *testing.T) {
	f, srv := newFake(t)
	c := client(srv)
	if _, err := c.EnsureOrganization(context.Background(), "acme"); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	delete(f.objects["flows"], f.flowPK("paddock-device-authorization"))
	f.put("flows", map[string]any{"pk": uuid.NewString(), "slug": "paddock-device-authorization", "name": "paddock-device-authorization"})
	recreated := f.flowPK("paddock-device-authorization")
	f.mu.Unlock()
	for _, slug := range []string{"acme", "globex"} {
		if _, err := c.EnsureOrganization(context.Background(), slug); err != nil {
			t.Fatalf("%s: %v", slug, err)
		}
	}
	for _, p := range f.objects["providers"] {
		if p["authorization_flow"] != recreated {
			t.Fatalf("%s: authorization_flow = %v, want the recreated flow %s", p["name"], p["authorization_flow"], recreated)
		}
	}
}

// Without a signing key the answer is not kept: once the key exists, the next run sets it on the provider.
func TestMissingSigningKeyIsNotCached(t *testing.T) {
	f, srv := newFake(t)
	f.mu.Lock()
	keys := f.objects["certificatekeypairs"]
	f.objects["certificatekeypairs"] = nil
	f.mu.Unlock()
	c := client(srv)
	if _, err := c.EnsureOrganization(context.Background(), "acme"); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.objects["certificatekeypairs"] = keys
	f.mu.Unlock()
	if _, err := c.EnsureOrganization(context.Background(), "acme"); err != nil {
		t.Fatal(err)
	}
	for pk := range keys {
		for _, p := range f.objects["providers"] {
			if p["signing_key"] != pk {
				t.Fatalf("signing_key = %v, want %s", p["signing_key"], pk)
			}
		}
	}
}

// The access policy is bound to the device application before the provider is attached, so the application never
// admits users without it.
func TestAccessPolicyBoundBeforeProviderAttached(t *testing.T) {
	f, srv := newFake(t)
	if _, err := client(srv).EnsureOrganization(context.Background(), "acme"); err != nil {
		t.Fatal(err)
	}
	binding := slices.Index(f.requests, "POST /api/v3/policies/bindings/")
	attach := slices.Index(f.requests, "PATCH /api/v3/core/applications/paddock-device-acme/")
	if binding < 0 || attach < 0 || binding > attach {
		t.Fatalf("binding created at request %d, provider attached at %d: %v", binding, attach, f.requests)
	}
	if f.objects["applications"]["paddock-device-acme"]["provider"] == nil {
		t.Fatal("application without provider")
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
		provider["refresh_token_validity"] != "days=30" || provider["access_code_validity"] != "minutes=10" ||
		provider["refresh_token_threshold"] != "seconds=0" || len(grants) != 3 || len(provider["property_mappings"].([]any)) != 4 {
		t.Fatalf("provider %v", provider)
	}
	if uris := provider["redirect_uris"].([]any); uris[0].(map[string]any)["url"] != authentik.DeviceRedirectURI {
		t.Fatalf("redirect uris %v", uris)
	}
	app := f.objects["applications"]["paddock-device-acme"]
	if app["policy_engine_mode"] != "all" || app["provider"] != float64(intOf(provider["pk"])) {
		t.Fatalf("application %v", app)
	}

	// A refresh-token threshold set by hand breaks every Hello PIN login (RR-40): the next reconciliation resets it.
	provider["refresh_token_threshold"] = "days=1"
	if _, err := client(srv).EnsureOrganization(context.Background(), "acme"); err != nil {
		t.Fatal(err)
	}
	for _, p := range f.objects["providers"] {
		if p["refresh_token_threshold"] != "seconds=0" {
			t.Fatalf("refresh_token_threshold %v after the reconciliation, want seconds=0", p["refresh_token_threshold"])
		}
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

// TestRoleGroupUsers (plan M8s decision 22): the direct members of a role group with their active flag; a group that
// does not exist is ErrGroupNotFound, never an empty listing.
func TestRoleGroupUsers(t *testing.T) {
	f, srv := newFake(t)
	c := client(srv)
	ctx := context.Background()
	if _, err := c.EnsureOrganization(ctx, "acme"); err != nil {
		t.Fatal(err)
	}
	admins := f.groupByName("paddock.acme.admins").pk
	f.users[910] = &fakeUser{pk: 910, username: "alice@acme.test", groups: []string{admins}}
	f.users[911] = &fakeUser{pk: 911, username: "dave@acme.test", groups: []string{admins}, inactive: true}
	f.users[912] = &fakeUser{pk: 912, username: "bob@acme.test", groups: []string{f.groupByName("paddock.acme.auditors").pk}}
	users, err := c.RoleGroupUsers(ctx, "paddock.acme.admins")
	if err != nil || len(users) != 2 || users[0].Username != "alice@acme.test" || !users[0].Active ||
		users[1].Username != "dave@acme.test" || users[1].Active || users[0].UID != "uid-910" {
		t.Fatalf("role group users %+v %v", users, err)
	}
	if users, err := c.RoleGroupUsers(ctx, "paddock.globex.admins"); !errors.Is(err, ports.ErrGroupNotFound) || len(users) != 0 {
		t.Fatalf("missing group: %+v %v", users, err)
	}
	// The direct read of one user requires its UID: a username can be reused.
	u, groups, found, err := c.UserMembership(ctx, "dave@acme.test", "uid-911")
	if err != nil || !found || u.Active || !slices.Equal(groups, []string{"paddock.acme.admins"}) {
		t.Fatalf("membership: %+v %v %v %v", u, groups, found, err)
	}
	if _, _, found, err := c.UserMembership(ctx, "dave@acme.test", "uid-910"); err != nil || found {
		t.Fatalf("membership with another UID: %v %v", found, err)
	}
}

// TestRoleGroupsUsersManyOrganizations (PDK-501): the members of the role groups of 150 organizations come from a
// handful of listings, not one per group, with request targets far below the limit of a request head; the groups of
// organizations not provisioned yet are skipped, and any other error fails the listing.
func TestRoleGroupsUsersManyOrganizations(t *testing.T) {
	f, srv := newFake(t)
	c := client(srv)
	ctx := context.Background()
	group := func(name string) string {
		pk := uuid.NewString()
		f.groups[pk] = &fakeGroup{pk: pk, name: name}
		return pk
	}
	everywhere := &fakeUser{pk: 100, username: "root"}
	f.users[100] = everywhere
	everywhere.groups = append(everywhere.groups, group("paddock.platform.admins"))
	names := []string{"paddock.platform.admins"}
	want := map[string]bool{"100": true}
	for i := range 150 {
		slug := fmt.Sprintf("organization-with-a-long-slug-%03d", i)
		for j, role := range []string{"admins", "operators", "auditors"} {
			name := "paddock." + slug + "." + role
			names = append(names, name)
			if i%50 == 7 {
				continue
			}
			pk := group(name)
			member := 1000 + 3*i + j
			f.users[member] = &fakeUser{pk: member, username: name, groups: []string{pk}}
			want[strconv.Itoa(member)] = true
			if j == 0 {
				everywhere.groups = append(everywhere.groups, pk)
			}
		}
	}
	f.users[99] = &fakeUser{pk: 99, username: "no-role", groups: []string{group("paddock.organization-with-a-long-slug-000")}}
	f.requests = nil
	users, err := c.RoleGroupsUsers(ctx, names)
	if err != nil {
		t.Fatal(err)
	}
	distinct := func(users []ports.IdentityUser) map[string]bool {
		out := map[string]bool{}
		for _, u := range users {
			out[u.PK] = true
		}
		return out
	}
	if got := distinct(users); !maps.Equal(got, want) {
		t.Fatalf("%d distinct members, want %d", len(got), len(want))
	}
	// About 60 names fit one listing; each of the 9 missing groups costs one listing more.
	if n := f.count("GET /api/v3/core/users/"); n > 20 {
		t.Fatalf("%d listings for %d role groups, want a handful", n, len(names))
	}
	if f.longestURI > 8192 {
		t.Fatalf("a request target of %d bytes", f.longestURI)
	}
	// A refusal that does not name the missing group halves the batch until the group is found.
	f.unnamedGroupRefusal, f.requests = true, nil
	if users, err = c.RoleGroupsUsers(ctx, names); err != nil || !maps.Equal(distinct(users), want) {
		t.Fatalf("%d distinct members, %v", len(distinct(users)), err)
	}
	if n := f.count("GET /api/v3/core/users/"); n >= len(names) {
		t.Fatalf("%d listings for %d role groups when the refusal names no group", n, len(names))
	}
	f.unnamedGroupRefusal = false
	f.failOnce = map[string]int{"GET /api/v3/core/users/": http.StatusForbidden}
	if _, err := c.RoleGroupsUsers(ctx, names); err == nil || errors.Is(err, ports.ErrGroupNotFound) {
		t.Fatalf("a refused listing: %v", err)
	}
}

// TestRoleGroupUsersSettles: a member leaving during a numbered listing would shift the next page and hide another
// member; the listing is repeated until the total holds, and fails when it never does.
func TestRoleGroupUsersSettles(t *testing.T) {
	f, srv := newFake(t)
	c := client(srv)
	ctx := context.Background()
	if _, err := c.EnsureOrganization(ctx, "acme"); err != nil {
		t.Fatal(err)
	}
	admins := f.groupByName("paddock.acme.admins").pk
	for i := range 1203 {
		f.users[2000+i] = &fakeUser{pk: 2000 + i, username: "a" + strconv.Itoa(i), groups: []string{admins}}
	}
	removed := false
	f.afterUserPage = func() {
		if !removed {
			removed = true
			delete(f.users, 2001)
		}
	}
	users, err := c.RoleGroupUsers(ctx, "paddock.acme.admins")
	if err != nil || len(users) != 1202 || slices.ContainsFunc(users, func(u ports.IdentityUser) bool { return u.Username == "a1" }) {
		t.Fatalf("%d users, %v", len(users), err)
	}
	next := 5000
	f.afterUserPage = func() {
		next++
		f.users[next] = &fakeUser{pk: next, username: "n" + strconv.Itoa(next), groups: []string{admins}}
	}
	if _, err := c.RoleGroupUsers(ctx, "paddock.acme.admins"); !errors.Is(err, problem.UpstreamUnavailable) {
		t.Fatalf("a listing that never settles: %v", err)
	}
}

// TestSuperusers (plan M8b decision 33): the users with superuser rights only, in the settled paged listing of the
// role groups.
func TestSuperusers(t *testing.T) {
	f, srv := newFake(t)
	c := client(srv)
	ctx := context.Background()
	for i := range 1203 {
		f.users[3000+i] = &fakeUser{pk: 3000 + i, username: "s" + strconv.Itoa(i), superuser: i%2 == 0}
	}
	f.users[9000] = &fakeUser{pk: 9000, username: "plain"}
	users, err := c.Superusers(ctx)
	if err != nil || len(users) != 602 || users[0].Username != "s0" || users[0].PK != "3000" || users[0].UID != "uid-3000" ||
		slices.ContainsFunc(users, func(u ports.IdentityUser) bool { return u.Username == "plain" || u.Username == "s1" }) {
		t.Fatalf("%d superusers, %v", len(users), err)
	}
	next := 5000
	f.afterUserPage = func() {
		next++
		f.users[next] = &fakeUser{pk: next, username: "n" + strconv.Itoa(next), superuser: true}
	}
	if _, err := c.Superusers(ctx); !errors.Is(err, problem.UpstreamUnavailable) {
		t.Fatalf("a listing that never settles: %v", err)
	}
	f.afterUserPage = nil
	f.failNext, f.failStatus = 10, http.StatusServiceUnavailable
	if _, err := c.Superusers(ctx); !errors.Is(err, problem.UpstreamUnavailable) {
		t.Fatalf("Authentik down: %v", err)
	}
}

// TestDirectoryProbe (PDK-424): a role group is readable when the token reads it by name; users are visible when a
// listing returns an internal or external user, never only service accounts; a blind token, whose role group listings
// come back empty without an error, fails both; a failed read is an error, never a verdict.
func TestDirectoryProbe(t *testing.T) {
	f, srv := newFake(t)
	c := client(srv)
	ctx := context.Background()
	if _, err := c.EnsureOrganization(ctx, "acme"); err != nil {
		t.Fatal(err)
	}
	f.users[700] = &fakeUser{pk: 700, username: "paddock-service", typ: "service_account"}
	if ok, err := c.GroupReadable(ctx, "paddock.acme.admins"); err != nil || !ok {
		t.Fatalf("readable group: %v %v", ok, err)
	}
	if ok, err := c.GroupReadable(ctx, "paddock.globex.admins"); err != nil || ok {
		t.Fatalf("missing group: %v %v", ok, err)
	}
	if ok, err := c.UsersVisible(ctx); err != nil || ok {
		t.Fatalf("only the service account: %v %v", ok, err)
	}
	f.users[701] = &fakeUser{pk: 701, username: "carol@acme.test", typ: "external"}
	if ok, err := c.UsersVisible(ctx); err != nil || !ok {
		t.Fatalf("an external user: %v %v", ok, err)
	}
	f.blind = true
	if users, err := c.RoleGroupUsers(ctx, "paddock.acme.admins"); err != nil || len(users) != 0 {
		t.Fatalf("blind listing: %+v %v, want empty without an error", users, err)
	}
	if ok, err := c.GroupReadable(ctx, "paddock.acme.admins"); err != nil || ok {
		t.Fatalf("blind group read: %v %v", ok, err)
	}
	if ok, err := c.UsersVisible(ctx); err != nil || ok {
		t.Fatalf("blind user listing: %v %v", ok, err)
	}
	f.blind = false
	f.failNext, f.failStatus = 10, http.StatusServiceUnavailable
	if _, err := c.UsersVisible(ctx); !errors.Is(err, problem.UpstreamUnavailable) {
		t.Fatalf("Authentik down, users: %v", err)
	}
	f.failNext = 10
	if _, err := c.GroupReadable(ctx, "paddock.acme.admins"); !errors.Is(err, problem.UpstreamUnavailable) {
		t.Fatalf("Authentik down, group: %v", err)
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
	if active, err := c.UserActive(ctx, pk); err != nil || !active {
		t.Fatalf("UserActive: %v, %v", active, err)
	}
	if err := c.LockUser(ctx, "acme", pk, true); err != nil {
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
	if err := c.UnlockUser(ctx, "acme", pk, false); err != nil {
		t.Fatal(err)
	}
	if slices.Contains(f.users[n].groups, locked) || f.users[n].inactive {
		t.Fatalf("after the unlock: groups %v, inactive %v", f.users[n].groups, f.users[n].inactive)
	}
}

// A lock of a user deactivated elsewhere revokes but does not reactivate; an unlock without activation keeps the user
// inactive, one with activation (completing an interrupted lock) activates it (plan M4b.1 decision 1).
func TestLockKeepsInactiveUserInactive(t *testing.T) {
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
	f.users[n].inactive = true
	if active, err := c.UserActive(ctx, pk); err != nil || active {
		t.Fatalf("UserActive of a deactivated user: %v, %v", active, err)
	}
	if err := c.LockUser(ctx, "acme", pk, false); err != nil {
		t.Fatal(err)
	}
	locked := f.groupByName("paddock.acme.locked").pk
	if !slices.Contains(f.users[n].groups, locked) || !f.users[n].inactive {
		t.Fatalf("after the lock: groups %v, inactive %v", f.users[n].groups, f.users[n].inactive)
	}
	if err := c.UnlockUser(ctx, "acme", pk, false); err != nil {
		t.Fatal(err)
	}
	if slices.Contains(f.users[n].groups, locked) || !f.users[n].inactive {
		t.Fatalf("after the unlock: groups %v, inactive %v", f.users[n].groups, f.users[n].inactive)
	}
	if err := c.UnlockUser(ctx, "acme", pk, true); err != nil || f.users[n].inactive {
		t.Fatalf("unlock with activation: %v, inactive %v", err, f.users[n].inactive)
	}
}

// A lock interrupted after the deactivation fails; the membership in .locked is in place (online logins stay blocked)
// and locking again completes it (ADR 0007 amendment).
func TestLockInterruptedAfterDeactivation(t *testing.T) {
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
	f.tokens["refresh_tokens"] = []int{n}
	f.failReactivation = true
	if err := c.LockUser(ctx, "acme", pk, true); err == nil {
		t.Fatal("a lock interrupted after the deactivation succeeded")
	}
	locked := f.groupByName("paddock.acme.locked").pk
	if !slices.Contains(f.users[n].groups, locked) || f.deactivations != 1 || !slices.Equal(f.tokens["refresh_tokens"], []int{0}) {
		t.Fatalf("interrupted lock: groups %v, deactivations %d, tokens %v", f.users[n].groups, f.deactivations, f.tokens)
	}
	f.failReactivation = false
	if err := c.LockUser(ctx, "acme", pk, true); err != nil {
		t.Fatalf("retry: %v", err)
	}
	if !slices.Contains(f.users[n].groups, locked) || f.users[n].inactive || f.deactivations != 2 {
		t.Fatalf("after the retry: groups %v, inactive %v, deactivations %d", f.users[n].groups, f.users[n].inactive, f.deactivations)
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
	// Only upstream groups with a member of paddock.acme are acme's (plan M3b decision 1).
	f.groups["up-1"] = &fakeGroup{pk: "up-1", name: "Engineering: Linux"}
	f.groups["up-2"] = &fakeGroup{pk: "up-2", name: "Globex only"}
	f.groups["up-3"] = &fakeGroup{pk: "up-3", name: "Empty"}
	root := f.groupByName("paddock.acme").pk
	f.users[5].groups = []string{root, pk, "up-1"}
	f.users[6] = &fakeUser{pk: 6, username: "frank@globex.test", groups: []string{"up-1", "up-2"}}
	upstream, err := c.UpstreamGroups(ctx, "acme")
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

// TestEndUserSessions (plan M8f decision 17): one bulk delete per call with every user pk, the deleted count decoded;
// a refusal is upstream_unavailable, a pk that is not an integer is refused before any request.
func TestEndUserSessions(t *testing.T) {
	var requests []string
	status := http.StatusOK
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.Method+" "+r.URL.Path+"?"+r.URL.RawQuery)
		if r.Header.Get("Authorization") != "Bearer test-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(status)
		if status == http.StatusOK {
			_, _ = w.Write([]byte(`{"deleted": 3}`))
		}
	}))
	t.Cleanup(srv.Close)
	ctx := context.Background()
	n, err := client(srv).EndUserSessions(ctx, []string{"7", "12"})
	if err != nil || n != 3 {
		t.Fatalf("EndUserSessions: %d %v", n, err)
	}
	if want := "DELETE /api/v3/core/authenticated_sessions/bulk_delete/?user_pks=7&user_pks=12"; len(requests) != 1 || requests[0] != want {
		t.Fatalf("requests %v, want %q", requests, want)
	}
	if n, err := client(srv).EndUserSessions(ctx, nil); err != nil || n != 0 || len(requests) != 1 {
		t.Fatalf("no users: %d %v after %d requests", n, err, len(requests))
	}
	if _, err := client(srv).EndUserSessions(ctx, []string{"7", "x&user_pks=1"}); err == nil || len(requests) != 1 {
		t.Fatalf("a pk that is not an integer: %v after %d requests", err, len(requests))
	}
	status = http.StatusForbidden
	if _, err := client(srv).EndUserSessions(ctx, []string{"7"}); !errors.Is(err, problem.UpstreamUnavailable) || !strings.Contains(err.Error(), "403") {
		t.Fatalf("403: %v", err)
	}
}

// TestCountUserSessions (PDK-342): the sessions of the users are counted over every page of the session listing; a
// pk that is not an integer is refused before any request, a failing listing is upstream_unavailable.
func TestCountUserSessions(t *testing.T) {
	var requests []string
	status := http.StatusOK
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.Method+" "+r.URL.Path+"?"+r.URL.RawQuery)
		w.WriteHeader(status)
		switch {
		case status != http.StatusOK:
		case r.URL.Query().Get("page") == "1":
			_, _ = w.Write([]byte(`{"pagination": {"next": 2}, "results": [{"user": 7}, {"user": 8}, {"user": 12}]}`))
		default:
			_, _ = w.Write([]byte(`{"pagination": {"next": 0}, "results": [{"user": 12}]}`))
		}
	}))
	t.Cleanup(srv.Close)
	ctx := context.Background()
	n, err := client(srv).CountUserSessions(ctx, []string{"7", "12"})
	if err != nil || n != 3 {
		t.Fatalf("CountUserSessions: %d %v, want 3", n, err)
	}
	want := []string{
		"GET /api/v3/core/authenticated_sessions/?page=1&page_size=500",
		"GET /api/v3/core/authenticated_sessions/?page=2&page_size=500",
	}
	if !slices.Equal(requests, want) {
		t.Fatalf("requests %v, want %v", requests, want)
	}
	requests = nil
	if n, err := client(srv).CountUserSessions(ctx, nil); err != nil || n != 0 || len(requests) != 0 {
		t.Fatalf("no users: %d %v after %d requests", n, err, len(requests))
	}
	if _, err := client(srv).CountUserSessions(ctx, []string{"7", "x"}); err == nil || len(requests) != 0 {
		t.Fatalf("a pk that is not an integer: %v after %d requests", err, len(requests))
	}
	status = http.StatusForbidden
	if _, err := client(srv).CountUserSessions(ctx, []string{"7"}); !errors.Is(err, problem.UpstreamUnavailable) {
		t.Fatalf("403: %v", err)
	}
}

// TestEndUserSessionsAfterRetryReportsWhatWasLeft documents the Authentik behaviour behind PDK-342: the first bulk
// delete ends the sessions but its response is lost (a 5xx, like a client timeout), and the retry reports 0 deleted;
// only the count before the delete has the sessions that ended.
func TestEndUserSessionsAfterRetryReportsWhatWasLeft(t *testing.T) {
	sessions := []int{7, 12, 12, 9}
	deletes := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			var b strings.Builder
			for i, u := range sessions {
				if i > 0 {
					b.WriteString(",")
				}
				fmt.Fprintf(&b, `{"user": %d}`, u)
			}
			_, _ = fmt.Fprintf(w, `{"pagination": {"next": 0}, "results": [%s]}`, b.String())
			return
		}
		deletes++
		deleted := 0
		kept := sessions[:0]
		for _, u := range sessions {
			if u == 7 || u == 12 {
				deleted++
				continue
			}
			kept = append(kept, u)
		}
		sessions = kept
		if deletes == 1 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_, _ = fmt.Fprintf(w, `{"deleted": %d}`, deleted)
	}))
	t.Cleanup(srv.Close)
	ctx := context.Background()
	counted, err := client(srv).CountUserSessions(ctx, []string{"7", "12"})
	if err != nil || counted != 3 {
		t.Fatalf("CountUserSessions: %d %v, want 3", counted, err)
	}
	n, err := client(srv).EndUserSessions(ctx, []string{"7", "12"})
	if err != nil || n != 0 || deletes != 2 {
		t.Fatalf("EndUserSessions: %d %v after %d deletes, want 0 after 2", n, err, deletes)
	}
}
