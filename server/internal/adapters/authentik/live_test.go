package authentik_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/adapters/authentik"
	"github.com/phischl/paddock-mdm/server/internal/domain/organization"
	"github.com/phischl/paddock-mdm/server/internal/ports"
)

// TestLiveAuthentik runs the adapter against a real Authentik (the development stack) with the paddock-service token,
// so the service role's permissions are exercised too. It is opt-in:
//
//	PADDOCK_AUTHENTIK_LIVE_URL=https://auth.paddock.localhost:8443 \
//	PADDOCK_AUTHENTIK_LIVE_TOKEN_FILE=deploy/compose/.secrets/authentik_service_token \
//	PADDOCK_AUTHENTIK_LIVE_ADMIN_TOKEN_FILE=deploy/compose/.secrets/authentik_bootstrap_token \
//	SSL_CERT_FILE=deploy/compose/.secrets/caddy-root.crt go test -run TestLiveAuthentik ./internal/adapters/authentik/
//
// With PADDOCK_AUTHENTIK_RECORD=1 it rewrites the response fixtures in testdata/ (see testdata/README.md). Everything it
// creates is deleted at the end with the admin (bootstrap) token.
func TestLiveAuthentik(t *testing.T) {
	base := os.Getenv("PADDOCK_AUTHENTIK_LIVE_URL")
	if base == "" {
		t.Skip("PADDOCK_AUTHENTIK_LIVE_URL is not set (opt-in test against a running Authentik)")
	}
	token := readSecret(t, os.Getenv("PADDOCK_AUTHENTIK_LIVE_TOKEN_FILE"))
	admin := &rawAPI{t: t, base: base, token: readSecret(t, os.Getenv("PADDOCK_AUTHENTIK_LIVE_ADMIN_TOKEN_FILE"))}
	rec := &recorder{next: http.DefaultTransport, record: os.Getenv("PADDOCK_AUTHENTIK_RECORD") == "1"}
	c := authentik.New(base, token).WithHTTPClient(&http.Client{Transport: rec, Timeout: 30 * time.Second})
	ctx := context.Background()
	slug := "fixture-" + uuid.NewString()[:8]
	t.Cleanup(func() { admin.deleteOrganization(slug) })

	refs, err := c.EnsureOrganization(ctx, slug)
	if err != nil {
		t.Fatalf("EnsureOrganization: %v", err)
	}
	again, err := c.EnsureOrganization(ctx, slug)
	if err != nil || again != refs || refs.LockedGroupPK == "" {
		t.Fatalf("second EnsureOrganization: %+v, %v (first %+v)", again, err, refs)
	}
	if err := c.EnsureBrandFlows(ctx); err != nil {
		t.Fatalf("EnsureBrandFlows: %v", err)
	}
	app := organization.DeviceLoginApp(slug)
	prov := admin.first("/providers/oauth2/?name=" + app)
	if prov["client_type"] != "public" || prov["refresh_token_validity"] != "days=30" || prov["access_token_validity"] != "minutes=10" ||
		prov["issuer_mode"] != "per_provider" || prov["sub_mode"] != "hashed_user_id" || len(prov["property_mappings"].([]any)) != 4 {
		t.Errorf("provider %v", prov)
	}
	if got := fmt.Sprint(prov["grant_types"]); !strings.Contains(got, "device_code") || !strings.Contains(got, "refresh_token") {
		t.Errorf("grant types %s", got)
	}
	application := admin.first("/core/applications/?superuser_full_list=true&slug=" + app)
	if application["policy_engine_mode"] != "all" {
		t.Errorf("application %v", application)
	}
	if b := admin.first("/policies/bindings/?target=" + application["pk"].(string)); b["policy_obj"].(map[string]any)["name"] != authentik.AccessPolicyName(slug) {
		t.Errorf("binding %v", b)
	}

	username := "live-" + uuid.NewString()[:8] + "@" + slug + ".test"
	pk, err := c.CreateUser(ctx, slug, ports.NewIdentityUser{Username: username, Name: "Live Test", Email: username})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if _, err := c.CreateUser(ctx, slug, ports.NewIdentityUser{Username: username, Name: "Twice"}); !errors.Is(err, ports.ErrUsernameTaken) {
		t.Fatalf("duplicate CreateUser: %v", err)
	}
	link, err := c.RecoveryLink(ctx, pk)
	if err != nil || !strings.Contains(link, "/if/flow/paddock-recovery/?flow_token=") {
		t.Fatalf("RecoveryLink: %q, %v", link, err)
	}
	// The pinned Authentik keeps the link as the user's token <uid>-password-reset and reuses its key (plan M12h-2
	// amendment f): a second link is the same URL until the token is deleted, and ending it leaves none.
	if again, err := c.RecoveryLink(ctx, pk); err != nil || again != link {
		t.Fatalf("RecoveryLink again: %q, %v, want Authentik's reused link", again, err)
	}
	if n, err := c.RevokeRecoveryLinks(ctx, pk); err != nil || n != 1 {
		t.Fatalf("RevokeRecoveryLinks: %d, %v, want 1", n, err)
	}
	if n, err := c.RevokeRecoveryLinks(ctx, pk); err != nil || n != 0 {
		t.Fatalf("RevokeRecoveryLinks again: %d, %v, want 0", n, err)
	}
	if fresh, err := c.RecoveryLink(ctx, pk); err != nil || fresh == link {
		t.Fatalf("RecoveryLink after revocation: %q, %v, want a new link", fresh, err)
	}
	if connected, err := c.HasSourceConnection(ctx, pk); err != nil || connected {
		t.Fatalf("HasSourceConnection of a user Paddock created: %v, %v, want false", connected, err)
	}
	if u, _, found, err := c.UserByUsername(ctx, username); err != nil || !found || u.PK != pk {
		t.Fatalf("UserByUsername: %+v, %v, %v, want the user %s", u, found, err, pk)
	}
	if err := c.UpdateUser(ctx, pk, "Live Test Renamed", username); err != nil {
		t.Fatalf("UpdateUser: %v", err)
	}
	users, err := c.OrganizationUsers(ctx, slug)
	if err != nil || len(users) != 1 || users[0].PK != pk || !users[0].Managed || users[0].Name != "Live Test Renamed" {
		t.Fatalf("OrganizationUsers: %+v, %v", users, err)
	}
	// Every Authentik has its bootstrap administrator as superuser; the new organization user is none.
	supers, err := c.Superusers(ctx)
	if err != nil || len(supers) == 0 || slices.ContainsFunc(supers, func(u ports.IdentityUser) bool { return u.PK == pk }) {
		t.Fatalf("Superusers: %+v, %v", supers, err)
	}
	// Several role groups in one listing (PDK-501): Authentik ORs the names, and a group it does not know is skipped.
	adminsPK, err := c.FindGroup(ctx, organization.RoleGroup(slug, organization.GroupAdmins))
	if err != nil || adminsPK == "" {
		t.Fatalf("FindGroup admins: %q, %v", adminsPK, err)
	}
	if err := c.AddMember(ctx, adminsPK, pk); err != nil {
		t.Fatal(err)
	}
	roleGroups := []string{organization.RoleGroup(slug, organization.GroupOperators), organization.RoleGroup("missing-"+slug, organization.GroupAdmins),
		organization.RoleGroup(slug, organization.GroupAdmins), organization.RoleGroup(slug, organization.GroupAuditors)}
	if members, err := c.RoleGroupsUsers(ctx, roleGroups); err != nil || len(members) != 1 || members[0].PK != pk {
		t.Fatalf("RoleGroupsUsers: %+v, %v", members, err)
	}
	// The same listing keyed by group, with each user's groups (PDK-570).
	byGroup, err := c.RoleGroupsMembers(ctx, roleGroups)
	if _, missing := byGroup[roleGroups[1]]; err != nil || len(byGroup) != 3 || missing || len(byGroup[roleGroups[0]]) != 0 ||
		len(byGroup[roleGroups[2]]) != 1 || byGroup[roleGroups[2]][0].PK != pk {
		t.Fatalf("RoleGroupsMembers: %+v, %v", byGroup, err)
	}
	// The organization's device login groups with their members in one listing searched by the name prefix (PDK-570).
	deviceGroup := organization.DeviceLoginGroup(slug, uuid.New())
	dpk, err := c.EnsureGroup(ctx, slug, deviceGroup)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.AddMember(ctx, dpk, pk); err != nil {
		t.Fatal(err)
	}
	if listed, err := c.DeviceLoginGroups(ctx, slug); err != nil || len(listed) != 1 || listed[deviceGroup].PK != dpk ||
		!slices.Equal(listed[deviceGroup].Members, []string{pk}) {
		t.Fatalf("DeviceLoginGroups: %+v, %v", listed, err)
	}
	if err := c.DeleteGroup(ctx, dpk); err != nil {
		t.Fatal(err)
	}
	if listed, err := c.DeviceLoginGroups(ctx, slug); err != nil || len(listed) != 0 {
		t.Fatalf("DeviceLoginGroups after the delete: %+v, %v", listed, err)
	}
	if err := c.RemoveMember(ctx, adminsPK, pk); err != nil {
		t.Fatal(err)
	}

	groupName := organization.LocalUserGroup(slug, "live")
	gpk, err := c.EnsureGroup(ctx, slug, groupName)
	if err != nil {
		t.Fatal(err)
	}
	if found, err := c.FindGroup(ctx, groupName); err != nil || found != gpk {
		t.Fatalf("FindGroup: %q, %v", found, err)
	}
	if err := c.AddMember(ctx, gpk, pk); err != nil {
		t.Fatal(err)
	}
	if members, err := c.GroupMembers(ctx, gpk); err != nil || !slices.Equal(members, []string{pk}) {
		t.Fatalf("GroupMembers: %v, %v", members, err)
	}
	if err := c.RemoveMember(ctx, gpk, pk); err != nil {
		t.Fatal(err)
	}
	if members, _ := c.GroupMembers(ctx, gpk); len(members) != 0 {
		t.Fatalf("members after removal: %v", members)
	}

	if active, err := c.UserActive(ctx, pk); err != nil || !active {
		t.Fatalf("UserActive before the lock: %v, %v", active, err)
	}
	if err := c.LockUser(ctx, slug, pk, true); err != nil {
		t.Fatalf("LockUser: %v", err)
	}
	if members, _ := c.GroupMembers(ctx, refs.LockedGroupPK); !slices.Equal(members, []string{pk}) {
		t.Fatalf("locked group members after lock: %v", members)
	}
	if active, err := c.UserActive(ctx, pk); err != nil || !active {
		t.Fatalf("UserActive after the lock: %v, %v", active, err)
	}
	if err := c.UnlockUser(ctx, slug, pk, false); err != nil {
		t.Fatalf("UnlockUser: %v", err)
	}
	if members, _ := c.GroupMembers(ctx, refs.LockedGroupPK); len(members) != 0 {
		t.Fatalf("locked group members after unlock: %v", members)
	}
	// A lock without reactivation leaves the user inactive, an unlock with activation activates it.
	if err := c.LockUser(ctx, slug, pk, false); err != nil {
		t.Fatalf("LockUser without reactivation: %v", err)
	}
	if active, err := c.UserActive(ctx, pk); err != nil || active {
		t.Fatalf("UserActive after a lock without reactivation: %v, %v", active, err)
	}
	if err := c.UnlockUser(ctx, slug, pk, true); err != nil {
		t.Fatalf("UnlockUser with activation: %v", err)
	}
	if active, err := c.UserActive(ctx, pk); err != nil || !active {
		t.Fatalf("UserActive after an unlock with activation: %v, %v", active, err)
	}

	upstream, err := c.UpstreamGroups(ctx, slug)
	if err != nil {
		t.Fatal(err)
	}
	for _, g := range upstream {
		if organization.IsPaddockGroup(g.Name) {
			t.Fatalf("UpstreamGroups lists %s", g.Name)
		}
	}

	if err := c.DeleteGroup(ctx, gpk); err != nil {
		t.Fatal(err)
	}
	if err := c.DeleteGroup(ctx, gpk); err != nil {
		t.Fatalf("second DeleteGroup: %v", err)
	}
	if err := c.DeleteUser(ctx, pk); err != nil {
		t.Fatal(err)
	}
	if err := c.DeleteUser(ctx, pk); err != nil {
		t.Fatalf("second DeleteUser: %v", err)
	}
	deleteLiveOrganization(ctx, t, c, admin, slug)
	if rec.record {
		rec.write(t, slug)
	}
}

// deleteLiveOrganization runs DeleteOrganization with the service token (plan M17 decision 10) and checks with the
// admin token that every object it counts is gone, so a permission missing from the service role fails here.
func deleteLiveOrganization(ctx context.Context, t *testing.T, c *authentik.Client, admin *rawAPI, slug string) {
	t.Helper()
	managed := "gone-" + uuid.NewString()[:8] + "@" + slug + ".test"
	userPK, err := c.CreateUser(ctx, slug, ports.NewIdentityUser{Username: managed, Name: "Deleted With The Organization", Email: managed})
	if err != nil {
		t.Fatalf("CreateUser before DeleteOrganization: %v", err)
	}
	app := organization.DeviceLoginApp(slug)
	appPK := admin.first("/core/applications/?superuser_full_list=true&slug=" + app)["pk"].(string)
	provPK := admin.first("/providers/oauth2/?name=" + app)["pk"]
	policyPK := admin.first("/policies/expression/?name=" + authentik.AccessPolicyName(slug))["pk"].(string)
	mappingPK := admin.first("/propertymappings/provider/scope/?name=" + authentik.GroupsMappingName(slug))["pk"].(string)
	bindings := map[string]bool{}
	for _, q := range []string{"target=" + appPK, "policy=" + policyPK} {
		for _, b := range admin.list("/policies/bindings/?" + q) {
			bindings[b["pk"].(string)] = true
		}
	}
	var groups []string
	for _, g := range admin.list("/core/groups/?include_users=false&page_size=100&search=" + organization.RootGroup(slug)) {
		if name, _ := g["name"].(string); name == organization.RootGroup(slug) || strings.HasPrefix(name, organization.RootGroup(slug)+".") {
			groups = append(groups, g["pk"].(string))
		}
	}
	if len(bindings) == 0 || len(groups) == 0 {
		t.Fatalf("fixture organization has %d bindings and %d groups", len(bindings), len(groups))
	}

	d, err := c.DeleteOrganization(ctx, slug)
	if err != nil {
		t.Fatalf("DeleteOrganization with the service token: %v (counts so far %+v)", err, d)
	}
	want := ports.OrgIdentityDeletion{Groups: len(groups), Users: 1, Applications: 1, Providers: 1, Policies: len(bindings) + 1, Mappings: 1}
	if d != want {
		t.Errorf("DeleteOrganization counts %+v, want %+v", d, want)
	}
	gone := []string{"/core/applications/" + app + "/", fmt.Sprintf("/providers/oauth2/%v/", provPK),
		"/policies/expression/" + policyPK + "/", "/propertymappings/provider/scope/" + mappingPK + "/", "/core/users/" + userPK + "/"}
	for pk := range bindings {
		gone = append(gone, "/policies/bindings/"+pk+"/")
	}
	for _, pk := range groups {
		gone = append(gone, "/core/groups/"+pk+"/")
	}
	for _, path := range gone {
		if code, body := admin.call(http.MethodGet, path); code != http.StatusNotFound {
			t.Errorf("GET %s after DeleteOrganization: %d %s", path, code, body)
		}
	}
	if again, err := c.DeleteOrganization(ctx, slug); err != nil || again != (ports.OrgIdentityDeletion{}) {
		t.Errorf("second DeleteOrganization: %+v, %v", again, err)
	}
}

func readSecret(t *testing.T, file string) string {
	t.Helper()
	if file == "" {
		t.Fatal("token file variable not set")
	}
	b, err := os.ReadFile(file) //nolint:gosec // test input
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(b))
}

// rawAPI reads and cleans up with the admin token.
type rawAPI struct {
	t           *testing.T
	base, token string
}

func (a *rawAPI) call(method, path string) (int, []byte) {
	req, err := http.NewRequest(method, strings.TrimRight(a.base, "/")+"/api/v3"+path, nil) //nolint:noctx // test helper
	if err != nil {
		a.t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+a.token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		a.t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, body
}

func (a *rawAPI) list(path string) []map[string]any {
	code, body := a.call(http.MethodGet, path)
	var page struct {
		Results []map[string]any `json:"results"`
	}
	if code != http.StatusOK || json.Unmarshal(body, &page) != nil {
		a.t.Fatalf("GET %s: %d %s", path, code, body)
	}
	return page.Results
}

func (a *rawAPI) first(path string) map[string]any {
	r := a.list(path)
	if len(r) == 0 {
		a.t.Fatalf("GET %s: no result", path)
	}
	return r[0]
}

// deleteOrganization removes the device login objects, every group and every user of the fixture organization.
func (a *rawAPI) deleteOrganization(slug string) {
	app := organization.DeviceLoginApp(slug)
	for _, step := range []struct{ list, item, key string }{
		{"/core/applications/?superuser_full_list=true&slug=" + app, "/core/applications/%v/", "slug"},
		{"/providers/oauth2/?name=" + app, "/providers/oauth2/%v/", "pk"},
		{"/policies/expression/?name=" + authentik.AccessPolicyName(slug), "/policies/expression/%v/", "pk"},
		{"/propertymappings/provider/scope/?name=" + authentik.GroupsMappingName(slug), "/propertymappings/provider/scope/%v/", "pk"},
		{"/core/groups/?include_users=false&search=paddock." + slug, "/core/groups/%v/", "pk"},
	} {
		for _, obj := range a.list(step.list) {
			if name, _ := obj["name"].(string); step.key == "pk" && strings.HasPrefix(step.list, "/core/groups/") &&
				name != organization.RootGroup(slug) && !strings.HasPrefix(name, organization.RootGroup(slug)+".") {
				continue
			}
			if code, body := a.call(http.MethodDelete, fmt.Sprintf(step.item, obj[step.key])); code >= 300 && code != http.StatusNotFound {
				a.t.Errorf("cleanup %s: %d %s", step.item, code, body)
			}
		}
	}
	// The users the test created stay behind when it fails before DeleteUser or DeleteOrganization.
	for _, u := range a.list("/core/users/?include_groups=false&path=paddock/" + slug) {
		pk, _ := u["pk"].(float64)
		if code, body := a.call(http.MethodDelete, fmt.Sprintf("/core/users/%.0f/", pk)); code >= 300 && code != http.StatusNotFound {
			a.t.Errorf("cleanup user %.0f: %d %s", pk, code, body)
		}
	}
}

// recorder keeps the first response of every endpoint for the fixtures.
type recorder struct {
	next   http.RoundTripper
	record bool
	mu     sync.Mutex
	seen   []recorded
}

type recorded struct {
	Method, Path string
	Status       int
	Body         json.RawMessage
}

func (r *recorder) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := r.next.RoundTrip(req)
	if err != nil || !r.record {
		return resp, err
	}
	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		return nil, err
	}
	resp.Body = io.NopCloser(bytes.NewReader(body))
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(body) > 0 && json.Valid(body) {
		r.seen = append(r.seen, recorded{Method: req.Method, Path: req.URL.Path, Status: resp.StatusCode, Body: body})
	}
	return resp, nil
}

var (
	idPattern     = regexp.MustCompile(`/[0-9a-f-]{36}/|/[0-9]+/`)
	clientSecret  = regexp.MustCompile(`"client_secret": "[^"]*"`)
	linkFlowToken = regexp.MustCompile(`flow_token=[A-Za-z0-9]+`)
)

// write stores the first response per method and path pattern as testdata/<method>_<path>.json, with the fixture
// organization's slug replaced by "fixture-org" and client secrets and link tokens redacted.
func (r *recorder) write(t *testing.T, slug string) {
	written := map[string]bool{}
	for _, s := range r.seen {
		pattern := idPattern.ReplaceAllString(strings.ReplaceAll(s.Path, slug, "fixture-org"), "/{id}/")
		name := strings.ToLower(s.Method) + strings.NewReplacer("/api/v3", "", "/", "_", "{", "", "}", "").Replace(strings.TrimSuffix(pattern, "/"))
		if s.Status >= 300 {
			name += fmt.Sprintf("_%d", s.Status)
		}
		if written[name] {
			continue
		}
		written[name] = true
		var pretty bytes.Buffer
		if err := json.Indent(&pretty, bytes.ReplaceAll(s.Body, []byte(slug), []byte("fixture-org")), "", "  "); err != nil {
			t.Fatal(err)
		}
		pretty.WriteByte('\n')
		redacted := clientSecret.ReplaceAll(pretty.Bytes(), []byte(`"client_secret": "redacted"`))
		redacted = linkFlowToken.ReplaceAll(redacted, []byte("flow_token=redacted"))
		if err := os.WriteFile(filepath.Join("testdata", name+".json"), redacted, 0o644); err != nil { //nolint:gosec // fixtures are public
			t.Fatal(err)
		}
	}
}
