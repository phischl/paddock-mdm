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

	"github.com/paddock-mdm/paddock/server/internal/adapters/authentik"
	"github.com/paddock-mdm/paddock/server/internal/domain/organization"
	"github.com/paddock-mdm/paddock/server/internal/ports"
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
	if err := c.UpdateUser(ctx, pk, "Live Test Renamed", username); err != nil {
		t.Fatalf("UpdateUser: %v", err)
	}
	users, err := c.OrganizationUsers(ctx, slug)
	if err != nil || len(users) != 1 || users[0].PK != pk || !users[0].Managed || users[0].Name != "Live Test Renamed" {
		t.Fatalf("OrganizationUsers: %+v, %v", users, err)
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

	if err := c.LockUser(ctx, slug, pk); err != nil {
		t.Fatalf("LockUser: %v", err)
	}
	if members, _ := c.GroupMembers(ctx, refs.LockedGroupPK); !slices.Equal(members, []string{pk}) {
		t.Fatalf("locked group members after lock: %v", members)
	}
	if err := c.UnlockUser(ctx, slug, pk); err != nil {
		t.Fatalf("UnlockUser: %v", err)
	}
	if members, _ := c.GroupMembers(ctx, refs.LockedGroupPK); len(members) != 0 {
		t.Fatalf("locked group members after unlock: %v", members)
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
	if rec.record {
		rec.write(t, slug)
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

// deleteOrganization removes the device login objects and every group of the fixture organization.
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
