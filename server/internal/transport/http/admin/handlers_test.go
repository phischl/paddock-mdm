package admin_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/fstest"
	"time"

	"aead.dev/minisign"
	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/getkin/kin-openapi/routers"
	"github.com/getkin/kin-openapi/routers/legacy"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/phischl/paddock-mdm/pkg/protocol"
	"github.com/phischl/paddock-mdm/server/internal/adapters/auditpg/auditstore"
	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/platform/httpx"
	"github.com/phischl/paddock-mdm/server/internal/ports"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/problem"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/pgtest"
	"github.com/phischl/paddock-mdm/server/internal/transport/http/admin"
	"github.com/phischl/paddock-mdm/server/internal/transport/http/admin/adminapi"
)

// fakeIdP is the identity provider of the handler tests: organizations, users and groups in memory.
type fakeIdP struct {
	mu      sync.Mutex
	fail    bool
	users   map[string]ports.NewIdentityUser // pk → user
	groups  map[string]string                // pk → name
	members map[string][]string              // group pk → user pks
	locked  map[string]bool                  // user pk → locked (and tokens revoked)
}

// fakePKs numbers the users of every fake identity provider of the test binary.
var fakePKs atomic.Int64

func newFakeIdP() *fakeIdP {
	return &fakeIdP{users: map[string]ports.NewIdentityUser{}, groups: map[string]string{}, members: map[string][]string{},
		locked: map[string]bool{}}
}

func (f *fakeIdP) err() error {
	if f.fail {
		return problem.UpstreamUnavailable
	}
	return nil
}

func (f *fakeIdP) EnsureOrganization(context.Context, string) (ports.OrgIdentityRefs, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.err(); err != nil {
		return ports.OrgIdentityRefs{}, err
	}
	return ports.OrgIdentityRefs{RootGroupPK: "r", AdminsGroupPK: "a", OperatorsGroupPK: "o", AuditorsGroupPK: "u", LockedGroupPK: "l"}, nil
}

func (f *fakeIdP) CreateUser(_ context.Context, _ string, u ports.NewIdentityUser) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.err(); err != nil {
		return "", err
	}
	for _, x := range f.users {
		if x.Username == u.Username {
			return "", ports.ErrUsernameTaken
		}
	}
	// Authentik pks are unique across the shared test database.
	pk := strconv.FormatInt(fakePKs.Add(1), 10)
	f.users[pk] = u
	return pk, nil
}

func (f *fakeIdP) UpdateUser(_ context.Context, pk, name, email string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	u := f.users[pk]
	u.Name, u.Email = name, email
	f.users[pk] = u
	return f.err()
}

func (f *fakeIdP) DeleteUser(_ context.Context, pk string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.users, pk)
	return f.err()
}

func (f *fakeIdP) RecoveryLink(_ context.Context, pk string) (string, error) {
	return "https://auth.test/if/flow/paddock-recovery/?flow_token=" + pk, f.err()
}

func (f *fakeIdP) LockUser(_ context.Context, _, pk string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.err(); err != nil {
		return err
	}
	f.locked[pk] = true
	return nil
}

func (f *fakeIdP) UnlockUser(_ context.Context, _, pk string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.err(); err != nil {
		return err
	}
	delete(f.locked, pk)
	return nil
}

func (f *fakeIdP) OrganizationUsers(context.Context, string) ([]ports.IdentityUser, error) {
	return nil, f.err()
}

func (f *fakeIdP) EnsureGroup(_ context.Context, _, name string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.err(); err != nil {
		return "", err
	}
	for pk, n := range f.groups {
		if n == name {
			return pk, nil
		}
	}
	pk := "g-" + uuid.NewString()
	f.groups[pk] = name
	return pk, nil
}

func (f *fakeIdP) FindGroup(_ context.Context, name string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for pk, n := range f.groups {
		if n == name {
			return pk, nil
		}
	}
	return "", f.err()
}

func (f *fakeIdP) DeleteGroup(_ context.Context, pk string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.groups, pk)
	delete(f.members, pk)
	return f.err()
}

func (f *fakeIdP) AddMember(_ context.Context, group, user string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.err(); err != nil {
		return err
	}
	if !slices.Contains(f.members[group], user) {
		f.members[group] = append(f.members[group], user)
	}
	return nil
}

func (f *fakeIdP) RemoveMember(_ context.Context, group, user string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.err(); err != nil {
		return err
	}
	f.members[group] = slices.DeleteFunc(f.members[group], func(x string) bool { return x == user })
	return nil
}

func (f *fakeIdP) GroupMembers(_ context.Context, group string) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.members[group]), f.err()
}

func (f *fakeIdP) UpstreamGroups(_ context.Context, slug string) ([]ports.IdentityGroup, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var root []string
	for pk, n := range f.groups {
		if n == "paddock."+slug {
			root = f.members[pk]
		}
	}
	var out []ports.IdentityGroup
	for pk, n := range f.groups {
		if !strings.HasPrefix(n, "paddock.") && slices.ContainsFunc(f.members[pk], func(u string) bool { return slices.Contains(root, u) }) {
			out = append(out, ports.IdentityGroup{PK: pk, Name: n})
		}
	}
	return out, f.err()
}

// discardStore accepts agent artifacts without storing them.
type discardStore struct{}

func (discardStore) Put(context.Context, string, string, string, []byte) error { return nil }

type env struct {
	t        *testing.T
	keysDown bool // the fake bundle key source fails
	handler  http.Handler
	keys     *admin.Keyring
	router   routers.Router
	super    *pgx.Conn
	writer   *db.AuditWriterPool
	idp      *fakeIdP
	release  minisign.PrivateKey // signs agent releases the server accepts
	acme     uuid.UUID
	globex   uuid.UUID
}

func newEnv(t *testing.T) *env {
	t.Helper()
	ctx := context.Background()
	pg := pgtest.SharedPaddock(t)
	ag := pgtest.SharedAudit(t)
	orgPool, err := db.NewOrgPool(ctx, pg.API, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(orgPool.Close)
	platformPool, err := db.NewPlatformPool(ctx, pg.Platform, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(platformPool.Close)
	reader, err := db.NewAuditReader(ctx, ag.Reader, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(reader.Close)
	writer, err := db.NewAuditWriterPool(ctx, ag.Writer, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(writer.Close)
	super, err := pgx.Connect(ctx, pg.Super)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = super.Close(ctx) })

	key := make([]byte, 32)
	_, _ = rand.Read(key)
	keys := &admin.Keyring{}
	if err := keys.SetKeys(base64.StdEncoding.EncodeToString(key), ""); err != nil {
		t.Fatal(err)
	}
	runner := app.NewActionRunner(orgPool, platformPool, httpx.RequestID)
	idp := newFakeIdP()
	static, err := admin.NewStaticHandler(fstest.MapFS{"index.html": {Data: []byte(testIndex)}})
	if err != nil {
		t.Fatal(err)
	}
	releasePub, releaseKey, err := minisign.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	e := &env{t: t, keys: keys, super: super, writer: writer, idp: idp, release: releaseKey}
	verifyRelease := func(bin, sig []byte) bool { return minisign.Verify(releasePub, bin, sig) }
	bundleKeys := func(context.Context) ([]protocol.BundleKey, error) {
		if e.keysDown {
			return nil, problem.UpstreamUnavailable
		}
		return []protocol.BundleKey{{KeyID: "bundle-signing:v1", PublicKey: testBundleKey}}, nil
	}
	handler := admin.NewHandler(admin.Deps{
		DeviceGroups:  app.NewDeviceGroups(runner, orgPool),
		Tokens:        app.NewEnrollmentTokens(runner, orgPool, bundleKeys, "https://device.test"),
		Devices:       app.NewDevices(runner, orgPool),
		Managed:       app.NewManagedConfig(runner, orgPool),
		Organizations: app.NewOrganizations(runner, platformPool, idp),
		Accounts:      app.NewAccounts(runner, orgPool, platformPool),
		Releases:      app.NewAgentReleases(runner, platformPool, discardStore{}, verifyRelease, true),
		Users:         app.NewUsers(runner, orgPool, idp),
		UserGroups:    app.NewUserGroups(runner, orgPool, idp),
		Logins:        app.NewLogins(runner, orgPool, idp),
		LoginSettings: app.NewLoginSettings(runner, orgPool),
		Privileges:    app.NewPrivileges(runner, orgPool),
		Commands:      app.NewDeviceCommands(orgPool),
		LocalAdmin:    app.NewLocalAdmin(runner, orgPool, fakeDecrypter{}),
		AuditLog:      app.NewAuditLog(reader),
		Runner:        runner,
		Keys:          keys,
		OIDC:          admin.NewOIDC(admin.OIDCConfig{}),
		PublicURL:     "https://admin.test",
		Static:        static,
	})

	spec, err := adminapi.GetSpec()
	if err != nil {
		t.Fatal(err)
	}
	spec.Servers = openapi3.Servers{{URL: "https://admin.test"}}
	router, err := legacy.NewRouter(spec)
	if err != nil {
		t.Fatal(err)
	}
	e.handler, e.router = handler, router
	e.acme = e.org("acme")
	e.globex = e.org("globex")
	return e
}

// org inserts an active organization with a unique slug.
func (e *env) org(prefix string) uuid.UUID {
	id := uuid.Must(uuid.NewV7())
	_, err := e.super.Exec(context.Background(), "INSERT INTO organization (id, slug, name, status) VALUES ($1, $2, $3, 'active')",
		id, prefix+"-"+id.String()[28:], prefix)
	if err != nil {
		e.t.Fatal(err)
	}
	return id
}

// session returns a cookie for a new admin account of org with role.
func (e *env) session(org uuid.UUID, role principal.Role) *http.Cookie {
	p := principal.Principal{Kind: principal.KindAdmin, ID: uuid.Must(uuid.NewV7()), Subject: uuid.NewString(),
		Display: string(role) + "@test", Role: role, OrganizationID: org}
	_, err := e.super.Exec(context.Background(), `INSERT INTO admin_account (id, organization_id, authentik_sub, username, display_name, role)
		VALUES ($1, $2, $3, $4, $4, $5)`, p.ID, org, p.Subject, p.Display, string(role))
	if err != nil {
		e.t.Fatal(err)
	}
	return e.cookie(p)
}

func (e *env) platformSession() *http.Cookie {
	p := principal.Principal{Kind: principal.KindPlatformAdmin, ID: uuid.Must(uuid.NewV7()), Subject: uuid.NewString(),
		Display: "root@test", Role: principal.RolePlatform}
	_, err := e.super.Exec(context.Background(), `INSERT INTO platform_admin (id, authentik_sub, username, display_name)
		VALUES ($1, $2, $3, $3)`, p.ID, p.Subject, p.Display)
	if err != nil {
		e.t.Fatal(err)
	}
	return e.cookie(p)
}

// steppedUp returns the session cookie after a step-up authentication at at (plan M4a decision 6).
func (e *env) steppedUp(c *http.Cookie, at time.Time) *http.Cookie {
	var sess admin.Session
	if err := e.keys.Open(admin.SessionCookie, c.Value, &sess); err != nil {
		e.t.Fatal(err)
	}
	sess.StepUpAt, sess.StepUpJTI = at.Unix(), "jti-test"
	v, err := e.keys.Seal(admin.SessionCookie, sess)
	if err != nil {
		e.t.Fatal(err)
	}
	return &http.Cookie{Name: admin.SessionCookie, Value: v}
}

func (e *env) cookie(p principal.Principal) *http.Cookie {
	v, err := e.keys.Seal(admin.SessionCookie, admin.NewSession(p, "en", time.Now()))
	if err != nil {
		e.t.Fatal(err)
	}
	return &http.Cookie{Name: admin.SessionCookie, Value: v}
}

type call struct {
	method, path string
	body         any
	cookie       *http.Cookie
	noCSRF       bool
	rawBody      string
	contentType  string            // default application/json
	headers      map[string]string // additional request headers
	skipReqCheck bool              // negative tests send requests that violate the contract on purpose
}

type result struct {
	status int
	header http.Header
	body   []byte
}

func (r result) decode(t *testing.T, v any) {
	t.Helper()
	if err := json.Unmarshal(r.body, v); err != nil {
		t.Fatalf("decode %s: %v", r.body, err)
	}
}

func (r result) problemCode(t *testing.T) string {
	t.Helper()
	var p httpx.Problem
	r.decode(t, &p)
	return p.Code
}

// do sends the request, validates request and response against api/openapi/admin.yaml.
func (e *env) do(c call) result {
	e.t.Helper()
	var body []byte
	switch {
	case c.rawBody != "":
		body = []byte(c.rawBody)
	case c.body != nil:
		body, _ = json.Marshal(c.body)
	}
	req := httptest.NewRequest(c.method, "https://admin.test"+c.path, bytes.NewReader(body))
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.contentType != "" {
		req.Header.Set("Content-Type", c.contentType)
	}
	for k, v := range c.headers {
		req.Header.Set(k, v)
	}
	if c.method != http.MethodGet && !c.noCSRF {
		req.Header.Set("X-Paddock-CSRF", "1")
	}
	if c.cookie != nil {
		req.AddCookie(c.cookie)
	}
	route, pathParams, err := e.router.FindRoute(req)
	if err != nil {
		e.t.Fatalf("%s %s is not in the OpenAPI contract: %v", c.method, c.path, err)
	}
	reqInput := &openapi3filter.RequestValidationInput{
		Request: req, PathParams: pathParams, Route: route,
		Options: &openapi3filter.Options{AuthenticationFunc: openapi3filter.NoopAuthenticationFunc},
	}
	if !c.skipReqCheck {
		if err := openapi3filter.ValidateRequest(context.Background(), reqInput); err != nil {
			e.t.Fatalf("request violates the contract: %v", err)
		}
		req.Body = io.NopCloser(bytes.NewReader(body))
	}
	rec := httptest.NewRecorder()
	e.handler.ServeHTTP(rec, req)
	res := result{status: rec.Code, header: rec.Header(), body: rec.Body.Bytes()}
	respInput := &openapi3filter.ResponseValidationInput{
		RequestValidationInput: reqInput, Status: res.status, Header: res.header,
		Options: &openapi3filter.Options{IncludeResponseStatus: true},
	}
	respInput.SetBodyBytes(res.body)
	if err := openapi3filter.ValidateResponse(context.Background(), respInput); err != nil {
		e.t.Fatalf("%s %s: response %d violates the contract: %v\n%s", c.method, c.path, res.status, err, res.body)
	}
	if res.header.Get(httpx.HeaderRequestID) == "" {
		e.t.Fatal("response without X-Request-Id")
	}
	return res
}

// events returns the action rows recorded for a request ID.
func (e *env) events(requestID string) []string {
	e.t.Helper()
	rows, err := e.super.Query(context.Background(), "SELECT code || ':' || coalesce(outcome, status) || ':' || coalesce(error_code, '') FROM action WHERE correlation_id = $1", requestID)
	if err != nil {
		e.t.Fatal(err)
	}
	out, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		e.t.Fatal(err)
	}
	return out
}

func (e *env) expectEvent(r result, want string) {
	e.t.Helper()
	got := e.events(r.header.Get(httpx.HeaderRequestID))
	if len(got) != 1 || got[0] != want {
		e.t.Fatalf("audit for request: %v, want exactly [%s]", got, want)
	}
}

func TestDeviceGroupLifecycle(t *testing.T) {
	e := newEnv(t)
	alice := e.session(e.acme, principal.RoleOrgAdmin)

	created := e.do(call{method: "POST", path: "/api/v1/device-groups", cookie: alice, body: map[string]any{"name": "Laptops", "description": "all laptops"}})
	if created.status != http.StatusCreated {
		t.Fatalf("create: %d %s", created.status, created.body)
	}
	e.expectEvent(created, "device_group.created:success:")
	var g adminapi.DeviceGroup
	created.decode(t, &g)
	if created.header.Get("Location") != "/api/v1/device-groups/"+g.Id.String() {
		t.Fatalf("Location %q", created.header.Get("Location"))
	}

	got := e.do(call{method: "GET", path: "/api/v1/device-groups/" + g.Id.String(), cookie: alice})
	if got.status != http.StatusOK {
		t.Fatalf("get: %d", got.status)
	}
	if len(e.events(got.header.Get(httpx.HeaderRequestID))) != 0 {
		t.Fatal("a read was audited")
	}

	renamed := e.do(call{method: "PATCH", path: "/api/v1/device-groups/" + g.Id.String(), cookie: alice, body: map[string]any{"name": "Notebooks"}})
	if renamed.status != http.StatusOK {
		t.Fatalf("rename: %d %s", renamed.status, renamed.body)
	}
	e.expectEvent(renamed, "device_group.updated:success:")

	dup := e.do(call{method: "POST", path: "/api/v1/device-groups", cookie: alice, body: map[string]any{"name": "Notebooks"}})
	if dup.status != http.StatusConflict || dup.problemCode(t) != "name_taken" {
		t.Fatalf("duplicate: %d %s", dup.status, dup.body)
	}
	e.expectEvent(dup, "device_group.created:failure:name_taken")

	list := e.do(call{method: "GET", path: "/api/v1/device-groups?page_size=10", cookie: alice})
	var page adminapi.DeviceGroupPage
	list.decode(t, &page)
	if list.status != http.StatusOK || len(page.Items) != 1 || page.Total != 1 || page.Items[0].Name != "Notebooks" {
		t.Fatalf("list: %d %s", list.status, list.body)
	}

	deleted := e.do(call{method: "DELETE", path: "/api/v1/device-groups/" + g.Id.String(), cookie: alice})
	if deleted.status != http.StatusNoContent {
		t.Fatalf("delete: %d", deleted.status)
	}
	e.expectEvent(deleted, "device_group.deleted:success:")

	gone := e.do(call{method: "DELETE", path: "/api/v1/device-groups/" + g.Id.String(), cookie: alice})
	if gone.status != http.StatusNotFound || gone.problemCode(t) != "not_found" {
		t.Fatalf("second delete: %d %s", gone.status, gone.body)
	}
	e.expectEvent(gone, "device_group.deleted:failure:not_found")
}

func TestValidationAndRejectionsAreAudited(t *testing.T) {
	e := newEnv(t)
	alice := e.session(e.acme, principal.RoleOrgAdmin)
	bob := e.session(e.acme, principal.RoleOrgAuditor)

	empty := e.do(call{method: "POST", path: "/api/v1/device-groups", cookie: alice, body: map[string]any{"name": ""}, skipReqCheck: true})
	if empty.status != http.StatusBadRequest || empty.problemCode(t) != "invalid_request" {
		t.Fatalf("empty name: %d %s", empty.status, empty.body)
	}
	e.expectEvent(empty, "device_group.created:failure:invalid_request")

	malformed := e.do(call{method: "POST", path: "/api/v1/device-groups", cookie: alice, rawBody: "{", skipReqCheck: true})
	if malformed.status != http.StatusBadRequest {
		t.Fatalf("malformed body: %d", malformed.status)
	}
	e.expectEvent(malformed, "device_group.created:failure:invalid_request")

	badID := e.do(call{method: "PATCH", path: "/api/v1/device-groups/not-a-uuid", cookie: alice, body: map[string]any{"name": "x"}, skipReqCheck: true})
	if badID.status != http.StatusBadRequest {
		t.Fatalf("bad id: %d", badID.status)
	}
	e.expectEvent(badID, "device_group.updated:failure:invalid_request")

	noCSRF := e.do(call{method: "POST", path: "/api/v1/device-groups", cookie: alice, body: map[string]any{"name": "x"}, noCSRF: true, skipReqCheck: true})
	if noCSRF.status != http.StatusForbidden || noCSRF.problemCode(t) != "csrf_missing" {
		t.Fatalf("no CSRF: %d %s", noCSRF.status, noCSRF.body)
	}
	e.expectEvent(noCSRF, "device_group.created:denied:csrf_missing")

	denied := e.do(call{method: "POST", path: "/api/v1/device-groups", cookie: bob, body: map[string]any{"name": "x"}})
	if denied.status != http.StatusForbidden || denied.problemCode(t) != "forbidden" {
		t.Fatalf("auditor create: %d %s", denied.status, denied.body)
	}
	e.expectEvent(denied, "device_group.created:denied:forbidden")

	unauth := e.do(call{method: "POST", path: "/api/v1/device-groups", body: map[string]any{"name": "x"}})
	if unauth.status != http.StatusUnauthorized || unauth.problemCode(t) != "unauthenticated" {
		t.Fatalf("unauthenticated: %d", unauth.status)
	}
	if n := len(e.events(unauth.header.Get(httpx.HeaderRequestID))); n != 0 {
		t.Fatal("unauthenticated request was audited")
	}
}

func TestCrossOrganizationIs404(t *testing.T) {
	e := newEnv(t)
	alice := e.session(e.acme, principal.RoleOrgAdmin)
	carol := e.session(e.globex, principal.RoleOrgAdmin)
	created := e.do(call{method: "POST", path: "/api/v1/device-groups", cookie: carol, body: map[string]any{"name": "Globex servers"}})
	var g adminapi.DeviceGroup
	created.decode(t, &g)

	for _, c := range []call{
		{method: "GET", path: "/api/v1/device-groups/" + g.Id.String(), cookie: alice},
		{method: "PATCH", path: "/api/v1/device-groups/" + g.Id.String(), cookie: alice, body: map[string]any{"name": "pwned"}},
		{method: "DELETE", path: "/api/v1/device-groups/" + g.Id.String(), cookie: alice},
	} {
		r := e.do(c)
		if r.status != http.StatusNotFound || r.problemCode(t) != "not_found" || strings.Contains(string(r.body), g.Id.String()) {
			t.Fatalf("%s as acme: %d %s", c.method, r.status, r.body)
		}
	}
	list := e.do(call{method: "GET", path: "/api/v1/device-groups", cookie: alice})
	if strings.Contains(string(list.body), g.Id.String()) {
		t.Fatal("acme list contains a globex group")
	}
}

func TestRoleBoundaries(t *testing.T) {
	e := newEnv(t)
	root := e.platformSession()
	alice := e.session(e.acme, principal.RoleOrgAdmin)
	operator := e.session(e.acme, principal.RoleOrgOperator)

	r := e.do(call{method: "GET", path: "/api/v1/device-groups", cookie: root})
	if r.status != http.StatusForbidden || r.problemCode(t) != "no_organization" {
		t.Fatalf("platform admin on /api/v1: %d %s", r.status, r.body)
	}
	r = e.do(call{method: "GET", path: "/api/platform/v1/organizations", cookie: alice})
	if r.status != http.StatusForbidden || r.problemCode(t) != "forbidden" {
		t.Fatalf("org admin on platform API: %d %s", r.status, r.body)
	}
	r = e.do(call{method: "GET", path: "/api/v1/audit-events", cookie: operator})
	if r.status != http.StatusForbidden {
		t.Fatalf("operator reading audit: %d", r.status)
	}
	me := e.do(call{method: "GET", path: "/api/v1/me", cookie: root})
	var m adminapi.Me
	me.decode(t, &m)
	if me.status != http.StatusOK || m.Role != adminapi.MeRolePlatformAdmin || m.Organization != nil {
		t.Fatalf("platform /me: %d %s", me.status, me.body)
	}
	me = e.do(call{method: "GET", path: "/api/v1/me", cookie: alice})
	me.decode(t, &m)
	if m.Organization == nil || m.Organization.Id != e.acme || m.Role != adminapi.MeRoleOrgAdmin {
		t.Fatalf("org /me: %s", me.body)
	}
	locale := e.do(call{method: "PATCH", path: "/api/v1/me", cookie: alice, body: map[string]any{"locale": "en"}})
	if locale.status != http.StatusOK {
		t.Fatalf("set locale: %d", locale.status)
	}
	bad := e.do(call{method: "PATCH", path: "/api/v1/me", cookie: alice, body: map[string]any{"locale": "de"}, skipReqCheck: true})
	if bad.status != http.StatusBadRequest {
		t.Fatalf("unsupported locale: %d", bad.status)
	}
	unknown := e.do(call{method: "GET", path: "/api/v1/me", cookie: &http.Cookie{Name: admin.SessionCookie, Value: "forged"}})
	if unknown.status != http.StatusUnauthorized {
		t.Fatalf("forged cookie: %d", unknown.status)
	}
}

func TestOrganizationProvisioning(t *testing.T) {
	e := newEnv(t)
	root := e.platformSession()
	slug := "org-" + uuid.NewString()[:8]

	e.idp.fail = true
	failed := e.do(call{method: "POST", path: "/api/platform/v1/organizations", cookie: root, body: map[string]any{"slug": slug, "name": "Initech"}})
	if failed.status != http.StatusBadGateway || failed.problemCode(t) != "upstream_unavailable" {
		t.Fatalf("authentik down: %d %s", failed.status, failed.body)
	}
	e.expectEvent(failed, "organization.created:failure:upstream_unavailable")

	e.idp.fail = false
	retried := e.do(call{method: "POST", path: "/api/platform/v1/organizations", cookie: root, body: map[string]any{"slug": slug, "name": "Initech"}})
	var o adminapi.Organization
	retried.decode(t, &o)
	if retried.status != http.StatusOK || o.Status != "active" {
		t.Fatalf("re-provisioning: %d %s", retried.status, retried.body)
	}
	e.expectEvent(retried, "organization.created:success:")

	taken := e.do(call{method: "POST", path: "/api/platform/v1/organizations", cookie: root, body: map[string]any{"slug": slug, "name": "Initech"}})
	if taken.status != http.StatusConflict || taken.problemCode(t) != "slug_taken" {
		t.Fatalf("slug taken: %d %s", taken.status, taken.body)
	}
	e.expectEvent(taken, "organization.created:failure:slug_taken")

	fresh := e.do(call{method: "POST", path: "/api/platform/v1/organizations", cookie: root, body: map[string]any{"slug": slug + "x", "name": "Initrode"}})
	if fresh.status != http.StatusCreated || fresh.header.Get("Location") == "" {
		t.Fatalf("create: %d %s", fresh.status, fresh.body)
	}
	invalid := e.do(call{method: "POST", path: "/api/platform/v1/organizations", cookie: root, body: map[string]any{"slug": "platform", "name": "x"}})
	if invalid.status != http.StatusBadRequest {
		t.Fatalf("reserved slug: %d", invalid.status)
	}
	e.expectEvent(invalid, "organization.created:failure:invalid_request")

	list := e.do(call{method: "GET", path: "/api/platform/v1/organizations", cookie: root})
	if list.status != http.StatusOK || !strings.Contains(string(list.body), slug) {
		t.Fatalf("list: %d", list.status)
	}
	one := e.do(call{method: "GET", path: "/api/platform/v1/organizations/" + o.Id.String(), cookie: root})
	if one.status != http.StatusOK {
		t.Fatalf("get: %d", one.status)
	}
}

func TestAuditEvents(t *testing.T) {
	e := newEnv(t)
	alice := e.session(e.acme, principal.RoleOrgAdmin)
	now := time.Now().UTC()
	err := e.writer.InWriter(context.Background(), func(ctx context.Context, q *auditstore.Queries) error {
		if err := q.EnsureAuditPartition(ctx, now); err != nil {
			return err
		}
		if err := q.EnsureAuditPartition(ctx, now.AddDate(0, -1, 0)); err != nil {
			return err
		}
		orgs := []uuid.UUID{e.globex}
		for range 12 {
			orgs = append(orgs, e.acme)
		}
		for i, org := range orgs {
			_, err := q.InsertAuditEvent(ctx, auditstore.InsertAuditEventParams{
				EventID: uuid.Must(uuid.NewV7()), OrganizationID: org, OccurredAt: now.Add(-time.Duration(i) * time.Minute),
				RecordedAt: now, Code: "device_group.created", Outcome: "failure", Source: "portal",
				Actor: []byte(`{"type":"admin","display":"alice","step_up":false}`), Target: []byte(`{"type":"device_group","id":"x"}`),
				Params: []byte(`{"name":"g","error_code":"name_taken"}`), CorrelationID: "c", ObjectKey: "k",
			})
			if err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	r := e.do(call{method: "GET", path: "/api/v1/audit-events?page_size=10", cookie: alice})
	var page adminapi.AuditEventPage
	r.decode(t, &page)
	if r.status != http.StatusOK || len(page.Items) != 10 || page.Total != 12 || page.TotalCapped || page.Sort != "-occurred_at" {
		t.Fatalf("page 1: %d %s", r.status, r.body)
	}
	if page.Items[0].ErrorCode == nil || *page.Items[0].ErrorCode != "name_taken" || page.Items[0].Params["error_code"] != nil {
		t.Fatalf("error_code not presented: %+v", page.Items[0])
	}
	r2 := e.do(call{method: "GET", path: "/api/v1/audit-events?page_size=10&page=2", cookie: alice})
	var page2 adminapi.AuditEventPage
	r2.decode(t, &page2)
	if len(page2.Items) != 2 || page2.Total != 12 || page2.Page != 2 {
		t.Fatalf("page 2: %s", r2.body)
	}
	if !page2.Items[0].OccurredAt.Before(page.Items[9].OccurredAt) {
		t.Fatal("page 2 does not continue page 1")
	}
	tooLarge := e.do(call{method: "GET", path: "/api/v1/audit-events?from=2026-01-01T00:00:00Z&to=2026-06-01T00:00:00Z", cookie: alice})
	if tooLarge.status != http.StatusBadRequest || tooLarge.problemCode(t) != "range_too_large" {
		t.Fatalf("range: %d %s", tooLarge.status, tooLarge.body)
	}
}

func TestStaticPortalAndHeaders(t *testing.T) {
	e := newEnv(t)
	for _, path := range []string{"/", "/device-groups", "/login-denied"} {
		req := httptest.NewRequest("GET", "https://admin.test"+path, nil)
		rec := httptest.NewRecorder()
		e.handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "<title>Paddock</title>") {
			t.Fatalf("%s: %d", path, rec.Code)
		}
		if csp := rec.Header().Get("Content-Security-Policy"); !cspWithNonce.MatchString(csp) {
			t.Fatalf("CSP %q", csp)
		}
	}
	req := httptest.NewRequest("GET", "https://admin.test/api/v1/nope", nil)
	req.AddCookie(e.session(e.acme, principal.RoleOrgAdmin))
	rec := httptest.NewRecorder()
	e.handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound || rec.Header().Get("Content-Type") != "application/problem+json" {
		t.Fatalf("unknown API path: %d %s", rec.Code, rec.Header().Get("Content-Type"))
	}
	if csp := rec.Header().Get("Content-Security-Policy"); csp != defaultCSP {
		t.Fatalf("API CSP %q", csp)
	}
	login := httptest.NewRequest("GET", "https://admin.test/api/auth/login?return_to=//evil", nil)
	rec = httptest.NewRecorder()
	e.handler.ServeHTTP(rec, login)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("login with //evil: %d", rec.Code)
	}
}
