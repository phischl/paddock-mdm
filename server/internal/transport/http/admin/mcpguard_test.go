package admin_test

import (
	"context"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/pkg/mcpcatalog"
	"github.com/phischl/paddock-mdm/server/internal/domain/organization"
	"github.com/phischl/paddock-mdm/server/internal/platform/httpx"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/transport/http/admin"
	"github.com/phischl/paddock-mdm/server/internal/transport/http/admin/adminapi"
)

// mcpLogin opens an MCP session of a new user in groups and returns its access token.
func (m *mcpWorld) mcpLogin(groups ...string) string {
	m.t.Helper()
	token, r := m.login(m.user(groups...), nil)
	if r.status != http.StatusNoContent {
		m.t.Fatalf("MCP login: %d %s", r.status, r.body)
	}
	return token
}

// setPolicy saves acme's MCP policy directly in the database.
func (m *mcpWorld) setPolicy(enabled, write bool, mode string, ops ...string) {
	m.t.Helper()
	if ops == nil {
		ops = []string{}
	}
	if _, err := m.e.super.Exec(context.Background(), `INSERT INTO organization_mcp_settings (organization_id, enabled, write_enabled, mode, allowed_operations)
		VALUES ($1, $2, $3, $4, $5) ON CONFLICT (organization_id) DO UPDATE SET enabled = $2, write_enabled = $3, mode = $4, allowed_operations = $5`,
		m.e.acme, enabled, write, mode, ops); err != nil {
		m.t.Fatal(err)
	}
}

// setPlatformPolicy saves the platform's MCP policy; it is removed again when the test ends.
func (m *mcpWorld) setPlatformPolicy(enabled, write bool) {
	m.t.Helper()
	ctx := context.Background()
	if _, err := m.e.super.Exec(ctx, `INSERT INTO platform_mcp_settings (enabled, write_enabled) VALUES ($1, $2)
		ON CONFLICT (singleton) DO UPDATE SET enabled = $1, write_enabled = $2, mode = 'all', allowed_operations = '{}'`, enabled, write); err != nil {
		m.t.Fatal(err)
	}
	m.t.Cleanup(func() {
		if _, err := m.e.super.Exec(ctx, "DELETE FROM platform_mcp_settings"); err != nil {
			m.t.Error(err)
		}
	})
}

// optIn sets the MCP write opt-in of the account behind an MCP access token.
func (m *mcpWorld) optIn(token string, on bool) {
	m.t.Helper()
	rec, ok := m.record(token)
	if !ok {
		m.t.Fatal("no MCP session record")
	}
	table := "admin_account"
	if rec.Kind == string(principal.KindPlatformAdmin) {
		table = "platform_admin"
	}
	at := "NULL"
	if on {
		at = "now()"
	}
	if _, err := m.e.super.Exec(context.Background(), "UPDATE "+table+" SET mcp_write_enabled_at = "+at+" WHERE id = $1", rec.AccountID); err != nil {
		m.t.Fatal(err)
	}
}

func (m *mcpWorld) call(token, method, path string, body any) result {
	m.t.Helper()
	return m.e.do(call{method: method, path: path, body: body, headers: bearer(token)})
}

func (m *mcpWorld) createGroup(token string) result {
	m.t.Helper()
	return m.call(token, http.MethodPost, "/api/v1/device-groups", map[string]any{"name": "mcp " + uuid.NewString()[:8]})
}

func (m *mcpWorld) access(token string) adminapi.McpAccess {
	m.t.Helper()
	r := m.call(token, http.MethodGet, "/api/v1/mcp/access", nil)
	if r.status != http.StatusOK {
		m.t.Fatalf("GET /api/v1/mcp/access: %d %s", r.status, r.body)
	}
	var a adminapi.McpAccess
	r.decode(m.t, &a)
	return a
}

// expectNoEvent fails when the request recorded an audit event.
func (e *env) expectNoEvent(name string, r result) {
	e.t.Helper()
	if got := e.events(r.header.Get(httpx.HeaderRequestID)); len(got) != 0 {
		e.t.Fatalf("%s recorded %v", name, got)
	}
}

// expectMCPEvent checks the one event of a request and that it carries the audit source mcp.
func (e *env) expectMCPEvent(r result, want string) {
	e.t.Helper()
	e.expectEvent(r, want)
	var source string
	if err := e.super.QueryRow(context.Background(), "SELECT source FROM action WHERE correlation_id = $1",
		r.header.Get(httpx.HeaderRequestID)).Scan(&source); err != nil {
		e.t.Fatal(err)
	}
	if source != "mcp" {
		e.t.Fatalf("event source %q, want mcp", source)
	}
}

func expectDetail(t *testing.T, name string, r result, detail string) {
	t.Helper()
	var p httpx.Problem
	r.decode(t, &p)
	if p.Detail != detail {
		t.Fatalf("%s: detail %q, want %q", name, p.Detail, detail)
	}
}

// TestMCPGuardBootstrap: without a saved policy, MCP sessions of both scopes may still call the bootstrap operations
// and nothing else (plan M14 §3.4 item 20 (b), (d)).
func TestMCPGuardBootstrap(t *testing.T) {
	m := newMCPWorld(t)
	if _, err := m.e.super.Exec(context.Background(), "DELETE FROM platform_mcp_settings"); err != nil {
		t.Fatal(err)
	}
	alice := m.mcpLogin(m.admins())
	for _, path := range []string{"/api/v1/me", "/api/v1/mcp/access", "/api/v1/mcp/catalog"} {
		if r := m.call(alice, http.MethodGet, path, nil); r.status != http.StatusOK {
			t.Fatalf("bootstrap %s: %d %s", path, r.status, r.body)
		}
	}
	if a := m.access(alice); a.Enabled || a.WriteEffective || a.AllowedOperations == nil || len(a.AllowedOperations) != 0 ||
		a.Channel != adminapi.McpAccessChannelMcp || a.Scope != adminapi.McpAccessScopeOrganization {
		t.Fatalf("access without a policy: %+v", a)
	}
	r := m.call(alice, http.MethodGet, "/api/v1/devices", nil)
	expectProblem(t, "devices without a policy", r, http.StatusForbidden, "mcp_disabled")
	m.e.expectNoEvent("devices without a policy", r)

	root := m.mcpLogin(organization.PlatformAdminsGroup())
	r = m.call(root, http.MethodGet, "/api/platform/v1/organizations", nil)
	expectProblem(t, "organizations without a platform policy", r, http.StatusForbidden, "mcp_disabled")
	if a := m.access(root); a.Enabled || len(a.AllowedOperations) != 0 || a.Scope != adminapi.McpAccessScopePlatform {
		t.Fatalf("platform access without a policy: %+v", a)
	}
}

// TestMCPGuardPortalAndTokens: portal sessions and API tokens pass the guard untouched, whatever the policy, and are
// never rate limited.
func TestMCPGuardPortalAndTokens(t *testing.T) {
	e := newEnv(t)
	alice := e.session(e.acme, principal.RoleOrgAdmin)
	token := e.createAPIToken("acme", alice, "guard", adminapi.ApiTokenRoleOrgAdmin)
	for i := range admin.MCPReadLimitPerMinute + 5 {
		if r := e.do(call{method: "GET", path: "/api/v1/devices", cookie: alice}); r.status != http.StatusOK {
			t.Fatalf("portal request %d: %d %s", i+1, r.status, r.body)
		}
		if r := e.do(call{method: "GET", path: "/api/v1/devices", headers: bearer(token.Secret)}); r.status != http.StatusOK {
			t.Fatalf("API token request %d: %d %s", i+1, r.status, r.body)
		}
	}
	if r := e.do(call{method: "POST", path: "/api/v1/device-groups", cookie: alice, body: map[string]any{"name": "portal"}}); r.status != http.StatusCreated {
		t.Fatalf("portal write: %d %s", r.status, r.body)
	}
	if r := e.do(call{method: "POST", path: "/api/v1/device-groups", headers: bearer(token.Secret), body: map[string]any{"name": "token"}}); r.status != http.StatusCreated {
		t.Fatalf("API token write: %d %s", r.status, r.body)
	}
}

// TestMCPGuardPolicy: the policy's enabled flag, tool selection and write switch and the account's opt-in, in the
// guard's order; refused writes record exactly one denied event with source mcp, refused reads none.
func TestMCPGuardPolicy(t *testing.T) {
	m := newMCPWorld(t)
	alice := m.mcpLogin(m.admins())

	m.setPolicy(false, true, "all")
	r := m.call(alice, http.MethodGet, "/api/v1/devices", nil)
	expectProblem(t, "disabled read", r, http.StatusForbidden, "mcp_disabled")
	m.e.expectNoEvent("disabled read", r)
	r = m.createGroup(alice)
	expectProblem(t, "disabled write", r, http.StatusForbidden, "mcp_disabled")
	m.e.expectMCPEvent(r, "device_group.created:denied:mcp_disabled")

	m.optIn(alice, true)
	m.setPolicy(true, true, "selected", "listDevices")
	r = m.call(alice, http.MethodGet, "/api/v1/device-groups", nil)
	expectProblem(t, "unselected read", r, http.StatusForbidden, "mcp_tool_not_allowed")
	m.e.expectNoEvent("unselected read", r)
	r = m.createGroup(alice)
	expectProblem(t, "unselected write", r, http.StatusForbidden, "mcp_tool_not_allowed")
	m.e.expectMCPEvent(r, "device_group.created:denied:mcp_tool_not_allowed")
	if r := m.call(alice, http.MethodGet, "/api/v1/devices", nil); r.status != http.StatusOK {
		t.Fatalf("selected read: %d %s", r.status, r.body)
	}

	m.setPolicy(true, false, "all")
	r = m.createGroup(alice)
	expectProblem(t, "policy without writes", r, http.StatusForbidden, "mcp_write_not_enabled")
	expectDetail(t, "policy without writes", r, "the MCP policy of this scope does not allow changes")
	m.e.expectMCPEvent(r, "device_group.created:denied:mcp_write_not_enabled")

	m.setPolicy(true, true, "all")
	m.optIn(alice, false)
	r = m.createGroup(alice)
	expectProblem(t, "account not opted in", r, http.StatusForbidden, "mcp_write_not_enabled")
	expectDetail(t, "account not opted in", r, "enable MCP write access for your account in the portal (account menu)")
	m.e.expectMCPEvent(r, "device_group.created:denied:mcp_write_not_enabled")

	m.optIn(alice, true)
	r = m.createGroup(alice)
	if r.status != http.StatusCreated {
		t.Fatalf("allowed write: %d %s", r.status, r.body)
	}
	m.e.expectMCPEvent(r, "device_group.created:success:")
}

// TestMCPGuardNotOffered: operations the MCP never offers are refused with mcp_tool_not_allowed before the role and
// step-up checks, with one denied event; a step-up the use case decides on (a Full profile) still answers
// step_up_required with the MCP detail.
func TestMCPGuardNotOffered(t *testing.T) {
	m := newMCPWorld(t)
	alice := m.mcpLogin(m.admins())
	m.setPolicy(true, true, "all")
	m.optIn(alice, true)

	device := m.e.insertDevice(m.e.acme, "guard-lock", "active")
	r := m.call(alice, http.MethodPost, "/api/v1/devices/"+device.String()+"/lock", map[string]any{"confirm_hostname": "guard-lock"})
	expectProblem(t, "lock", r, http.StatusForbidden, "mcp_tool_not_allowed")
	expectDetail(t, "lock", r, "this operation is not available through the MCP; use the portal")
	m.e.expectMCPEvent(r, "revocation.requested:denied:mcp_tool_not_allowed")

	r = m.call(alice, http.MethodPut, mcpSettingsPath, map[string]any{"enabled": true, "write_enabled": true, "mode": "all", "allowed_operations": []string{}})
	expectProblem(t, "policy change", r, http.StatusForbidden, "mcp_tool_not_allowed")
	m.e.expectMCPEvent(r, "organization.mcp_policy_changed:denied:mcp_tool_not_allowed")

	r = m.call(alice, http.MethodPost, "/api/v1/me/mcp-write/enable", nil)
	expectProblem(t, "own opt-in", r, http.StatusForbidden, "mcp_tool_not_allowed")
	m.e.expectMCPEvent(r, "admin.mcp_write_enabled:denied:mcp_tool_not_allowed")

	r = m.call(alice, http.MethodPost, "/api/v1/permission-profiles", map[string]any{"name": "mcp full", "class": "full"})
	expectProblem(t, "full profile", r, http.StatusForbidden, "step_up_required")
	if !strings.Contains(string(r.body), "MCP sessions") {
		t.Fatalf("full profile: detail does not name MCP sessions: %s", r.body)
	}
	m.e.expectMCPEvent(r, "permission_profile.created:denied:step_up_required")
}

// TestMCPGuardRateLimit: 120 reads per account and minute, then 429 rate_limited with Retry-After; writes have their
// own budget of 30; a refused write is recorded once.
func TestMCPGuardRateLimit(t *testing.T) {
	m := newMCPWorld(t)
	alice := m.mcpLogin(m.admins())
	m.setPolicy(true, true, "all")
	m.optIn(alice, true)

	for i := range admin.MCPReadLimitPerMinute {
		if r := m.call(alice, http.MethodGet, "/api/v1/mcp/access", nil); r.status != http.StatusOK {
			t.Fatalf("read %d: %d %s", i+1, r.status, r.body)
		}
	}
	r := m.call(alice, http.MethodGet, "/api/v1/mcp/access", nil)
	expectProblem(t, "read 121", r, http.StatusTooManyRequests, "rate_limited")
	if s, err := strconv.Atoi(r.header.Get("Retry-After")); err != nil || s < 1 || s > 60 {
		t.Fatalf("Retry-After %q", r.header.Get("Retry-After"))
	}
	r = authCall(m.e, call{method: "GET", path: "/api/v1/devices", headers: bearer(alice)})
	expectProblem(t, "policy-checked read beyond the budget", r, http.StatusTooManyRequests, "rate_limited")

	// Another account of the same organization has its own budget.
	if r := m.call(m.mcpLogin(m.admins()), http.MethodGet, "/api/v1/devices", nil); r.status != http.StatusOK {
		t.Fatalf("other account: %d %s", r.status, r.body)
	}

	for i := range admin.MCPWriteLimitPerMinute {
		if r := m.createGroup(alice); r.status != http.StatusCreated {
			t.Fatalf("write %d: %d %s", i+1, r.status, r.body)
		}
	}
	r = authCall(m.e, call{method: "POST", path: "/api/v1/device-groups", body: map[string]any{"name": "one too many"},
		headers: map[string]string{"Authorization": "Bearer " + alice, "X-Paddock-CSRF": "1"}})
	expectProblem(t, "write 31", r, http.StatusTooManyRequests, "rate_limited")
	if r.header.Get("Retry-After") == "" {
		t.Fatal("write 31 without Retry-After")
	}
	m.e.expectMCPEvent(r, "device_group.created:denied:rate_limited")
}

// TestMCPAccessAPI: GET /api/v1/mcp/access per scope, channel, opt-in and role (plan M14 §3.4 item 19).
func TestMCPAccessAPI(t *testing.T) {
	m := newMCPWorld(t)
	m.setPolicy(true, true, "all")
	alice := m.mcpLogin(m.admins())

	a := m.access(alice)
	if !a.Enabled || !a.WriteEnabled || a.WriteOptedIn || a.WriteEffective || a.CatalogVersion != mcpcatalog.Version ||
		!slices.Contains(a.AllowedOperations, "listDevices") || slices.Contains(a.AllowedOperations, "createDeviceGroup") ||
		slices.Contains(a.AllowedOperations, "lockDevice") || slices.Contains(a.AllowedOperations, "listOrganizations") {
		t.Fatalf("alice without opt-in: %+v", a)
	}
	m.optIn(alice, true)
	if a := m.access(alice); !a.WriteOptedIn || !a.WriteEffective || !slices.Contains(a.AllowedOperations, "createDeviceGroup") ||
		slices.Contains(a.AllowedOperations, "lockDevice") {
		t.Fatalf("alice after the opt-in: %+v", a)
	}
	for _, name := range m.access(alice).AllowedOperations {
		if tool, _ := mcpcatalog.ByName(name); !tool.Expose || tool.StepUp || tool.Scope == mcpcatalog.ScopePlatform {
			t.Fatalf("alice is offered %+v", tool)
		}
	}

	auditor := m.mcpLogin(organization.RoleGroup(m.slug, organization.GroupAuditors))
	if a := m.access(auditor); a.WriteEffective || hasWriteTool(a.AllowedOperations) || !slices.Contains(a.AllowedOperations, "listDevices") {
		t.Fatalf("auditor: %+v", a)
	}

	// An operator opted in is offered no write tool reserved to other roles.
	operator := m.mcpLogin(organization.RoleGroup(m.slug, organization.GroupOperators))
	m.optIn(operator, true)
	op := m.access(operator)
	if !op.WriteEffective || !hasWriteTool(op.AllowedOperations) {
		t.Fatalf("operator: %+v", op)
	}
	for _, name := range op.AllowedOperations {
		tool, _ := mcpcatalog.ByName(name)
		if roles, ok := admin.PrivilegedRoles(tool.Pattern); tool.Class == mcpcatalog.ClassWrite && ok && len(roles) > 0 &&
			!slices.Contains(roles, principal.RoleOrgOperator) {
			t.Fatalf("operator is offered %s, reserved to %v", name, roles)
		}
	}

	m.setPolicy(true, true, "selected", "listDevices", "createDeviceGroup")
	if a := m.access(alice); !slices.Equal(a.AllowedOperations, []string{"createDeviceGroup", "listDevices"}) {
		t.Fatalf("selected: %+v", a)
	}

	m.setPlatformPolicy(true, false)
	root := m.mcpLogin(organization.PlatformAdminsGroup())
	if a := m.access(root); a.Scope != adminapi.McpAccessScopePlatform || !slices.Contains(a.AllowedOperations, "listOrganizations") ||
		slices.Contains(a.AllowedOperations, "listDevices") || hasWriteTool(a.AllowedOperations) {
		t.Fatalf("platform administrator: %+v", a)
	}

	portal := m.e.session(m.e.acme, principal.RoleOrgAdmin)
	r := m.e.do(call{method: "GET", path: "/api/v1/mcp/access", cookie: portal})
	var pa adminapi.McpAccess
	r.decode(t, &pa)
	if r.status != http.StatusOK || pa.Channel != adminapi.McpAccessChannelPortal || pa.WriteOptedIn {
		t.Fatalf("portal: %d %s", r.status, r.body)
	}
	if r := m.e.do(call{method: "POST", path: "/api/v1/me/mcp-write/enable", cookie: m.e.steppedUp(portal, time.Now())}); r.status != http.StatusOK {
		t.Fatalf("portal opt-in: %d %s", r.status, r.body)
	}
	r = m.e.do(call{method: "GET", path: "/api/v1/mcp/access", cookie: portal})
	pa = adminapi.McpAccess{}
	r.decode(t, &pa)
	if !pa.WriteOptedIn || !pa.WriteEffective {
		t.Fatalf("portal after the opt-in: %s", r.body)
	}

	token := m.e.createAPIToken("acme", portal, "access", adminapi.ApiTokenRoleOrgAdmin)
	r = m.e.do(call{method: "GET", path: "/api/v1/mcp/access", headers: bearer(token.Secret)})
	pa = adminapi.McpAccess{}
	r.decode(t, &pa)
	if r.status != http.StatusOK || pa.Channel != adminapi.McpAccessChannelApi || pa.WriteOptedIn {
		t.Fatalf("API token: %d %s", r.status, r.body)
	}
}

func hasWriteTool(names []string) bool {
	return slices.ContainsFunc(names, func(n string) bool {
		t, _ := mcpcatalog.ByName(n)
		return t.Class == mcpcatalog.ClassWrite
	})
}

// TestMCPCatalogAPI: GET /api/v1/mcp/catalog answers every tool of the shared catalog with its flags.
func TestMCPCatalogAPI(t *testing.T) {
	e := newEnv(t)
	r := e.do(call{method: "GET", path: "/api/v1/mcp/catalog", cookie: e.session(e.acme, principal.RoleOrgAuditor)})
	var c adminapi.McpCatalog
	r.decode(t, &c)
	tools := mcpcatalog.Tools()
	if r.status != http.StatusOK || c.Version != mcpcatalog.Version || len(c.Tools) != len(tools) {
		t.Fatalf("catalog: %d, version %s, %d tools", r.status, c.Version, len(c.Tools))
	}
	for i, want := range tools {
		got := c.Tools[i]
		if got.OperationId != want.Name || got.Method != want.Method || got.Path != want.Path || got.Tag != want.Tag ||
			string(got.Scope) != string(want.Scope) || string(got.Class) != string(want.Class) || got.StepUp != want.StepUp ||
			got.Destructive != want.Destructive || got.Exposed != want.Expose || got.Summary != want.Summary {
			t.Fatalf("tool %d: %+v, want %+v", i, got, want)
		}
	}
	if tool, _ := mcpcatalog.ByName("getMcpAccess"); !tool.Bootstrap || tool.Expose {
		t.Fatalf("getMcpAccess: %+v", tool)
	}
}
