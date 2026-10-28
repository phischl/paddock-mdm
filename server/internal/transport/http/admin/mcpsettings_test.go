package admin_test

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
	"github.com/phischl/paddock-mdm/server/internal/platform/httpx"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/transport/http/admin/adminapi"
)

const (
	mcpSettingsPath         = "/api/v1/settings/mcp"
	platformMCPSettingsPath = "/api/platform/v1/settings/mcp"
)

// eventOf returns the organization and the params of the one event recorded for a request.
func (e *env) eventOf(r result) (uuid.UUID, map[string]any) {
	e.t.Helper()
	var org uuid.UUID
	var params map[string]any
	if err := e.super.QueryRow(context.Background(), "SELECT organization_id, coalesce(params, '{}'::jsonb) FROM action WHERE correlation_id = $1",
		r.header.Get(httpx.HeaderRequestID)).Scan(&org, &params); err != nil {
		e.t.Fatal(err)
	}
	return org, params
}

func (e *env) mcpSettings(path string, c *http.Cookie) adminapi.McpSettings {
	e.t.Helper()
	r := e.do(call{method: "GET", path: path, cookie: c})
	if r.status != http.StatusOK {
		e.t.Fatalf("GET %s: %d %s", path, r.status, r.body)
	}
	if !strings.Contains(string(r.body), `"updated_at":`) || !strings.Contains(string(r.body), `"updated_by":`) {
		e.t.Fatalf("GET %s omits updated_at or updated_by: %s", path, r.body)
	}
	var s adminapi.McpSettings
	r.decode(e.t, &s)
	return s
}

func isDefaultMCPPolicy(s adminapi.McpSettings) bool {
	return !s.Enabled && !s.WriteEnabled && s.Mode == adminapi.McpSettingsModeAll && s.AllowedOperations != nil &&
		len(s.AllowedOperations) == 0 && s.UpdatedAt == nil && s.UpdatedBy == nil
}

// expectInvalidPolicy checks one PUT refused with 400 invalid_request whose detail names detail.
func (e *env) expectInvalidPolicy(name string, r result, detail string) {
	e.t.Helper()
	expectProblem(e.t, name, r, http.StatusBadRequest, "invalid_request")
	if !strings.Contains(string(r.body), detail) {
		e.t.Fatalf("%s: detail does not name %s: %s", name, detail, r.body)
	}
}

// TestMCPSettingsAPI: GET answers the default (MCP off) without a saved policy for every organization role; PUT needs
// org_admin and a step-up, validates the policy, upserts it and records organization.mcp_policy_changed once per
// attempt (plan M14 §3.4 item 17).
func TestMCPSettingsAPI(t *testing.T) {
	e := newEnv(t)
	alice := e.session(e.acme, principal.RoleOrgAdmin)
	for _, role := range []principal.Role{principal.RoleOrgAdmin, principal.RoleOrgOperator, principal.RoleOrgAuditor} {
		if s := e.mcpSettings(mcpSettingsPath, e.session(e.acme, role)); !isDefaultMCPPolicy(s) {
			t.Fatalf("%s without a saved policy: %+v", role, s)
		}
	}
	put := func(c *http.Cookie, body map[string]any) result {
		return e.do(call{method: "PUT", path: mcpSettingsPath, cookie: c, body: body})
	}
	policy := func(mode string, ops ...string) map[string]any {
		if ops == nil {
			ops = []string{}
		}
		return map[string]any{"enabled": true, "write_enabled": false, "mode": mode, "allowed_operations": ops}
	}
	valid := policy("selected", "listDevices", "createDeviceGroup")

	r := put(alice, valid)
	expectProblem(t, "without a step-up", r, http.StatusForbidden, "step_up_required")
	e.expectEvent(r, "organization.mcp_policy_changed:denied:step_up_required")

	r = put(e.steppedUp(e.session(e.acme, principal.RoleOrgOperator), time.Now()), valid)
	expectProblem(t, "operator", r, http.StatusForbidden, "forbidden")
	e.expectEvent(r, "organization.mcp_policy_changed:denied:forbidden")

	stepped := e.steppedUp(alice, time.Now())
	many := make([]string, 501)
	for i := range many {
		many[i] = fmt.Sprintf("op%d", i)
	}
	for _, tc := range []struct {
		name   string
		body   map[string]any
		detail string
	}{
		{"mode all with operations", policy("all", "listDevices"), "mode all"},
		{"mode selected without operations", policy("selected"), "at least one"},
		{"unknown id", policy("selected", "listDevices", "noSuchOperation"), "noSuchOperation"},
		{"step-up id", policy("selected", "lockDevice"), "lockDevice"},
		{"501 ids", policy("selected", many...), "500"},
	} {
		r := e.do(call{method: "PUT", path: mcpSettingsPath, cookie: stepped, body: tc.body, skipReqCheck: tc.name == "501 ids"})
		e.expectInvalidPolicy(tc.name, r, tc.detail)
		e.expectEvent(r, "organization.mcp_policy_changed:failure:invalid_request")
	}
	// A duplicate violates uniqueItems of the contract, so the request check is skipped; the server names the id.
	r = e.do(call{method: "PUT", path: mcpSettingsPath, cookie: stepped, body: policy("selected", "listDevices", "listDevices"), skipReqCheck: true})
	e.expectInvalidPolicy("duplicate", r, `\"listDevices\" is listed twice`)
	e.expectEvent(r, "organization.mcp_policy_changed:failure:invalid_request")
	if s := e.mcpSettings(mcpSettingsPath, alice); !isDefaultMCPPolicy(s) {
		t.Fatalf("a refused PUT stored %+v", s)
	}

	r = put(stepped, valid)
	var s adminapi.McpSettings
	r.decode(t, &s)
	if r.status != http.StatusOK || !s.Enabled || s.WriteEnabled || s.Mode != adminapi.McpSettingsModeSelected ||
		!slices.Equal(s.AllowedOperations, []string{"listDevices", "createDeviceGroup"}) || s.UpdatedAt == nil || s.UpdatedBy == nil {
		t.Fatalf("PUT: %d %s", r.status, r.body)
	}
	e.expectEvent(r, "organization.mcp_policy_changed:success:")
	org, params := e.eventOf(r)
	if org != e.acme || params["enabled"] != true || params["write_enabled"] != false || params["mode"] != "selected" ||
		params["allowed_count"] != float64(2) {
		t.Fatalf("event in %s with params %v", org, params)
	}
	if got := e.mcpSettings(mcpSettingsPath, e.session(e.acme, principal.RoleOrgAuditor)); !got.Enabled || got.UpdatedBy == nil || *got.UpdatedBy != *s.UpdatedBy {
		t.Fatalf("GET after PUT: %+v", got)
	}

	// The upsert replaces the row; another organization keeps its default.
	r = put(stepped, map[string]any{"enabled": false, "write_enabled": true, "mode": "all", "allowed_operations": []string{}})
	if r.status != http.StatusOK {
		t.Fatalf("second PUT: %d %s", r.status, r.body)
	}
	if got := e.mcpSettings(mcpSettingsPath, alice); got.Enabled || !got.WriteEnabled || got.Mode != adminapi.McpSettingsModeAll || len(got.AllowedOperations) != 0 {
		t.Fatalf("after the second PUT: %+v", got)
	}
	if got := e.mcpSettings(mcpSettingsPath, e.session(e.globex, principal.RoleOrgAdmin)); !isDefaultMCPPolicy(got) {
		t.Fatalf("globex sees %+v", got)
	}

	if r := e.do(call{method: "GET", path: mcpSettingsPath, cookie: e.platformSession()}); r.status != http.StatusForbidden {
		t.Fatalf("GET by a platform administrator: %d %s", r.status, r.body)
	}
}

// TestPlatformMCPSettingsAPI: the platform policy behaves like the organization's for platform_admin and records
// platform.mcp_policy_changed in the platform pseudo-organization; organization administrators are forbidden.
func TestPlatformMCPSettingsAPI(t *testing.T) {
	e := newEnv(t)
	if _, err := e.super.Exec(context.Background(), "DELETE FROM platform_mcp_settings"); err != nil {
		t.Fatal(err)
	}
	root := e.platformSession()
	alice := e.session(e.acme, principal.RoleOrgAdmin)
	if s := e.mcpSettings(platformMCPSettingsPath, root); !isDefaultMCPPolicy(s) {
		t.Fatalf("without a saved policy: %+v", s)
	}
	r := e.do(call{method: "GET", path: platformMCPSettingsPath, cookie: alice})
	expectProblem(t, "GET by an organization administrator", r, http.StatusForbidden, "forbidden")

	valid := map[string]any{"enabled": true, "write_enabled": true, "mode": "selected", "allowed_operations": []string{"listOrganizations"}}
	put := func(c *http.Cookie, body map[string]any) result {
		return e.do(call{method: "PUT", path: platformMCPSettingsPath, cookie: c, body: body})
	}
	r = put(root, valid)
	expectProblem(t, "without a step-up", r, http.StatusForbidden, "step_up_required")
	e.expectEvent(r, "platform.mcp_policy_changed:denied:step_up_required")

	r = put(e.steppedUp(alice, time.Now()), valid)
	expectProblem(t, "organization administrator", r, http.StatusForbidden, "forbidden")
	e.expectEvent(r, "platform.mcp_policy_changed:denied:forbidden")

	stepped := e.steppedUp(root, time.Now())
	r = put(stepped, map[string]any{"enabled": true, "write_enabled": false, "mode": "selected", "allowed_operations": []string{"lockDevice"}})
	e.expectInvalidPolicy("step-up id", r, "lockDevice")
	e.expectEvent(r, "platform.mcp_policy_changed:failure:invalid_request")

	r = put(stepped, valid)
	var s adminapi.McpSettings
	r.decode(t, &s)
	if r.status != http.StatusOK || !s.Enabled || !s.WriteEnabled || !slices.Equal(s.AllowedOperations, []string{"listOrganizations"}) ||
		s.UpdatedAt == nil || s.UpdatedBy == nil {
		t.Fatalf("PUT: %d %s", r.status, r.body)
	}
	e.expectEvent(r, "platform.mcp_policy_changed:success:")
	org, params := e.eventOf(r)
	if org != audit.PlatformOrganizationID || params["mode"] != "selected" || params["allowed_count"] != float64(1) ||
		params["write_enabled"] != true {
		t.Fatalf("event in %s with params %v", org, params)
	}
	if got := e.mcpSettings(platformMCPSettingsPath, root); !got.Enabled || got.UpdatedBy == nil || *got.UpdatedBy != *s.UpdatedBy {
		t.Fatalf("GET after PUT: %+v", got)
	}
	if got := e.mcpSettings(mcpSettingsPath, alice); !isDefaultMCPPolicy(got) {
		t.Fatalf("the platform policy leaked into acme: %+v", got)
	}
}

// TestMCPWriteOptIn: an administrator opts in with a step-up and out without one, each attempt recorded once with
// the param role; auditors, API tokens and MCP sessions are forbidden (plan M14 §3.4 item 18).
func TestMCPWriteOptIn(t *testing.T) {
	m := newMCPWorld(t)
	e := m.e
	const enablePath, disablePath = "/api/v1/me/mcp-write/enable", "/api/v1/me/mcp-write/disable"
	post := func(path string, c *http.Cookie) result {
		return e.do(call{method: "POST", path: path, cookie: c})
	}
	me := func(name string, r result, want bool) {
		t.Helper()
		var got adminapi.Me
		r.decode(t, &got)
		if r.status != http.StatusOK || got.McpWriteEnabled != want {
			t.Fatalf("%s: %d %s, want mcp_write_enabled %v", name, r.status, r.body, want)
		}
	}

	for _, tc := range []struct {
		role   principal.Role
		cookie *http.Cookie
		org    uuid.UUID
	}{
		{principal.RoleOrgAdmin, e.session(e.acme, principal.RoleOrgAdmin), e.acme},
		{principal.RoleOrgOperator, e.session(e.acme, principal.RoleOrgOperator), e.acme},
		{principal.RolePlatform, e.platformSession(), audit.PlatformOrganizationID},
	} {
		r := post(enablePath, tc.cookie)
		expectProblem(t, string(tc.role)+" without a step-up", r, http.StatusForbidden, "step_up_required")
		e.expectEvent(r, "admin.mcp_write_enabled:denied:step_up_required")

		r = post(enablePath, e.steppedUp(tc.cookie, time.Now()))
		me(string(tc.role)+" enable", r, true)
		e.expectEvent(r, "admin.mcp_write_enabled:success:")
		if org, params := e.eventOf(r); org != tc.org || params["role"] != string(tc.role) {
			t.Fatalf("%s: event in %s with params %v", tc.role, org, params)
		}
		me(string(tc.role)+" GET /api/v1/me", e.do(call{method: "GET", path: "/api/v1/me", cookie: tc.cookie}), true)

		r = post(disablePath, tc.cookie)
		me(string(tc.role)+" disable", r, false)
		e.expectEvent(r, "admin.mcp_write_disabled:success:")
		if org, params := e.eventOf(r); org != tc.org || params["role"] != string(tc.role) {
			t.Fatalf("%s: event in %s with params %v", tc.role, org, params)
		}
		me(string(tc.role)+" GET /api/v1/me after disable", e.do(call{method: "GET", path: "/api/v1/me", cookie: tc.cookie}), false)
	}

	// AccountState, which the MCP bearer re-reads on every request, follows the opt-in.
	operator := principal.Principal{Kind: principal.KindAdmin, ID: uuid.Must(uuid.NewV7()), Subject: uuid.NewString(),
		Display: "op@test", Role: principal.RoleOrgOperator, OrganizationID: e.acme}
	if _, err := e.super.Exec(context.Background(), `INSERT INTO admin_account (id, organization_id, authentik_sub, username, display_name, role)
		VALUES ($1, $2, $3, $4, $4, 'org_operator')`, operator.ID, e.acme, operator.Subject, operator.Display); err != nil {
		t.Fatal(err)
	}
	opCookie := e.cookie(operator)
	me("operator enable", post(enablePath, e.steppedUp(opCookie, time.Now())), true)
	if st, err := e.accounts.AccountState(context.Background(), operator); err != nil || !st.MCPWriteEnabled {
		t.Fatalf("AccountState after enable: %+v %v", st, err)
	}
	me("operator disable", post(disablePath, opCookie), false)
	if st, err := e.accounts.AccountState(context.Background(), operator); err != nil || st.MCPWriteEnabled {
		t.Fatalf("AccountState after disable: %+v %v", st, err)
	}

	auditor := e.session(e.acme, principal.RoleOrgAuditor)
	for _, path := range []string{enablePath, disablePath} {
		r := post(path, e.steppedUp(auditor, time.Now()))
		expectProblem(t, "auditor "+path, r, http.StatusForbidden, "forbidden")
		e.expectEvent(r, map[string]string{enablePath: "admin.mcp_write_enabled", disablePath: "admin.mcp_write_disabled"}[path]+":denied:forbidden")
	}

	token := e.createAPIToken("acme", e.steppedUp(e.session(e.acme, principal.RoleOrgAdmin), time.Now()), "mcp-write", adminapi.ApiTokenRoleOrgAdmin)
	for _, path := range []string{enablePath, disablePath} {
		r := e.do(call{method: "POST", path: path, headers: bearer(token.Secret)})
		expectProblem(t, "API token "+path, r, http.StatusForbidden, "forbidden")
		e.expectEvent(r, map[string]string{enablePath: "admin.mcp_write_enabled", disablePath: "admin.mcp_write_disabled"}[path]+":denied:forbidden")
	}

	access, r := m.login(m.user(m.admins()), nil)
	if r.status != http.StatusNoContent {
		t.Fatalf("MCP login: %d %s", r.status, r.body)
	}
	for _, path := range []string{enablePath, disablePath} {
		r := e.do(call{method: "POST", path: path, headers: bearer(access)})
		expectProblem(t, "MCP session "+path, r, http.StatusForbidden, "forbidden")
		e.expectEvent(r, map[string]string{enablePath: "admin.mcp_write_enabled", disablePath: "admin.mcp_write_disabled"}[path]+":denied:forbidden")
	}
	var got adminapi.Me
	m.me(access).decode(t, &got)
	if got.McpWriteEnabled {
		t.Fatal("an MCP session opted its account in")
	}

	// A request rejected before the handler (no CSRF header) is recorded in the caller's own scope.
	r = e.do(call{method: "POST", path: enablePath, cookie: e.steppedUp(e.platformSession(), time.Now()), noCSRF: true, skipReqCheck: true})
	expectProblem(t, "platform administrator without CSRF", r, http.StatusForbidden, "csrf_missing")
	e.expectEvent(r, "admin.mcp_write_enabled:denied:csrf_missing")
	if org, _ := e.eventOf(r); org != audit.PlatformOrganizationID {
		t.Fatalf("rejected request recorded in %s", org)
	}
}
