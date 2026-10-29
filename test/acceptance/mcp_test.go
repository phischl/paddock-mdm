package acceptance

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/pkg/mcpcatalog"
	"github.com/phischl/paddock-mdm/test/acceptance/internal/authflow"
	"github.com/phischl/paddock-mdm/test/acceptance/internal/env"
)

// mcpPortalOnly are step-up operations an MCP session never gets as tools (plan M14 §9.3 M5).
var mcpPortalOnly = []string{"lockDevice", "destroyDevice", "revealDeviceLocalAdmin", "uninstallDevice", "endAllSessions"}

// mcpLoginWhere selects the admin.login events of an MCP session of the account $1 since since: first logins
// (renewal false) or renewals.
func mcpLoginWhere(since time.Time, renewal bool) string {
	cond := "coalesce(params->>'renewal', 'false') <> 'true'"
	if renewal {
		cond = "params->>'renewal' = 'true'"
	}
	return fmt.Sprintf("code = 'admin.login' AND source = 'mcp' AND params->>'channel' = 'mcp' AND actor->>'id' = $1 "+
		"AND %s AND occurred_at >= '%s'", cond, since.UTC().Format(time.RFC3339Nano))
}

// TestMCP is the acceptance gate of plan M14 §9.3 (ADR 0044): the MCP login through Authentik with `paddockctl mcp
// login` (L1–L4) and the MCP session's reach (M0–M10) — the fail-closed default, reads with each role, writes only
// with the scope's policy and the administrator's own opt-in, the scope policy, no step-up, organization isolation,
// exactly one audit event per action, no API tokens, the rate limit and the audit display. The login is driven
// headlessly; the stdio server is driven as the MCP client paddock-gate/1.0; direct API calls use the access token of
// the session file. Every policy and opt-in is written back and every session signed out when the gate ends.
func TestMCP(t *testing.T) {
	alice := login(t, env.Alice)
	root := login(t, env.PlatformAdmin)
	acme := orgOf(t, alice)
	aliceID, rootID := whoami(t, alice).ID, whoami(t, root).ID
	idx := auditIndex(t)
	restoreMCPState(t, acme, aliceID, rootID)
	// The workstations of the two dev administrators live for the whole gate; L1 signs them in.
	aliceCLI, rootCLI := newMCPCLI(t), newMCPCLI(t)
	var groupID string

	t.Run("L1 login", func(t *testing.T) {
		since := time.Now().Add(-2 * time.Second)
		if line := aliceCLI.signIn(t, mcpDevIdentity(t, env.Alice, false)); !strings.HasSuffix(line, "(org_admin, acme)") {
			t.Fatalf("login line %q, want … (org_admin, acme)", line)
		}
		var me struct {
			ID, Role, Channel string
		}
		res := call(t, aliceCLI.portal(t), http.MethodGet, "/api/v1/me", nil)
		expectStatus(t, res, http.StatusOK, "")
		if err := res.JSON(&me); err != nil || me.ID != aliceID || me.Channel != "mcp" || me.Role != "org_admin" {
			t.Fatalf("GET /api/v1/me of alice's MCP session: %s (%v)", res.Body, err)
		}
		expectOneIndexEvent(t, idx, acme, mcpLoginWhere(since, false), aliceID, "admin.login", "success", auditPollTimeout)

		if line := rootCLI.signIn(t, mcpDevIdentity(t, env.PlatformAdmin, true)); !strings.HasSuffix(line, "(platform_admin, platform)") {
			t.Fatalf("login line %q, want … (platform_admin, platform)", line)
		}
		res = call(t, rootCLI.portal(t), http.MethodGet, "/api/v1/me", nil)
		expectStatus(t, res, http.StatusOK, "")
		if err := res.JSON(&me); err != nil || me.Role != "platform_admin" || me.Channel != "mcp" {
			t.Fatalf("GET /api/v1/me of the platform MCP session: %s (%v)", res.Body, err)
		}

		// A member of the organization's root group only: Authentik admits the identity, Paddock finds no role.
		user, pw := tempUser(t, "mcp-norole", env.RootGroup("acme"))
		norole := newMCPCLI(t)
		r := norole.login(t, mcpIdentity{username: user, password: pw, totp: &authflow.TOTP{}})
		if r.code != 1 || !strings.Contains(r.stderr, "no_role") {
			t.Fatalf("login without a role: %+v, want exit 1 naming no_role", r)
		}
		norole.signedOut(t)
		ev := expectOneIndexEvent(t, idx, platformOrg, "code = 'admin.login' AND actor->>'display' = $1", user,
			"admin.login", "denied", auditPollTimeout)
		if ev.Params["channel"] != "mcp" || ev.Params["denial_reason"] != "no_role" {
			t.Fatalf("denied MCP login params %v, want channel mcp and denial_reason no_role", ev.Params)
		}
	})

	t.Run("L2 expired token", func(t *testing.T) {
		s := aliceCLI.session(t)
		if left := time.Until(s.ExpiresAt); left > 2*time.Minute {
			t.Fatalf("the access token lives %s more; the development overlay gives paddock-mcp one-minute tokens", left)
		}
		time.Sleep(time.Until(s.ExpiresAt) + 2*time.Second)
		expectStatus(t, call(t, tokenPortal(t, s.AccessToken), http.MethodGet, "/api/v1/me", nil), http.StatusUnauthorized, "unauthenticated")
		since := time.Now().Add(-2 * time.Second)
		if r := aliceCLI.run(t, nil, "mcp", "tools", "-o", "json"); r.code != 0 {
			t.Fatalf("paddockctl mcp tools with an expired access token: %+v", r)
		}
		renewed := aliceCLI.session(t)
		if renewed.AccessToken == s.AccessToken || !renewed.ExpiresAt.After(time.Now()) {
			t.Fatalf("session file not renewed: expires %s", renewed.ExpiresAt)
		}
		expectOneIndexEvent(t, idx, acme, mcpLoginWhere(since, true), aliceID, "admin.login", "success", auditPollTimeout)
	})

	t.Run("M0 off by default", func(t *testing.T) {
		clearMCPPolicies(t, acme)
		res := call(t, alice, http.MethodGet, "/api/v1/settings/mcp", nil)
		expectStatus(t, res, http.StatusOK, "")
		var policy struct {
			Enabled   bool    `json:"enabled"`
			UpdatedAt *string `json:"updated_at"`
		}
		if err := res.JSON(&policy); err != nil || policy.Enabled || policy.UpdatedAt != nil {
			t.Fatalf("policy without a saved row: %s (%v), want enabled false and no updated_at", res.Body, err)
		}
		mp := aliceCLI.portal(t)
		expectStatus(t, call(t, mp, http.MethodGet, "/api/v1/devices", nil), http.StatusForbidden, "mcp_disabled")
		res = call(t, mp, http.MethodPost, "/api/v1/device-groups", map[string]string{"name": uniqueName("mcp m0")})
		expectMCPRefusal(t, alice, res, http.StatusForbidden, "mcp_disabled", "device_group.created")
		if r := aliceCLI.run(t, nil, "mcp", "tools", "-o", "json"); r.code != 0 || strings.TrimSpace(r.stdout) != "[]" {
			t.Fatalf("paddockctl mcp tools with the MCP off: %+v, want an empty list", r)
		}
		srv := aliceCLI.serve(t)
		if tools := srv.toolNames(t); len(tools) != 0 {
			t.Fatalf("tools/list with the MCP off: %v", tools)
		}
		if stderr := srv.close(t); !strings.Contains(stderr, "the MCP is switched off for this scope") {
			t.Fatalf("paddockctl mcp stderr %q, want the switched-off hint", stderr)
		}
		expectStatus(t, call(t, rootCLI.portal(t), http.MethodGet, "/api/platform/v1/organizations", nil), http.StatusForbidden, "mcp_disabled")
	})

	t.Run("M1 read with each role", func(t *testing.T) {
		res := putMCPPolicy(t, alice, env.Alice, "/api/v1/settings/mcp", mcpPolicy(true, true))
		expectOneEvent(t, alice, res.RequestID, "organization.mcp_policy_changed", "success")
		res = putMCPPolicy(t, root, env.PlatformAdmin, "/api/platform/v1/settings/mcp", mcpPolicy(true, true))
		expectOneIndexEvent(t, idx, platformOrg, "correlation_id = $1", res.RequestID, "platform.mcp_policy_changed", "success", auditPollTimeout)

		operator := newMCPCLI(t)
		operator.signIn(t, mcpTempIdentity(mfaTempUser(t, "mcp-op", env.RoleGroup("acme", "operators"))))
		auditor := newMCPCLI(t)
		auditor.signIn(t, mcpTempIdentity(mfaTempUser(t, "mcp-aud", env.RoleGroup("acme", "auditors"))))
		for name, c := range map[string]*mcpCLI{"org_admin": aliceCLI, "org_operator": operator, "org_auditor": auditor} {
			srv := c.serve(t)
			tools := srv.toolNames(t)
			if !hasTool(tools, "listDevices") || !hasTool(tools, "getMe") {
				t.Fatalf("%s: tools/list %v lacks listDevices or getMe", name, tools)
			}
			r := srv.call(t, "listDevices", nil)
			if r.IsError || r.Structured.Status != http.StatusOK || r.Structured.Notice != mcpcatalog.Notice || len(r.Content) == 0 {
				t.Fatalf("%s: listDevices: %+v", name, r)
			}
			srv.close(t)
		}
		srv := rootCLI.serve(t)
		tools := srv.toolNames(t)
		if !hasTool(tools, "listOrganizations") || hasTool(tools, "listDevices") {
			t.Fatalf("platform tools/list %v: want listOrganizations and no listDevices", tools)
		}
		if r := srv.call(t, "listOrganizations", nil); r.IsError || r.Structured.Status != http.StatusOK {
			t.Fatalf("listOrganizations: %+v", r)
		}
	})

	t.Run("M2 write refused without opt-in", func(t *testing.T) {
		expectStatus(t, call(t, alice, http.MethodPost, "/api/v1/me/mcp-write/disable", nil), http.StatusOK, "")
		srv := aliceCLI.serve(t)
		if !hasTool(srv.toolNames(t), "listDevices") {
			t.Fatal("tools/list without the opt-in lacks listDevices")
		}
		for _, tool := range srv.tools(t) {
			if !tool.Annotations.ReadOnlyHint {
				t.Fatalf("tools/list without the opt-in offers the write tool %s", tool.Name)
			}
		}
		res := call(t, aliceCLI.portal(t), http.MethodPost, "/api/v1/device-groups", map[string]string{"name": uniqueName("mcp m2")})
		expectMCPRefusal(t, alice, res, http.StatusForbidden, "mcp_write_not_enabled", "device_group.created")
	})

	t.Run("M3 write allowed with opt-in", func(t *testing.T) {
		freshStepUp(t, alice, env.Alice)
		res := call(t, alice, http.MethodPost, "/api/v1/me/mcp-write/enable", nil)
		expectStatus(t, res, http.StatusOK, "")
		expectOneEvent(t, alice, res.RequestID, "admin.mcp_write_enabled", "success")

		srv := aliceCLI.serve(t)
		var create, remove *mcpListedTool
		tools := srv.tools(t)
		for i := range tools {
			switch tools[i].Name {
			case "createDeviceGroup":
				create = &tools[i]
			case "deleteDeviceGroup":
				remove = &tools[i]
			}
		}
		if create == nil || remove == nil || remove.Annotations.DestructiveHint == nil || !*remove.Annotations.DestructiveHint {
			t.Fatalf("tools/list with the opt-in: createDeviceGroup %v, deleteDeviceGroup %v (want destructiveHint true)", create, remove)
		}
		r := srv.call(t, "createDeviceGroup", map[string]any{"body": map[string]string{"name": uniqueName("mcp m3")}})
		var group struct {
			ID string `json:"id"`
		}
		if r.IsError || r.Structured.Status != http.StatusCreated || json.Unmarshal(r.Structured.Data, &group) != nil || group.ID == "" {
			t.Fatalf("createDeviceGroup: %+v", r)
		}
		groupID = group.ID
		deleteOnCleanup(t, alice, "/api/v1/device-groups/"+group.ID)
		ev := expectOneTargetEvent(t, alice, "device_group.created", group.ID, "success")
		if ev.Source != "mcp" || ev.Actor.Client != mcpGateClient || ev.Actor.Type != "admin" || ev.Actor.ID != aliceID {
			t.Fatalf("device_group.created by the MCP: source %q, actor %+v; want mcp, alice, client %s", ev.Source, ev.Actor, mcpGateClient)
		}
		if r := srv.call(t, "deleteDeviceGroup", map[string]any{"id": group.ID}); r.IsError || r.Structured.Status != http.StatusNoContent {
			t.Fatalf("deleteDeviceGroup: %+v", r)
		}
		if ev := expectOneTargetEvent(t, alice, "device_group.deleted", group.ID, "success"); ev.Source != "mcp" {
			t.Fatalf("device_group.deleted by the MCP with source %q", ev.Source)
		}
	})

	t.Run("M4 scope policy", func(t *testing.T) {
		mp := aliceCLI.portal(t)
		putMCPPolicy(t, alice, env.Alice, "/api/v1/settings/mcp", mcpPolicy(true, true, "listDevices"))
		res := call(t, mp, http.MethodPost, "/api/v1/device-groups", map[string]string{"name": uniqueName("mcp m4")})
		expectMCPRefusal(t, alice, res, http.StatusForbidden, "mcp_tool_not_allowed", "device_group.created")
		res = call(t, mp, http.MethodGet, "/api/v1/device-groups", nil)
		expectStatus(t, res, http.StatusForbidden, "mcp_tool_not_allowed")
		expectNoEvent(t, alice, res.RequestID)

		putMCPPolicy(t, alice, env.Alice, "/api/v1/settings/mcp", mcpPolicy(true, false))
		res = call(t, mp, http.MethodPost, "/api/v1/device-groups", map[string]string{"name": uniqueName("mcp m4")})
		expectMCPRefusal(t, alice, res, http.StatusForbidden, "mcp_write_not_enabled", "device_group.created")

		putMCPPolicy(t, alice, env.Alice, "/api/v1/settings/mcp", mcpPolicy(false, false))
		expectStatus(t, call(t, mp, http.MethodGet, "/api/v1/devices", nil), http.StatusForbidden, "mcp_disabled")

		putMCPPolicy(t, alice, env.Alice, "/api/v1/settings/mcp", mcpPolicy(true, true))
	})

	t.Run("M5 step-up behaviour", func(t *testing.T) {
		// With write access on in both scopes the lists hold write tools, so a missing step-up tool is a refusal.
		freshStepUp(t, root, env.PlatformAdmin)
		expectStatus(t, call(t, root, http.MethodPost, "/api/v1/me/mcp-write/enable", nil), http.StatusOK, "")
		for scope, c := range map[string]*mcpCLI{"organization": aliceCLI, "platform": rootCLI} {
			srv := c.serve(t)
			listed := srv.tools(t)
			var tools []string
			writes := 0
			for _, tool := range listed {
				tools = append(tools, tool.Name)
				if !tool.Annotations.ReadOnlyHint {
					writes++
				}
			}
			if writes == 0 {
				t.Fatalf("%s tools/list with write access holds no write tool: %v", scope, tools)
			}
			for _, name := range mcpPortalOnly {
				if hasTool(tools, name) {
					t.Fatalf("%s tools/list offers the step-up operation %s", scope, name)
				}
			}
			srv.close(t)
		}
		mp := aliceCLI.portal(t)
		res := call(t, mp, http.MethodPost, "/api/v1/devices/"+uuid.NewString()+"/lock", map[string]string{"confirm_hostname": "mcp-gate"})
		expectMCPRefusal(t, alice, res, http.StatusForbidden, "mcp_tool_not_allowed", "revocation.requested")

		srv := aliceCLI.serve(t)
		r := srv.call(t, "createPermissionProfile", map[string]any{"body": map[string]string{"name": uniqueName("mcp full"), "class": "full"}})
		if !r.IsError || r.Structured.Error == nil || r.Structured.Error.Code != "step_up_required" ||
			!strings.Contains(r.Structured.Error.Detail, "MCP sessions") || r.Structured.Error.PortalPath != "/permission-profiles" {
			t.Fatalf("createPermissionProfile with a full profile: %+v %+v", r, r.Structured.Error)
		}
		if ev := expectOneEvent(t, alice, r.Structured.Error.RequestID, "permission_profile.created", "denied"); ev.ErrorCode != "step_up_required" || ev.Source != "mcp" {
			t.Fatalf("permission_profile.created: error code %q, source %q", ev.ErrorCode, ev.Source)
		}
		stepUpRes, err := mp.Do(testContext(t, time.Minute), http.MethodGet, "/api/auth/stepup?return_to=%2F", nil)
		if err != nil || stepUpRes.Status != http.StatusForbidden || stepUpRes.ProblemCode() != "forbidden" ||
			problemDetail(t, stepUpRes) != "MCP sessions cannot complete a step-up" {
			t.Fatalf("GET /api/auth/stepup with the MCP bearer: %+v %v, want 403 forbidden naming MCP sessions", stepUpRes, err)
		}
	})

	t.Run("M6 isolation", func(t *testing.T) {
		carol := login(t, env.Carol)
		tok := createToken(t, carol, tokenOptions{name: uniqueName("mcp gate globex"), autoApprove: true})
		hostname := "mcp-gate-" + uniqueSuffix()
		dev, s := enroll(t, tok.EnrollmentConfig, hostname)
		if s.Status != "active" {
			t.Fatalf("globex device enrollment %+v", s)
		}
		srv := aliceCLI.serve(t)
		r := srv.call(t, "getDevice", map[string]any{"id": dev.DeviceID})
		if !r.IsError || r.Structured.Status != http.StatusNotFound || r.Structured.Error == nil || r.Structured.Error.Code != "not_found" {
			t.Fatalf("getDevice with carol's device id: %+v", r)
		}
		if raw, _ := json.Marshal(r); strings.Contains(string(raw), hostname) {
			t.Fatalf("getDevice answer names globex's device: %s", raw)
		}
		expectStatus(t, call(t, rootCLI.portal(t), http.MethodGet, "/api/v1/devices", nil), http.StatusForbidden, "no_organization")
	})

	t.Run("M7 one event per action", func(t *testing.T) {
		// L1–M5 assert exactly one event per request; a body the use case rejects is one failure event.
		res := call(t, aliceCLI.portal(t), http.MethodPost, "/api/v1/device-groups", map[string]string{"name": ""})
		expectStatus(t, res, http.StatusBadRequest, "invalid_request")
		if ev := expectOneEvent(t, alice, res.RequestID, "device_group.created", "failure"); ev.Source != "mcp" {
			t.Fatalf("failure event with source %q", ev.Source)
		}
	})

	t.Run("M8 no tokens", func(t *testing.T) {
		created := createAPIToken(t, alice, env.Alice, "org_auditor")
		var me struct {
			Channel string `json:"channel"`
		}
		res := call(t, tokenPortal(t, created.Secret), http.MethodGet, "/api/v1/me", nil)
		expectStatus(t, res, http.StatusOK, "")
		if err := res.JSON(&me); err != nil || me.Channel != "api" {
			t.Fatalf("GET /api/v1/me with an API token: %s", res.Body)
		}
		fresh := newMCPCLI(t)
		r := fresh.run(t, []string{"PADDOCK_TOKEN_FILE=" + tokenFile(t, created.Secret, 0o600)}, "mcp", "tools")
		if r.code != 2 || !strings.Contains(r.stderr, "not signed in") {
			t.Fatalf("paddockctl mcp tools with a token file and no session: %+v", r)
		}
		res = call(t, tokenPortal(t, "pdkp_"+strings.Repeat("A", 43)), http.MethodGet, "/api/v1/me", nil)
		expectStatus(t, res, http.StatusUnauthorized, "")
	})

	t.Run("M9 rate limit", func(t *testing.T) {
		// A fixed one-minute window: up to two windows' budget within the token's lifetime finds the limit.
		token := aliceCLI.token(t)
		p := tokenPortal(t, token)
		var limited *env.Response
		for i, start := 0, time.Now(); i < 2*121 && time.Since(start) < 40*time.Second; i++ {
			res := call(t, p, http.MethodGet, "/api/v1/me", nil)
			if res.Status == http.StatusTooManyRequests {
				limited = &res
				break
			}
			expectStatus(t, res, http.StatusOK, "")
		}
		if limited == nil {
			t.Fatal("no 429 within two windows of MCP reads")
		}
		expectStatus(t, *limited, http.StatusTooManyRequests, "rate_limited")
		if s, err := strconv.Atoi(limited.Header.Get("Retry-After")); err != nil || s < 1 || s > 60 {
			t.Fatalf("Retry-After %q", limited.Header.Get("Retry-After"))
		}
		for range 130 {
			expectStatus(t, call(t, alice, http.MethodGet, "/api/v1/me", nil), http.StatusOK, "")
		}
	})

	t.Run("M10 audit display", func(t *testing.T) {
		if groupID == "" {
			t.Fatal("M3 created no device group")
		}
		res := call(t, alice, http.MethodGet, "/api/v1/audit-events?code=device_group.created&target_id="+groupID, nil)
		expectStatus(t, res, http.StatusOK, "")
		var page struct {
			Items []env.AuditEvent `json:"items"`
		}
		if err := res.JSON(&page); err != nil || len(page.Items) != 1 || page.Items[0].Source != "mcp" ||
			page.Items[0].Actor.Client != mcpGateClient {
			t.Fatalf("audit list for the M3 event: %s", res.Body)
		}
	})

	// Both wait for the identity sync round with users of their own, so they run together after the other cases.
	t.Run("L3 revoked session", func(t *testing.T) {
		t.Parallel()
		u := mfaTempUser(t, "mcp-l3", env.RoleGroup("acme", "admins"))
		c := newMCPCLI(t)
		c.signIn(t, mcpTempIdentity(u))
		old := c.token(t)
		if r := c.run(t, nil, "mcp", "logout"); r.code != 0 || !strings.Contains(r.stdout, "Signed out") {
			t.Fatalf("paddockctl mcp logout: %+v", r)
		}
		expectStatus(t, call(t, tokenPortal(t, old), http.MethodGet, "/api/v1/me", nil), http.StatusUnauthorized, "mcp_login_required")
		c.signedOut(t)
		if r := c.run(t, nil, "mcp", "tools"); r.code != 2 || !strings.Contains(r.stderr, "not signed in") {
			t.Fatalf("paddockctl mcp tools after logout: %+v", r)
		}

		c.signIn(t, mcpTempIdentity(u))
		ak, err := env.NewAuthentik()
		if err != nil {
			t.Fatal(err)
		}
		ctx := testContext(t, 3*time.Minute)
		pk, err := ak.UserPK(ctx, u.username)
		if err != nil || pk == 0 {
			t.Fatalf("user pk: %d %v", pk, err)
		}
		if err := ak.SetActive(ctx, pk, false); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = ak.SetActive(testContext(t, time.Minute), pk, true) })
		if ev := revokedEvent(t, idx, acme, u.username, accountRoundTimeout); ev.Params["reason"] != "deactivated" {
			t.Fatalf("event params %v", ev.Params)
		}
		expectStatus(t, call(t, tokenPortal(t, c.session(t).AccessToken), http.MethodGet, "/api/v1/me", nil), http.StatusUnauthorized, "")
		if r := c.run(t, nil, "mcp", "tools"); r.code != 1 || !strings.Contains(r.stderr, "login required") {
			t.Fatalf("paddockctl mcp tools after the deactivation: %+v", r)
		}
		if err := ak.SetActive(ctx, pk, true); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("L4 role change", func(t *testing.T) {
		t.Parallel()
		u := mfaTempUser(t, "mcp-l4", env.RoleGroup("acme", "admins"))
		u.stepUp(t)
		expectStatus(t, call(t, u.Portal, http.MethodPost, "/api/v1/me/mcp-write/enable", nil), http.StatusOK, "")
		c := newMCPCLI(t)
		c.signIn(t, mcpTempIdentity(u))
		srv := c.serve(t)
		if !hasTool(srv.toolNames(t), "createDeviceGroup") {
			t.Fatal("an opted-in administrator's tools/list lacks createDeviceGroup")
		}
		srv.close(t)

		ak, err := env.NewAuthentik()
		if err != nil {
			t.Fatal(err)
		}
		if err := ak.MoveGroup(testContext(t, time.Minute), u.username, env.RoleGroup("acme", "admins"), env.RoleGroup("acme", "auditors")); err != nil {
			t.Fatal(err)
		}
		ev := revokedEvent(t, idx, acme, u.username, accountRoundTimeout)
		if ev.Params["reason"] != "role_changed" || ev.Params["new_role"] != "org_auditor" {
			t.Fatalf("event params %v", ev.Params)
		}
		if r := c.run(t, nil, "mcp", "tools"); r.code != 1 || !strings.Contains(r.stderr, "login required") {
			t.Fatalf("paddockctl mcp tools after the role change: %+v", r)
		}
		if line := c.signIn(t, mcpTempIdentity(u)); !strings.HasSuffix(line, "(org_auditor, acme)") {
			t.Fatalf("login line after the role change %q", line)
		}
		srv = c.serve(t)
		if !hasTool(srv.toolNames(t), "listDevices") {
			t.Fatal("an auditor's tools/list lacks listDevices")
		}
		for _, tool := range srv.tools(t) {
			if !tool.Annotations.ReadOnlyHint {
				t.Fatalf("an auditor's tools/list offers the write tool %s", tool.Name)
			}
		}
	})
}
