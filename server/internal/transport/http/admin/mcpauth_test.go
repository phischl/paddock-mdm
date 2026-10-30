package admin_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/phischl/paddock-mdm/server/internal/domain/organization"
	"github.com/phischl/paddock-mdm/server/internal/platform/httpx"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/sessions"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/valkeytest"
	"github.com/phischl/paddock-mdm/server/internal/transport/http/admin"
	"github.com/phischl/paddock-mdm/server/internal/transport/http/admin/adminapi"
)

// mcpWorld is the MCP login (plan M14 §3.3) against a fake provider paddock-mcp, with a clock the test moves.
type mcpWorld struct {
	t    *testing.T
	e    *env
	idp  *fakeStepUpIdP
	slug string // slug of acme

	mu    sync.Mutex
	clock time.Time
}

func newMCPWorld(t *testing.T) *mcpWorld {
	t.Helper()
	return newMCPWorldWith(t, nil)
}

// newMCPWorldWith is newMCPWorld with store as the MCP session store; nil is the env's fake.
func newMCPWorldWith(t *testing.T, store admin.MCPSessionStore) *mcpWorld {
	t.Helper()
	idp := newFakeStepUpIdP(t)
	oidc := admin.NewOIDC(admin.OIDCConfig{Issuer: idp.URL, ClientID: "paddock-mcp", Scopes: admin.MCPScopes})
	discover, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	oidc.Discover(discover)
	if !oidc.Ready() {
		t.Fatal("discovery failed")
	}
	m := &mcpWorld{t: t, idp: idp, clock: time.Now()}
	m.e = newEnvWith(t, func(d *admin.Deps) {
		if store == nil {
			store = d.Sessions.(*fakeSessions)
		}
		d.MCPAuth = admin.NewMCPAuth(oidc, store, d.Accounts, false, m.now)
	})
	if err := m.e.super.QueryRow(context.Background(), "SELECT slug FROM organization WHERE id = $1", m.e.acme).Scan(&m.slug); err != nil {
		t.Fatal(err)
	}
	return m
}

func (m *mcpWorld) now() time.Time {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.clock
}

func (m *mcpWorld) advance(d time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.clock = m.clock.Add(d)
}

// mcpUser is an Authentik identity signing in through paddockctl mcp.
type mcpUser struct {
	sub, username string
	groups        []string
	authTime      int64
}

func (m *mcpWorld) user(groups ...string) mcpUser {
	name := "mcp-" + uuid.NewString()[:8] + "@acme.test"
	return mcpUser{sub: "sub-" + uuid.NewString(), username: name, groups: groups, authTime: time.Now().Unix()}
}

func (m *mcpWorld) admins() string { return organization.RoleGroup(m.slug, organization.GroupAdmins) }

// pair returns an ID token and an access token of u; amr nil leaves amr out of the ID token (a refreshed one), and
// life is the access token's remaining life.
func (m *mcpWorld) pair(u mcpUser, amr []string, life time.Duration) (idToken, accessToken string) {
	now := time.Now()
	base := func() map[string]any {
		return map[string]any{"iss": m.idp.URL, "aud": "paddock-mcp", "sub": u.sub, "preferred_username": u.username,
			"groups": u.groups, "auth_time": u.authTime, "iat": now.Unix(), "exp": now.Add(life).Unix(), "jti": uuid.NewString()}
	}
	id := base()
	if amr != nil {
		id["amr"] = amr
	}
	// Authentik copies amr into the access token of a login, as into its ID token.
	access := base()
	access["azp"], access["scope"] = "paddock-mcp", "openid profile email groups offline_access"
	if amr != nil {
		access["amr"] = amr
	}
	return m.idp.sign(m.t, id), m.idp.sign(m.t, access)
}

func (m *mcpWorld) open(id, access string, extra map[string]any) result {
	m.t.Helper()
	body := map[string]any{"id_token": id, "access_token": access}
	for k, v := range extra {
		body[k] = v
	}
	return authCall(m.e, call{method: "POST", path: "/api/auth/mcp/session", body: body,
		headers: map[string]string{"X-Paddock-MCP-Client": "claude-code/2.1"}})
}

// login opens an MCP session with a fresh login of u (amr pwd and mfa).
func (m *mcpWorld) login(u mcpUser, extra map[string]any) (string, result) {
	m.t.Helper()
	id, access := m.pair(u, []string{"pwd", "mfa"}, 30*time.Minute)
	return access, m.open(id, access, extra)
}

func (m *mcpWorld) me(token string) result {
	m.t.Helper()
	return m.e.do(call{method: "GET", path: "/api/v1/me", headers: bearer(token)})
}

// loginEvent returns the one admin.login event of a request as outcome|channel|renewal|denial_reason|reason|source.
func (m *mcpWorld) loginEvent(r result) string {
	m.t.Helper()
	rows, err := m.e.super.Query(context.Background(), `SELECT outcome || '|' || coalesce(params->>'channel', '-') || '|' ||
		coalesce(params->>'renewal', '-') || '|' || coalesce(params->>'denial_reason', '-') || '|' ||
		coalesce(params->>'reason', '-') || '|' || coalesce(source, '-')
		FROM action WHERE code = 'admin.login' AND correlation_id = $1`, r.header.Get(httpx.HeaderRequestID))
	if err != nil {
		m.t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			m.t.Fatal(err)
		}
		out = append(out, s)
	}
	if len(out) != 1 {
		m.t.Fatalf("admin.login events of the request: %v, want exactly one", out)
	}
	return out[0]
}

// authCall sends a request to a hand-written /api/auth/* route, which the generated contract router does not serve.
func authCall(e *env, c call) result {
	e.t.Helper()
	var body io.Reader
	if c.body != nil {
		raw, _ := json.Marshal(c.body)
		body = bytes.NewReader(raw)
	}
	req := httptest.NewRequest(c.method, "https://admin.test"+c.path, body)
	if c.body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range c.headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	e.handler.ServeHTTP(rec, req)
	res := result{status: rec.Code, header: rec.Header(), body: rec.Body.Bytes()}
	if res.status >= 400 && !strings.HasPrefix(res.header.Get("Content-Type"), "application/problem+json") {
		e.t.Fatalf("%s %s: %d without a problem: %s", c.method, c.path, res.status, res.body)
	}
	return res
}

func sessionIDOf(token string) string {
	sum := sha256.Sum256([]byte(token))
	return "mcp:" + hex.EncodeToString(sum[:])
}

func (m *mcpWorld) record(token string) (sessions.Record, bool) {
	m.e.sessions.mu.Lock()
	defer m.e.sessions.mu.Unlock()
	rec, ok := m.e.sessions.records[sessionIDOf(token)]
	return rec, ok
}

func (m *mcpWorld) bound(u mcpUser) bool {
	m.e.sessions.mu.Lock()
	defer m.e.sessions.mu.Unlock()
	_, ok := m.e.sessions.bindings[bindingID(u.sub, u.authTime)]
	return ok
}

func expectProblem(t *testing.T, name string, r result, status int, code string) {
	t.Helper()
	if r.status != status || r.problemCode(t) != code {
		t.Fatalf("%s: %d %s, want %d %s", name, r.status, r.body, status, code)
	}
}

// TestMCPLoginConfig: GET /api/auth/mcp/config answers the provider and its endpoints; without the MCP login every
// /api/auth/mcp/* route answers 404 and an MCP access token is refused.
func TestMCPLoginConfig(t *testing.T) {
	m := newMCPWorld(t)
	r := authCall(m.e, call{method: "GET", path: "/api/auth/mcp/config"})
	var cfg admin.McpLoginConfig
	r.decode(t, &cfg)
	if r.status != http.StatusOK || cfg.Issuer != m.idp.URL || cfg.ClientID != "paddock-mcp" ||
		strings.Join(cfg.Scopes, " ") != "openid profile email groups offline_access" ||
		cfg.DeviceAuthorizationEndpoint != m.idp.URL+"/device" || cfg.TokenEndpoint != m.idp.URL+"/token" ||
		cfg.RevocationEndpoint != m.idp.URL+"/revoke" {
		t.Fatalf("config: %d %s", r.status, r.body)
	}

	e := newEnv(t)
	expectProblem(t, "config without MCP login", authCall(e, call{method: "GET", path: "/api/auth/mcp/config"}), http.StatusNotFound, "not_found")
	id, access := m.pair(m.user(m.admins()), []string{"mfa"}, 30*time.Minute)
	expectProblem(t, "session without MCP login", authCall(e, call{method: "POST", path: "/api/auth/mcp/session",
		body: map[string]any{"id_token": id, "access_token": access}}), http.StatusNotFound, "not_found")
	expectProblem(t, "logout without MCP login", authCall(e, call{method: "POST", path: "/api/auth/mcp/logout", headers: bearer(access)}),
		http.StatusNotFound, "not_found")
	expectProblem(t, "bearer without MCP login", e.do(call{method: "GET", path: "/api/v1/me", headers: bearer(access)}),
		http.StatusUnauthorized, "unauthenticated")
}

// TestMCPSessionLifecycle: a login opens the record of the access token and binds the login; a refreshed pair (ID token
// without amr) renews with renewal true; the bearer acts as the account with channel mcp; logout ends the session and
// the binding.
func TestMCPSessionLifecycle(t *testing.T) {
	m := newMCPWorld(t)
	alice := m.user(m.admins())

	before := m.me("x.y.z")
	expectProblem(t, "unknown bearer", before, http.StatusUnauthorized, "unauthenticated")

	id, first := m.pair(alice, []string{"pwd", "mfa"}, 30*time.Minute)
	if r := m.me(first); r.status != http.StatusUnauthorized || r.problemCode(t) != "mcp_login_required" ||
		len(m.e.events(r.header.Get(httpx.HeaderRequestID))) != 0 {
		t.Fatalf("token before the session call: %d %s", r.status, r.body)
	}
	r := m.open(id, first, nil)
	if r.status != http.StatusNoContent {
		t.Fatalf("login: %d %s", r.status, r.body)
	}
	if got := m.loginEvent(r); got != "success|mcp|-|-|-|mcp" {
		t.Fatalf("login event %s", got)
	}
	rec, ok := m.record(first)
	if !ok || rec.Channel != "mcp" || rec.Role != string(principal.RoleOrgAdmin) || rec.Org != m.e.acme ||
		rec.Subject != alice.sub || rec.Display != alice.username {
		t.Fatalf("record %+v %v", rec, ok)
	}
	if ttl := m.e.sessions.ttls[sessionIDOf(first)]; ttl <= 29*time.Minute || ttl > 31*time.Minute {
		t.Fatalf("record lifetime %s", ttl)
	}
	if !m.bound(alice) {
		t.Fatal("the login was not bound")
	}

	r = m.me(first)
	var me adminapi.Me
	r.decode(t, &me)
	if r.status != http.StatusOK || me.Channel != adminapi.MeChannelMcp || me.Role != adminapi.MeRoleOrgAdmin || me.Id != rec.AccountID ||
		me.AlternateRole != nil {
		t.Fatalf("me: %d %s", r.status, r.body)
	}

	m.advance(20 * time.Minute)
	id, second := m.pair(alice, nil, 30*time.Minute)
	r = m.open(id, second, nil)
	if r.status != http.StatusNoContent {
		t.Fatalf("renewal: %d %s", r.status, r.body)
	}
	if got := m.loginEvent(r); got != "success|mcp|true|-|-|mcp" {
		t.Fatalf("renewal event %s", got)
	}
	for name, token := range map[string]string{"first": first, "renewed": second} {
		if r := m.me(token); r.status != http.StatusOK {
			t.Fatalf("%s token: %d %s", name, r.status, r.body)
		}
	}

	r = authCall(m.e, call{method: "POST", path: "/api/auth/mcp/logout", headers: bearer(second)})
	if r.status != http.StatusNoContent {
		t.Fatalf("logout: %d %s", r.status, r.body)
	}
	expectProblem(t, "after logout", m.me(second), http.StatusUnauthorized, "mcp_login_required")
	if m.bound(alice) {
		t.Fatal("logout left the login binding")
	}
	id, third := m.pair(alice, nil, 30*time.Minute)
	r = m.open(id, third, nil)
	expectProblem(t, "renewal after logout", r, http.StatusUnauthorized, "mcp_login_required")
	if got := m.loginEvent(r); got != "failure|mcp|-|-|mcp_login_required|mcp" {
		t.Fatalf("refused renewal event %s", got)
	}
	if r := authCall(m.e, call{method: "POST", path: "/api/auth/mcp/logout", headers: bearer(second)}); r.status != http.StatusNoContent {
		t.Fatalf("second logout: %d %s", r.status, r.body)
	}
}

// TestMCPSessionRefusals covers the refused logins and renewals (plan M14 §3.3 item 13, ADR 0044 amendment
// 2026-10-28), each with exactly one admin.login event of channel mcp.
func TestMCPSessionRefusals(t *testing.T) {
	m := newMCPWorld(t)

	u := m.user(m.admins())
	id, access := m.pair(u, []string{"pwd"}, 30*time.Minute)
	r := m.open(id, access, nil)
	expectProblem(t, "without mfa", r, http.StatusUnauthorized, "unauthenticated")
	if got := m.loginEvent(r); got != "denied|mcp|-|-|mfa_required|mcp" {
		t.Fatalf("mfa event %s", got)
	}

	id, _ = m.pair(u, []string{"mfa"}, 30*time.Minute)
	_, other := m.pair(m.user(m.admins()), []string{"mfa"}, 30*time.Minute)
	expectProblem(t, "subject mismatch", m.open(id, other, nil), http.StatusBadRequest, "invalid_request")

	id, access = m.pair(u, []string{"mfa"}, 40*time.Minute)
	expectProblem(t, "40-minute token", m.open(id, access, nil), http.StatusBadRequest, "invalid_request")

	foreign := newFakeStepUpIdP(t)
	fu := m.user(m.admins())
	claims := map[string]any{"iss": foreign.URL, "aud": "paddock-mcp", "sub": fu.sub, "amr": []string{"mfa"},
		"auth_time": fu.authTime, "exp": time.Now().Add(30 * time.Minute).Unix(), "iat": time.Now().Unix()}
	r = m.open(foreign.sign(t, claims), foreign.sign(t, claims), nil)
	expectProblem(t, "another issuer", r, http.StatusUnauthorized, "unauthenticated")
	if got := m.loginEvent(r); got != "failure|mcp|-|-|login_failed|mcp" {
		t.Fatalf("foreign issuer event %s", got)
	}

	_, r = m.login(m.user(), nil)
	expectProblem(t, "no role", r, http.StatusForbidden, "forbidden")
	var p httpx.Problem
	r.decode(t, &p)
	if p.Detail != "no_role" {
		t.Fatalf("no role detail %q", p.Detail)
	}
	if got := m.loginEvent(r); got != "denied|mcp|-|no_role|not_authorized|mcp" {
		t.Fatalf("no role event %s", got)
	}

	renew := func(name string, u mcpUser) {
		t.Helper()
		id, access := m.pair(u, nil, 30*time.Minute)
		r := m.open(id, access, nil)
		expectProblem(t, name, r, http.StatusUnauthorized, "mcp_login_required")
		if got := m.loginEvent(r); got != "failure|mcp|-|-|mcp_login_required|mcp" {
			t.Fatalf("%s: event %s", name, got)
		}
		if _, ok := m.record(access); ok {
			t.Fatalf("%s: a record was opened", name)
		}
	}
	renew("first login without amr", m.user(m.admins()))

	bob := m.user(m.admins())
	if _, r := m.login(bob, nil); r.status != http.StatusNoContent {
		t.Fatalf("login: %d %s", r.status, r.body)
	}
	later := bob
	later.authTime++
	renew("another auth_time", later)
	stranger := m.user(m.admins())
	stranger.authTime = bob.authTime
	renew("another subject", stranger)

	m.advance(8*time.Hour + time.Minute)
	renew("expired binding", bob)
}

// TestMCPRoleChoice covers ADR 0045 decision 7 for MCP sessions: the organization role by default, the platform role
// on request, and role_not_granted for a role the groups do not grant.
func TestMCPRoleChoice(t *testing.T) {
	m := newMCPWorld(t)
	both := m.user(organization.PlatformAdminsGroup(), m.admins())

	token, r := m.login(both, nil)
	if r.status != http.StatusNoContent {
		t.Fatalf("default role: %d %s", r.status, r.body)
	}
	var me adminapi.Me
	m.me(token).decode(t, &me)
	if me.Role != adminapi.MeRoleOrgAdmin || me.AlternateRole != nil {
		t.Fatalf("default role: %+v", me)
	}
	token, r = m.login(both, map[string]any{"role": "platform"})
	if r.status != http.StatusNoContent {
		t.Fatalf("platform role: %d %s", r.status, r.body)
	}
	me = adminapi.Me{}
	m.me(token).decode(t, &me)
	if me.Role != adminapi.MeRolePlatformAdmin || me.Channel != adminapi.MeChannelMcp || me.AlternateRole != nil {
		t.Fatalf("platform role: %+v", me)
	}

	_, r = m.login(m.user(m.admins()), map[string]any{"role": "platform"})
	expectProblem(t, "role not granted", r, http.StatusForbidden, "forbidden")
	var p httpx.Problem
	r.decode(t, &p)
	if p.Detail != "role_not_granted" {
		t.Fatalf("detail %q", p.Detail)
	}
	if got := m.loginEvent(r); got != "denied|mcp|-|role_not_granted|not_authorized|mcp" {
		t.Fatalf("event %s", got)
	}
}

// TestMCPBearer covers the bearer path (plan M14 §3.3 item 14): only an MCP record of the current generation with an
// active account of the record's role authenticates; a deactivation or role change revokes every session and binding
// of the account; tokens of any other shape are refused without an event; the step-up refuses an MCP bearer.
func TestMCPBearer(t *testing.T) {
	m := newMCPWorld(t)
	alice := m.user(m.admins())
	token, r := m.login(alice, nil)
	if r.status != http.StatusNoContent {
		t.Fatalf("login: %d %s", r.status, r.body)
	}
	rec, _ := m.record(token)

	r = authCall(m.e, call{method: "GET", path: "/api/auth/stepup", headers: bearer(token)})
	expectProblem(t, "step-up with an MCP bearer", r, http.StatusForbidden, "forbidden")

	for name, secret := range map[string]string{"pdkp": "pdkp_" + strings.Repeat("a", 43), "garbage": "not-a-token"} {
		r := m.me(secret)
		if r.status != http.StatusUnauthorized || r.problemCode(t) != "unauthenticated" ||
			len(m.e.events(r.header.Get(httpx.HeaderRequestID))) != 0 {
			t.Fatalf("%s bearer: %d %s", name, r.status, r.body)
		}
	}

	// A portal record found under the MCP key is not an MCP session.
	_, portalToken := m.pair(alice, nil, 30*time.Minute)
	m.e.sessions.mu.Lock()
	m.e.sessions.records[sessionIDOf(portalToken)] = sessions.Record{AccountID: rec.AccountID, Kind: rec.Kind, Role: rec.Role, Org: rec.Org}
	m.e.sessions.mu.Unlock()
	expectProblem(t, "portal record", m.me(portalToken), http.StatusUnauthorized, "unauthenticated")

	m.e.sessions.down = true
	expectProblem(t, "store down", m.me(token), http.StatusServiceUnavailable, "session_store_unavailable")
	m.e.sessions.down = false

	revoked := func(name string) {
		t.Helper()
		expectProblem(t, name, m.me(token), http.StatusUnauthorized, "unauthenticated")
		if _, ok := m.record(token); ok {
			t.Fatalf("%s: the record is left", name)
		}
		if m.bound(alice) {
			t.Fatalf("%s: the binding is left", name)
		}
	}
	ctx := context.Background()
	if _, err := m.e.super.Exec(ctx, "UPDATE admin_account SET disabled_at = now() WHERE id = $1", rec.AccountID); err != nil {
		t.Fatal(err)
	}
	revoked("disabled account")

	if token, r = m.login(alice, nil); r.status != http.StatusNoContent {
		t.Fatalf("login again: %d %s", r.status, r.body)
	}
	if _, err := m.e.super.Exec(ctx, "UPDATE admin_account SET role = 'org_auditor' WHERE id = $1", rec.AccountID); err != nil {
		t.Fatal(err)
	}
	revoked("changed role")

	if token, r = m.login(alice, nil); r.status != http.StatusNoContent {
		t.Fatalf("login after the role change: %d %s", r.status, r.body)
	}
	stepped := m.e.steppedUp(m.e.platformSession(), time.Now())
	if r := m.e.do(call{method: "POST", path: "/api/platform/v1/sessions/end-all", cookie: stepped}); r.status != http.StatusOK {
		t.Fatalf("end all: %d %s", r.status, r.body)
	}
	expectProblem(t, "after end all", m.me(token), http.StatusUnauthorized, "unauthenticated")
	id, renewed := m.pair(alice, nil, 30*time.Minute)
	expectProblem(t, "renewal after end all", m.open(id, renewed, nil), http.StatusUnauthorized, "mcp_login_required")
}

// accountRole returns the role column of the admin account id.
func (m *mcpWorld) accountRole(id uuid.UUID) string {
	m.t.Helper()
	var role string
	if err := m.e.super.QueryRow(context.Background(), "SELECT role FROM admin_account WHERE id = $1", id).Scan(&role); err != nil {
		m.t.Fatal(err)
	}
	return role
}

// TestMCPRenewalRoleContext: a renewal is bound to the role context of its login (ADR 0044 amendment 2026-10-28): a
// refreshed pair whose groups resolve another role, kind or organization is refused with 401 mcp_login_required and
// ends the binding and all sessions of the account, its portal session too; the account row keeps the login's role.
func TestMCPRenewalRoleContext(t *testing.T) {
	m := newMCPWorld(t)
	var globex string
	if err := m.e.super.QueryRow(context.Background(), "SELECT slug FROM organization WHERE id = $1", m.e.globex).Scan(&globex); err != nil {
		t.Fatal(err)
	}
	auditors := organization.RoleGroup(m.slug, organization.GroupAuditors)
	for _, tc := range []struct {
		name         string
		login, renew []string
		renewRole    string
		wantRowRole  string
	}{
		{name: "role demoted", login: []string{m.admins()}, renew: []string{auditors}, wantRowRole: "org_admin"},
		{name: "role promoted", login: []string{auditors}, renew: []string{m.admins()}, wantRowRole: "org_auditor"},
		{name: "kind changed", login: []string{organization.PlatformAdminsGroup(), m.admins()},
			renew: []string{organization.PlatformAdminsGroup(), m.admins()}, renewRole: "platform", wantRowRole: "org_admin"},
		{name: "organization changed", login: []string{m.admins()},
			renew: []string{organization.RoleGroup(globex, organization.GroupAdmins)}, wantRowRole: "org_admin"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			u := m.user(tc.login...)
			token, r := m.login(u, nil)
			if r.status != http.StatusNoContent {
				t.Fatalf("login: %d %s", r.status, r.body)
			}
			rec, _ := m.record(token)
			portal := sessions.NewID()
			if _, err := m.e.sessions.Create(context.Background(), portal, sessions.Record{AccountID: rec.AccountID, Kind: rec.Kind,
				Role: rec.Role, Org: rec.Org}, time.Hour); err != nil {
				t.Fatal(err)
			}
			u.groups = tc.renew
			id, renewed := m.pair(u, nil, 30*time.Minute)
			var extra map[string]any
			if tc.renewRole != "" {
				extra = map[string]any{"role": tc.renewRole}
			}
			r = m.open(id, renewed, extra)
			expectProblem(t, "renewal", r, http.StatusUnauthorized, "mcp_login_required")
			if got := m.loginEvent(r); got != "failure|mcp|-|-|mcp_login_required|mcp" {
				t.Fatalf("event %s", got)
			}
			if _, ok := m.record(renewed); ok {
				t.Fatal("the renewal opened a record")
			}
			if _, ok := m.record(token); ok {
				t.Fatal("the MCP session of the login is left")
			}
			if m.bound(u) {
				t.Fatal("the binding is left")
			}
			m.e.sessions.mu.Lock()
			_, portalLeft := m.e.sessions.records[portal]
			m.e.sessions.mu.Unlock()
			if portalLeft {
				t.Fatal("the portal session of the account is left")
			}
			if got := m.accountRole(rec.AccountID); got != tc.wantRowRole {
				t.Fatalf("account role %s, want %s", got, tc.wantRowRole)
			}
		})
	}
}

// TestMCPRenewalRacingEndAll: End all sessions between the binding lookup and the new record refuses the renewal.
func TestMCPRenewalRacingEndAll(t *testing.T) {
	m := newMCPWorld(t)
	u := m.user(m.admins())
	if _, r := m.login(u, nil); r.status != http.StatusNoContent {
		t.Fatalf("login: %d %s", r.status, r.body)
	}
	m.e.sessions.beforeCreate = func() {
		m.e.sessions.beforeCreate = nil
		if _, err := m.e.sessions.EndAll(context.Background()); err != nil {
			t.Error(err)
		}
	}
	id, renewed := m.pair(u, nil, 30*time.Minute)
	r := m.open(id, renewed, nil)
	expectProblem(t, "renewal racing end all", r, http.StatusUnauthorized, "mcp_login_required")
	if got := m.loginEvent(r); !strings.HasPrefix(got, "failure|mcp|true|") {
		t.Fatalf("event %s", got)
	}
	if _, ok := m.record(renewed); ok {
		t.Fatal("the renewal left its record")
	}
	if m.bound(u) {
		t.Fatal("the binding survived the race")
	}
}

// TestMCPLoginRacingEndAll: End all sessions between the record and the binding of a login refuses the login and
// leaves neither behind.
func TestMCPLoginRacingEndAll(t *testing.T) {
	m := newMCPWorld(t)
	u := m.user(m.admins())
	m.e.sessions.beforeBind = func() {
		m.e.sessions.beforeBind = nil
		if _, err := m.e.sessions.EndAll(context.Background()); err != nil {
			t.Error(err)
		}
	}
	token, r := m.login(u, nil)
	expectProblem(t, "login racing end all", r, http.StatusUnauthorized, "mcp_login_required")
	if got := m.loginEvent(r); !strings.HasPrefix(got, "failure|mcp|-|") {
		t.Fatalf("event %s", got)
	}
	if _, ok := m.record(token); ok {
		t.Fatal("the login left its record")
	}
	if m.bound(u) {
		t.Fatal("the login left its binding")
	}
}

// TestMCPAccessTokenNeedsScope: the access-token markers are required together (fail closed): a token of the provider
// with azp but without scope is no access token for the session call, as a bearer, or at logout.
func TestMCPAccessTokenNeedsScope(t *testing.T) {
	m := newMCPWorld(t)
	u := m.user(m.admins())
	if _, r := m.login(u, nil); r.status != http.StatusNoContent {
		t.Fatalf("login: %d %s", r.status, r.body)
	}
	now := time.Now()
	noScope := m.idp.sign(t, map[string]any{"iss": m.idp.URL, "aud": "paddock-mcp", "azp": "paddock-mcp", "sub": u.sub,
		"preferred_username": u.username, "groups": u.groups, "auth_time": u.authTime, "iat": now.Unix(),
		"exp": now.Add(30 * time.Minute).Unix()})
	id, _ := m.pair(u, []string{"pwd", "mfa"}, 30*time.Minute)
	r := m.open(id, noScope, nil)
	expectProblem(t, "session call", r, http.StatusUnauthorized, "unauthenticated")
	if got := m.loginEvent(r); !strings.HasPrefix(got, "failure|mcp|-|-|login_failed|") {
		t.Fatalf("event %s", got)
	}
	expectProblem(t, "bearer", m.me(noScope), http.StatusUnauthorized, "unauthenticated")
	expectProblem(t, "logout", authCall(m.e, call{method: "POST", path: "/api/auth/mcp/logout", headers: bearer(noScope)}),
		http.StatusUnauthorized, "unauthenticated")
	if !m.bound(u) {
		t.Fatal("a refused logout ended the binding")
	}
}

// TestMCPSessionStoreFailures: a session call whose single-use marker or binding lookup fails answers 503 with one
// audited failure and opens nothing; a reply lost after the record or the binding was written leaves neither behind.
func TestMCPSessionStoreFailures(t *testing.T) {
	m := newMCPWorld(t)
	u := m.user(m.admins())
	if _, r := m.login(u, nil); r.status != http.StatusNoContent {
		t.Fatalf("login: %d %s", r.status, r.body)
	}
	for _, method := range []string{"UseLoginToken", "Binding"} {
		id, renewed := m.pair(u, nil, 30*time.Minute)
		m.e.sessions.failing[method] = true
		r := m.open(id, renewed, nil)
		m.e.sessions.failing[method] = false
		expectProblem(t, method, r, http.StatusServiceUnavailable, "session_store_unavailable")
		if got := m.loginEvent(r); !strings.HasPrefix(got, "failure|mcp|-|-|login_failed|") {
			t.Fatalf("%s: event %s", method, got)
		}
		if _, ok := m.record(renewed); ok {
			t.Fatalf("%s: a record was opened", method)
		}
	}

	fresh := m.user(m.admins())
	id, access := m.pair(fresh, []string{"pwd", "mfa"}, 30*time.Minute)
	m.e.sessions.failing["UseLoginToken"] = true
	r := m.open(id, access, nil)
	m.e.sessions.failing["UseLoginToken"] = false
	expectProblem(t, "marker of a login", r, http.StatusServiceUnavailable, "session_store_unavailable")
	if _, ok := m.record(access); ok || m.bound(fresh) {
		t.Fatal("a login whose marker failed left a record or a binding")
	}

	for _, method := range []string{"Create", "Bind"} {
		lost := m.user(m.admins())
		id, access := m.pair(lost, []string{"pwd", "mfa"}, 30*time.Minute)
		m.e.sessions.lostReply[method] = true
		r := m.open(id, access, nil)
		m.e.sessions.lostReply[method] = false
		if r.status == http.StatusNoContent {
			t.Fatalf("lost reply of %s: the login succeeded", method)
		}
		if _, ok := m.record(access); ok {
			t.Fatalf("lost reply of %s: the record is left", method)
		}
		if m.bound(lost) {
			t.Fatalf("lost reply of %s: the binding is left", method)
		}
	}
}

// TestMCPLoginTokenEncodings: the single-use marker keys on the verified token, and only canonical compact JWTs are
// accepted, so another encoding of a used login token never reopens a session; the original works exactly once.
func TestMCPLoginTokenEncodings(t *testing.T) {
	m := newMCPWorld(t)
	u := m.user(m.admins())
	id, access := m.pair(u, []string{"pwd", "mfa"}, 30*time.Minute)
	if r := m.open(id, access, nil); r.status != http.StatusNoContent {
		t.Fatalf("login: %d %s", r.status, r.body)
	}
	if r := authCall(m.e, call{method: "POST", path: "/api/auth/mcp/logout", headers: bearer(access)}); r.status != http.StatusNoContent {
		t.Fatalf("logout: %d %s", r.status, r.body)
	}
	head, sig := id[:strings.LastIndex(id, ".")+1], id[strings.LastIndex(id, ".")+1:]
	last := strings.IndexByte("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_", sig[len(sig)-1])
	// An RS256 signature of 256 bytes leaves four spare bits in its last character; setting one keeps the bytes.
	spare := string("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"[last|1])
	for name, variant := range map[string]string{
		"inserted line break":    id[:20] + "\n" + id[20:],
		"trailing CRLF":          id + "\r\n",
		"altered last character": head + sig[:len(sig)-1] + spare,
	} {
		if variant == id {
			t.Fatalf("%s: no variant", name)
		}
		_, fresh := m.pair(u, nil, 30*time.Minute)
		r := m.open(variant, fresh, nil)
		if r.status == http.StatusNoContent {
			t.Fatalf("%s: the variant opened a session", name)
		}
		if _, ok := m.record(fresh); ok || m.bound(u) {
			t.Fatalf("%s: a record or binding exists", name)
		}
	}

	// The bearer path refuses another encoding of a live access token as well.
	live, r := m.login(m.user(m.admins()), nil)
	if r.status != http.StatusNoContent {
		t.Fatalf("second login: %d %s", r.status, r.body)
	}
	alphabet := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	altered := live[:len(live)-1] + string(alphabet[strings.IndexByte(alphabet, live[len(live)-1])|1])
	expectProblem(t, "bearer in another encoding", m.me(altered), http.StatusUnauthorized, "unauthenticated")
	if r := m.me(live); r.status != http.StatusOK {
		t.Fatalf("the canonical bearer: %d %s", r.status, r.body)
	}
	// Another token with the same issuer, subject and jti is the same login token.
	claims := map[string]any{}
	payload := id[strings.Index(id, ".")+1 : strings.LastIndex(id, ".")]
	raw, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil || json.Unmarshal(raw, &claims) != nil {
		t.Fatalf("payload: %v", err)
	}
	claims["iat"] = time.Now().Unix() + 1
	_, fresh := m.pair(u, nil, 30*time.Minute)
	r = m.open(m.idp.sign(t, claims), fresh, nil)
	expectProblem(t, "same jti", r, http.StatusUnauthorized, "mcp_login_required")
	if got := m.loginEvent(r); got != "denied|mcp|-|-|token_replayed|mcp" {
		t.Fatalf("same jti: event %s", got)
	}
}

// TestMCPIDTokenIsNoAccessToken: an ID token of the provider is refused as the access token of a session call and as
// a bearer, although it has the same issuer, audience and signature.
func TestMCPIDTokenIsNoAccessToken(t *testing.T) {
	m := newMCPWorld(t)
	u := m.user(m.admins())
	id, _ := m.pair(u, []string{"pwd", "mfa"}, 30*time.Minute)
	r := m.open(id, id, nil)
	expectProblem(t, "ID token as access token", r, http.StatusUnauthorized, "unauthenticated")
	if got := m.loginEvent(r); !strings.HasPrefix(got, "failure|mcp|-|-|login_failed|") {
		t.Fatalf("event %s", got)
	}
	if _, r := m.login(u, nil); r.status != http.StatusNoContent {
		t.Fatalf("login: %d %s", r.status, r.body)
	}
	expectProblem(t, "ID token as bearer", m.me(id), http.StatusUnauthorized, "unauthenticated")
}

// unknownTokenAttempts reads paddock_api_token_auth_total{result="unknown"}.
func unknownTokenAttempts(t *testing.T) float64 {
	t.Helper()
	families, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range families {
		if f.GetName() != "paddock_api_token_auth_total" {
			continue
		}
		for _, metric := range f.GetMetric() {
			for _, l := range metric.GetLabel() {
				if l.GetName() == "result" && l.GetValue() == "unknown" {
					return metric.GetCounter().GetValue()
				}
			}
		}
	}
	return 0
}

// TestMalformedBearerCountsAsUnknownToken keeps docs/operations/api-tokens.md and RR-25: a bearer that is neither an
// API token nor an MCP access token of a configured MCP login counts as an unknown token attempt.
func TestMalformedBearerCountsAsUnknownToken(t *testing.T) {
	m := newMCPWorld(t)
	off := newEnv(t)
	_, jwt := m.pair(m.user(m.admins()), nil, 30*time.Minute)
	for name, tc := range map[string]struct {
		e      *env
		bearer string
	}{"garbage": {m.e, "not-a-token"}, "pdkp": {m.e, "pdkp_" + strings.Repeat("a", 43)}, "JWT without MCP login": {off, jwt}} {
		before := unknownTokenAttempts(t)
		r := tc.e.do(call{method: "GET", path: "/api/v1/me", headers: bearer(tc.bearer)})
		if r.status != http.StatusUnauthorized {
			t.Fatalf("%s: %d", name, r.status)
		}
		if after := unknownTokenAttempts(t); after != before+1 {
			t.Errorf("%s: unknown token attempts %v → %v", name, before, after)
		}
	}
}

// TestMCPLoginTokenSingleUse: a login token opens one session only (ADR 0044 amendment 2026-10-28): presented again,
// also after logout, End all sessions or a role change, it is refused with 401 mcp_login_required and one denied
// event; an access token is never accepted as the ID token.
func TestMCPLoginTokenSingleUse(t *testing.T) {
	m := newMCPWorld(t)
	replayed := func(name, id, access string) {
		t.Helper()
		_, had := m.record(access)
		r := m.open(id, access, nil)
		expectProblem(t, name, r, http.StatusUnauthorized, "mcp_login_required")
		if got := m.loginEvent(r); got != "denied|mcp|-|-|token_replayed|mcp" {
			t.Fatalf("%s: event %s", name, got)
		}
		if _, has := m.record(access); has != had {
			t.Fatalf("%s: the replay changed the session (before %v, after %v)", name, had, has)
		}
	}
	login := func(u mcpUser) (string, string) {
		t.Helper()
		id, access := m.pair(u, []string{"pwd", "mfa"}, 30*time.Minute)
		if r := m.open(id, access, nil); r.status != http.StatusNoContent {
			t.Fatalf("login: %d %s", r.status, r.body)
		}
		return id, access
	}

	u := m.user(m.admins())
	id, access := login(u)
	replayed("the same token twice", id, access)
	if r := m.me(access); r.status != http.StatusOK {
		t.Fatalf("the first session after a replay: %d %s", r.status, r.body)
	}

	if r := authCall(m.e, call{method: "POST", path: "/api/auth/mcp/logout", headers: bearer(access)}); r.status != http.StatusNoContent {
		t.Fatalf("logout: %d %s", r.status, r.body)
	}
	replayed("after logout", id, access)

	id, access = login(m.user(m.admins()))
	stepped := m.e.steppedUp(m.e.platformSession(), time.Now())
	if r := m.e.do(call{method: "POST", path: "/api/platform/v1/sessions/end-all", cookie: stepped}); r.status != http.StatusOK {
		t.Fatalf("end all: %d %s", r.status, r.body)
	}
	replayed("after end all", id, access)

	id, access = login(m.user(m.admins()))
	rec, _ := m.record(access)
	if _, err := m.e.super.Exec(context.Background(), "UPDATE admin_account SET role = 'org_auditor' WHERE id = $1", rec.AccountID); err != nil {
		t.Fatal(err)
	}
	if _, err := m.e.sessions.RevokeAccount(context.Background(), rec.AccountID); err != nil {
		t.Fatal(err)
	}
	replayed("after a role change", id, access)
	if got := m.accountRole(rec.AccountID); got != "org_auditor" {
		t.Fatalf("the replay changed the account role to %s", got)
	}

	_, access = m.pair(m.user(m.admins()), []string{"pwd", "mfa"}, 30*time.Minute)
	r := m.open(access, access, nil)
	expectProblem(t, "access token as ID token", r, http.StatusUnauthorized, "unauthenticated")
	if got := m.loginEvent(r); !strings.HasPrefix(got, "failure|mcp|-|-|login_failed|") {
		t.Fatalf("access token as ID token: event %s", got)
	}
}

// logout signs the bearer's MCP session out.
func (m *mcpWorld) logout(token string) {
	m.t.Helper()
	if r := authCall(m.e, call{method: "POST", path: "/api/auth/mcp/logout", headers: bearer(token)}); r.status != http.StatusNoContent {
		m.t.Fatalf("logout: %d %s", r.status, r.body)
	}
}

// chain logs u in and renews twice; it returns the three access tokens of the refresh chain, oldest first.
func (m *mcpWorld) chain(u mcpUser) []string {
	m.t.Helper()
	first, r := m.login(u, nil)
	if r.status != http.StatusNoContent {
		m.t.Fatalf("login: %d %s", r.status, r.body)
	}
	tokens := []string{first}
	for range 2 {
		m.advance(10 * time.Minute)
		id, renewed := m.pair(u, nil, 30*time.Minute)
		if r := m.open(id, renewed, nil); r.status != http.StatusNoContent {
			m.t.Fatalf("renewal: %d %s", r.status, r.body)
		}
		tokens = append(tokens, renewed)
	}
	return tokens
}

// TestMCPLogoutEndsRefreshChain: logout with any access token of a refresh chain ends the sessions of all its access
// tokens, not only the bearer's (PDK-468); the chain's set lives as long as the binding.
func TestMCPLogoutEndsRefreshChain(t *testing.T) {
	for _, bearerOf := range []int{2, 0} {
		t.Run(fmt.Sprintf("logout with token %d", bearerOf), func(t *testing.T) {
			m := newMCPWorld(t)
			u := m.user(m.admins())
			tokens := m.chain(u)
			for i, token := range tokens {
				if r := m.me(token); r.status != http.StatusOK {
					t.Fatalf("token %d before logout: %d %s", i, r.status, r.body)
				}
			}
			m.e.sessions.mu.Lock()
			members, ttl := len(m.e.sessions.chains[bindingID(u.sub, u.authTime)]), m.e.sessions.chainTTLs[bindingID(u.sub, u.authTime)]
			m.e.sessions.mu.Unlock()
			if members != 3 || ttl < 7*time.Hour {
				t.Fatalf("chain of %d records living %s, want 3 records for the binding's lifetime", members, ttl)
			}
			other := m.user(m.admins())
			otherToken, r := m.login(other, nil)
			if r.status != http.StatusNoContent {
				t.Fatalf("login of another user: %d %s", r.status, r.body)
			}

			m.logout(tokens[bearerOf])
			for i, token := range tokens {
				expectProblem(t, fmt.Sprintf("token %d after logout", i), m.me(token), http.StatusUnauthorized, "mcp_login_required")
			}
			if m.bound(u) {
				t.Fatal("logout left the binding")
			}
			if r := m.me(otherToken); r.status != http.StatusOK {
				t.Fatalf("another chain after logout: %d %s", r.status, r.body)
			}
		})
	}
}

// TestMCPBindingEndEndsRefreshChain: a renewal that finds its binding made stale by End all sessions ends the chain's
// records with the binding, and a mismatching renewal ends them with the account's sessions (PDK-468).
func TestMCPBindingEndEndsRefreshChain(t *testing.T) {
	m := newMCPWorld(t)
	u := m.user(m.admins())
	tokens := m.chain(u)
	if _, err := m.e.sessions.EndAll(context.Background()); err != nil {
		t.Fatal(err)
	}
	id, renewed := m.pair(u, nil, 30*time.Minute)
	expectProblem(t, "renewal of a stale binding", m.open(id, renewed, nil), http.StatusUnauthorized, "mcp_login_required")
	for i, token := range tokens {
		if _, ok := m.record(token); ok {
			t.Fatalf("record %d survived the end of its stale binding", i)
		}
	}
	if m.bound(u) {
		t.Fatal("the stale binding is left")
	}

	v := m.user(m.admins())
	tokens = m.chain(v)
	v.groups = []string{organization.RoleGroup(m.slug, organization.GroupAuditors)}
	id, renewed = m.pair(v, nil, 30*time.Minute)
	expectProblem(t, "mismatching renewal", m.open(id, renewed, nil), http.StatusUnauthorized, "mcp_login_required")
	for i, token := range tokens {
		if _, ok := m.record(token); ok {
			t.Fatalf("record %d survived a mismatching renewal", i)
		}
	}
	m.e.sessions.mu.Lock()
	_, chainLeft := m.e.sessions.chains[bindingID(v.sub, v.authTime)]
	m.e.sessions.mu.Unlock()
	if chainLeft || m.bound(v) {
		t.Fatal("a mismatching renewal left the chain or the binding")
	}
}

// TestMCPRenewalRacingLogout: a logout between the binding lookup and the new record refuses the renewal without
// writing its record and without ending the account's other sessions.
func TestMCPRenewalRacingLogout(t *testing.T) {
	m := newMCPWorld(t)
	u := m.user(m.admins())
	first, r := m.login(u, nil)
	if r.status != http.StatusNoContent {
		t.Fatalf("login: %d %s", r.status, r.body)
	}
	rec, _ := m.record(first)
	portal := sessions.NewID()
	if _, err := m.e.sessions.Create(context.Background(), portal, sessions.Record{AccountID: rec.AccountID, Kind: rec.Kind,
		Role: rec.Role, Org: rec.Org}, time.Hour); err != nil {
		t.Fatal(err)
	}
	m.e.sessions.beforeCreate = func() {
		m.e.sessions.beforeCreate = nil
		m.logout(first)
	}
	id, renewed := m.pair(u, nil, 30*time.Minute)
	r = m.open(id, renewed, nil)
	expectProblem(t, "renewal racing logout", r, http.StatusUnauthorized, "mcp_login_required")
	if got := m.loginEvent(r); !strings.HasPrefix(got, "failure|mcp|true|") {
		t.Fatalf("event %s", got)
	}
	if _, ok := m.record(renewed); ok {
		t.Fatal("the renewal wrote its record after the logout")
	}
	m.e.sessions.mu.Lock()
	_, portalLeft := m.e.sessions.records[portal]
	m.e.sessions.mu.Unlock()
	if !portalLeft {
		t.Fatal("a renewal racing logout ended the account's portal session")
	}
}

// TestMCPSessionCallFailingAfterMarker: a session call that fails after its single-use marker keeps the marker (fail
// closed, PDK-468): the same tokens are refused as replayed. A renewal recovers on its own with the next refreshed ID
// token, which has a new jti; a first login needs paddockctl mcp login again.
func TestMCPSessionCallFailingAfterMarker(t *testing.T) {
	m := newMCPWorld(t)
	u := m.user(m.admins())
	if _, r := m.login(u, nil); r.status != http.StatusNoContent {
		t.Fatalf("login: %d %s", r.status, r.body)
	}
	id, renewed := m.pair(u, nil, 30*time.Minute)
	m.e.sessions.failing["Create"] = true
	r := m.open(id, renewed, nil)
	m.e.sessions.failing["Create"] = false
	if r.status == http.StatusNoContent {
		t.Fatal("the failing renewal succeeded")
	}
	expectProblem(t, "the same renewal again", m.open(id, renewed, nil), http.StatusUnauthorized, "mcp_login_required")
	id, renewed = m.pair(u, nil, 30*time.Minute)
	if r := m.open(id, renewed, nil); r.status != http.StatusNoContent {
		t.Fatalf("the next refreshed tokens: %d %s", r.status, r.body)
	}
	if r := m.me(renewed); r.status != http.StatusOK {
		t.Fatalf("the recovered session: %d %s", r.status, r.body)
	}

	fresh := m.user(m.admins())
	id, access := m.pair(fresh, []string{"pwd", "mfa"}, 30*time.Minute)
	m.e.sessions.failing["Create"] = true
	r = m.open(id, access, nil)
	m.e.sessions.failing["Create"] = false
	if r.status == http.StatusNoContent {
		t.Fatal("the failing login succeeded")
	}
	expectProblem(t, "the same login again", m.open(id, access, nil), http.StatusUnauthorized, "mcp_login_required")
	if m.bound(fresh) {
		t.Fatal("a failed login left a binding to renew")
	}
}

// TestMCPLogoutAfterBindingExpiry: logout ends the chain's records also when the binding is already gone, as it is
// after auth_time + 8 h while the records of the last renewals still live (PDK-468 review 1), against Valkey.
func TestMCPLogoutAfterBindingExpiry(t *testing.T) {
	c := valkeytest.Start(t).Client(t)
	store := sessions.NewStore(c)
	m := newMCPWorldWith(t, store)
	u := m.user(m.admins())
	tokens := m.chain(u)
	sum := sha256.Sum256([]byte(u.sub))
	if err := c.Do(context.Background(), c.B().Del().Key("mcp-bind:"+hex.EncodeToString(sum[:])+":"+
		strconv.FormatInt(u.authTime, 10)).Build()).Error(); err != nil {
		t.Fatal(err)
	}
	for i, token := range tokens {
		if r := m.me(token); r.status != http.StatusOK {
			t.Fatalf("token %d after the binding expired: %d %s", i, r.status, r.body)
		}
	}

	m.logout(tokens[2])
	for i, token := range tokens {
		expectProblem(t, fmt.Sprintf("token %d after logout", i), m.me(token), http.StatusUnauthorized, "mcp_login_required")
		if _, _, found, err := store.Get(context.Background(), sessionIDOf(token)); err != nil || found {
			t.Fatalf("record %d after logout: found %v %v", i, found, err)
		}
	}
}

// bindHookStore is the Valkey session store with a hook that runs before a first login's binding is written.
type bindHookStore struct {
	*sessions.Store
	beforeBind func()
}

func (s *bindHookStore) Bind(ctx context.Context, sid, sub string, authTime int64, b sessions.Binding, ttl time.Duration) (sessions.Binding, error) {
	if s.beforeBind != nil {
		s.beforeBind()
		s.beforeBind = nil
	}
	return s.Store.Bind(ctx, sid, sub, authTime, b, ttl)
}

// TestMCPLoginRacingChainEnd: a logout or a revocation between the record and the binding of a first login refuses the
// login with one audited failure and leaves no binding that would accept renewals of the ended login (PDK-546), against
// Valkey.
func TestMCPLoginRacingChainEnd(t *testing.T) {
	for name, end := range map[string]func(m *mcpWorld, store *sessions.Store, access string){
		"logout": func(m *mcpWorld, _ *sessions.Store, access string) { m.logout(access) },
		"revocation": func(m *mcpWorld, store *sessions.Store, access string) {
			rec, _, found, err := store.Get(context.Background(), sessionIDOf(access))
			if err != nil || !found {
				m.t.Fatalf("record before the binding: found %v %v", found, err)
			}
			if _, err := store.RevokeAccount(context.Background(), rec.AccountID); err != nil {
				m.t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			store := &bindHookStore{Store: sessions.NewStore(valkeytest.Start(t).Client(t))}
			m := newMCPWorldWith(t, store)
			u := m.user(m.admins())
			id, access := m.pair(u, []string{"pwd", "mfa"}, 30*time.Minute)
			store.beforeBind = func() { end(m, store.Store, access) }
			r := m.open(id, access, nil)
			expectProblem(t, "login racing "+name, r, http.StatusUnauthorized, "mcp_login_required")
			if got := m.loginEvent(r); !strings.HasPrefix(got, "failure|mcp|-|") {
				t.Fatalf("event %s", got)
			}
			if _, _, found, err := store.Binding(context.Background(), u.sub, u.authTime); err != nil || found {
				t.Fatalf("binding after the race: found %v %v", found, err)
			}
			expectProblem(t, "bearer", m.me(access), http.StatusUnauthorized, "mcp_login_required")
			renewID, renewed := m.pair(u, nil, 30*time.Minute)
			expectProblem(t, "renewal", m.open(renewID, renewed, nil), http.StatusUnauthorized, "mcp_login_required")
		})
	}
}

// TestMCPTokensOfDifferentLogins: an access token whose auth_time differs from the ID token's is refused with one
// audited failure and opens nothing, at a first login and at a renewal (PDK-546); a renewal pair carrying the login's
// auth_time, as Authentik issues it, still opens a session.
func TestMCPTokensOfDifferentLogins(t *testing.T) {
	m := newMCPWorld(t)
	u := m.user(m.admins())
	other := u
	other.authTime--
	refused := func(name string, amr []string) {
		t.Helper()
		id, _ := m.pair(u, amr, 30*time.Minute)
		_, access := m.pair(other, amr, 30*time.Minute)
		r := m.open(id, access, nil)
		expectProblem(t, name, r, http.StatusBadRequest, "invalid_request")
		if got := m.loginEvent(r); !strings.HasPrefix(got, "failure|mcp|-|-|login_failed|") {
			t.Fatalf("%s: event %s", name, got)
		}
		if _, ok := m.record(access); ok {
			t.Fatalf("%s: a record was opened", name)
		}
	}
	refused("first login", []string{"pwd", "mfa"})
	if m.bound(u) || m.bound(other) {
		t.Fatal("a refused first login left a binding")
	}

	if _, r := m.login(u, nil); r.status != http.StatusNoContent {
		t.Fatalf("login: %d %s", r.status, r.body)
	}
	refused("renewal", nil)
	id, renewed := m.pair(u, nil, 30*time.Minute)
	if r := m.open(id, renewed, nil); r.status != http.StatusNoContent {
		t.Fatalf("renewal with the login's auth_time: %d %s", r.status, r.body)
	}
	if r := m.me(renewed); r.status != http.StatusOK {
		t.Fatalf("renewed bearer: %d %s", r.status, r.body)
	}
}
