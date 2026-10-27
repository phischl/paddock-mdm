package admin_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/domain/organization"
	"github.com/phischl/paddock-mdm/server/internal/transport/http/admin"
	"github.com/phischl/paddock-mdm/server/internal/transport/http/admin/adminapi"
)

// twoRoles is an identity in paddock.platform.admins and in one role group of acme (ADR 0045).
type twoRoles struct {
	w        *loginWorld
	sub      string
	username string
}

func newTwoRoles(w *loginWorld) *twoRoles {
	return &twoRoles{w: w, sub: "sub-" + uuid.NewString(), username: "dual-" + uuid.NewString() + "@acme.test"}
}

// claims are the ID token claims of the identity with groups.
func (u *twoRoles) claims(groups ...string) map[string]any {
	return map[string]any{"aud": "paddock-portal", "sub": u.sub, "preferred_username": u.username, "amr": []string{"pwd", "mfa"},
		"groups": groups}
}

func (u *twoRoles) both() map[string]any {
	return u.claims(organization.PlatformAdminsGroup(), organization.RoleGroup(u.w.slug, organization.GroupAdmins))
}

// signIn runs a plain sign-in and returns the session cookie.
func (u *twoRoles) signIn(claims map[string]any) *http.Cookie {
	u.w.t.Helper()
	res := u.w.login(context.Background(), claims)
	c := cookieOf(res, admin.SessionCookie)
	if res.Code != http.StatusFound || res.Header().Get("Location") != "/" || c == nil {
		u.w.t.Fatalf("sign-in: %d %s", res.Code, res.Header().Get("Location"))
	}
	return &http.Cookie{Name: admin.SessionCookie, Value: c.Value}
}

// startSwitch runs POST /api/auth/switch with the CSRF header and returns its result.
func (u *twoRoles) startSwitch(c *http.Cookie, body map[string]any) result {
	u.w.t.Helper()
	return postSwitch(u.w.e, c, body, true)
}

// postSwitch sends POST /api/auth/switch. The BFF endpoints are hand-written and not part of the embedded contract
// the env validates against (oapi-codegen excludes the auth tag), so the request goes to the handler directly.
func postSwitch(e *env, c *http.Cookie, body map[string]any, csrf bool) result {
	e.t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		e.t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "https://admin.test/api/auth/switch", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	if csrf {
		req.Header.Set("X-Paddock-CSRF", "1")
	}
	if c != nil {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	e.handler.ServeHTTP(rec, req)
	return result{status: rec.Code, header: rec.Header(), body: rec.Body.Bytes()}
}

// complete follows the authorization URL of a started switch: the identity provider issues claims and Authentik
// redirects back to the callback with the paddock_login cookie only (the session cookie is SameSite=Strict).
func (u *twoRoles) complete(start result, claims map[string]any) *httptest.ResponseRecorder {
	u.w.t.Helper()
	var body struct {
		AuthorizeURL string `json:"authorize_url"`
	}
	start.decode(u.w.t, &body)
	loc, err := url.Parse(body.AuthorizeURL)
	if err != nil || !strings.HasPrefix(body.AuthorizeURL, u.w.idp.URL+"/authorize") || loc.Query().Get("client_id") != "paddock-portal" {
		u.w.t.Fatalf("authorize_url %q: %v", body.AuthorizeURL, err)
	}
	var login *http.Cookie
	for _, c := range (&http.Response{Header: start.header}).Cookies() {
		if c.Name == admin.LoginCookie {
			login = c
		}
	}
	if login == nil || login.SameSite != http.SameSiteLaxMode || login.Path != "/api/auth" {
		u.w.t.Fatalf("login cookie %+v", login)
	}
	u.w.idp.mu.Lock()
	u.w.idp.claims, u.w.idp.nonce = claims, loc.Query().Get("nonce")
	u.w.idp.mu.Unlock()
	req := httptest.NewRequest(http.MethodGet,
		"https://admin.test/api/auth/callback?code=c&state="+url.QueryEscape(loc.Query().Get("state")), nil)
	req.AddCookie(login)
	rec := httptest.NewRecorder()
	u.w.e.handler.ServeHTTP(rec, req)
	return rec
}

func (u *twoRoles) session(c *http.Cookie) admin.Session {
	u.w.t.Helper()
	var s admin.Session
	if err := u.w.e.keys.Open(admin.SessionCookie, c.Value, &s); err != nil {
		u.w.t.Fatal(err)
	}
	return s
}

func (u *twoRoles) me(c *http.Cookie) adminapi.Me {
	u.w.t.Helper()
	r := u.w.e.do(call{method: "GET", path: "/api/v1/me", cookie: c})
	if r.status != http.StatusOK {
		u.w.t.Fatalf("GET /api/v1/me: %d %s", r.status, r.body)
	}
	var m adminapi.Me
	r.decode(u.w.t, &m)
	return m
}

// logins are the admin.login events of the identity: "<organization>|<outcome>|<previous_role>|<target type>|<denial>".
func (u *twoRoles) logins() []string {
	u.w.t.Helper()
	rows, err := u.w.e.super.Query(context.Background(), `SELECT organization_id::text || '|' || outcome || '|' ||
		coalesce(params->>'previous_role', '-') || '|' || coalesce(target->>'type', '-') || '|' || coalesce(params->>'denial_reason', '-')
		FROM action WHERE code = 'admin.login' AND actor->>'display' = $1 ORDER BY started_at, id`, u.username)
	if err != nil {
		u.w.t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			u.w.t.Fatal(err)
		}
		out = append(out, s)
	}
	return out
}

func (u *twoRoles) hasRecord(sid string) bool {
	u.w.e.sessions.mu.Lock()
	defer u.w.e.sessions.mu.Unlock()
	_, ok := u.w.e.sessions.records[sid]
	return ok
}

func cookieFrom(rec *httptest.ResponseRecorder) *http.Cookie {
	c := cookieOf(rec, admin.SessionCookie)
	if c == nil || c.Value == "" {
		return nil
	}
	return &http.Cookie{Name: admin.SessionCookie, Value: c.Value}
}

// TestRoleSwitch covers ADR 0045 decisions 3 and 4: a two-role identity signs in to its organization role, sees the
// platform role as alternate_role, and switches to platform administration and back; every switch is a new session
// that ends the previous one and is recorded once, in the scope it enters, with previous_role.
func TestRoleSwitch(t *testing.T) {
	w := newLoginWorld(t, nil)
	e := w.e
	u := newTwoRoles(w)
	acme := e.acme.String()
	platform := uuid.Nil.String()

	orgCookie := u.signIn(u.both())
	orgSess := u.session(orgCookie)
	if orgSess.Kind != "admin" || orgSess.Role != "org_admin" || orgSess.Org != e.acme || orgSess.AltRole != "platform_admin" ||
		orgSess.AltSlug != "" {
		t.Fatalf("sign-in session %+v", orgSess)
	}
	m := u.me(orgCookie)
	if m.Role != adminapi.MeRoleOrgAdmin || m.AlternateRole == nil || m.AlternateRole.Role != adminapi.MeAlternateRoleRolePlatformAdmin ||
		m.AlternateRole.OrganizationSlug != nil {
		t.Fatalf("me after sign-in: role %s, alternate %+v", m.Role, m.AlternateRole)
	}
	if r := e.do(call{method: "GET", path: "/api/platform/v1/organizations", cookie: orgCookie}); r.status != http.StatusForbidden ||
		r.problemCode(t) != "forbidden" {
		t.Fatalf("platform API from the organization session: %d %s", r.status, r.body)
	}
	if got := u.logins(); len(got) != 1 || got[0] != acme+"|success|-|admin_account|-" {
		t.Fatalf("sign-in events %v", got)
	}

	start := u.startSwitch(orgCookie, map[string]any{"role": "platform", "return_to": "/organizations"})
	if start.status != http.StatusOK {
		t.Fatalf("switch: %d %s", start.status, start.body)
	}
	if !u.hasRecord(orgSess.SID) {
		t.Fatal("starting the switch ended the session")
	}
	res := u.complete(start, u.both())
	platCookie := cookieFrom(res)
	if res.Code != http.StatusFound || res.Header().Get("Location") != "/organizations" || platCookie == nil {
		t.Fatalf("switch callback: %d %s", res.Code, res.Header().Get("Location"))
	}
	platSess := u.session(platCookie)
	if platSess.Kind != "platform_admin" || platSess.Role != "platform_admin" || platSess.Org != uuid.Nil ||
		platSess.AltRole != "org_admin" || platSess.AltSlug != w.slug || platSess.StepUpAt != 0 || platSess.SID == orgSess.SID ||
		platSess.PID == orgSess.PID {
		t.Fatalf("switched session %+v", platSess)
	}
	if u.hasRecord(orgSess.SID) || !u.hasRecord(platSess.SID) {
		t.Fatalf("records: previous present %v, new present %v", u.hasRecord(orgSess.SID), u.hasRecord(platSess.SID))
	}
	if got := u.logins(); len(got) != 2 || got[1] != platform+"|success|org_admin|platform_admin|-" {
		t.Fatalf("switch events %v", got)
	}
	if n := countRevoked(t, e, orgSess.PID, platSess.PID); n != 0 {
		t.Fatalf("%d admin.sessions_revoked events", n)
	}
	if r := e.do(call{method: "GET", path: "/api/v1/me", cookie: orgCookie}); r.status != http.StatusUnauthorized ||
		r.problemCode(t) != "unauthenticated" {
		t.Fatalf("previous cookie: %d %s", r.status, r.body)
	}
	m = u.me(platCookie)
	if m.Role != adminapi.MeRolePlatformAdmin || m.AlternateRole == nil || m.AlternateRole.Role != adminapi.MeAlternateRoleRoleOrgAdmin ||
		m.AlternateRole.OrganizationSlug == nil || *m.AlternateRole.OrganizationSlug != w.slug {
		t.Fatalf("me after the switch: role %s, alternate %+v", m.Role, m.AlternateRole)
	}
	if r := e.do(call{method: "GET", path: "/api/v1/device-groups", cookie: platCookie}); r.status != http.StatusForbidden ||
		r.problemCode(t) != "no_organization" {
		t.Fatalf("organization API from the platform session: %d %s", r.status, r.body)
	}

	back := u.startSwitch(platCookie, map[string]any{"role": "organization"})
	if back.status != http.StatusOK {
		t.Fatalf("switch back: %d %s", back.status, back.body)
	}
	res = u.complete(back, u.both())
	backCookie := cookieFrom(res)
	if res.Code != http.StatusFound || res.Header().Get("Location") != "/" || backCookie == nil {
		t.Fatalf("switch back callback: %d %s", res.Code, res.Header().Get("Location"))
	}
	backSess := u.session(backCookie)
	if backSess.Role != "org_admin" || backSess.Org != e.acme || backSess.PID != orgSess.PID || backSess.AltRole != "platform_admin" ||
		u.hasRecord(platSess.SID) || !u.hasRecord(backSess.SID) {
		t.Fatalf("switched back session %+v", backSess)
	}
	if got := u.logins(); len(got) != 3 || got[2] != acme+"|success|platform_admin|admin_account|-" {
		t.Fatalf("switch back events %v", got)
	}
}

// TestRoleSwitchRefusals: the switch endpoint answers per the table of ADR 0045 and changes nothing when it refuses.
func TestRoleSwitchRefusals(t *testing.T) {
	w := newLoginWorld(t, nil)
	e := w.e
	u := newTwoRoles(w)
	orgCookie := u.signIn(u.both())
	single := e.session(e.acme, "org_admin")
	problemOf := func(r result) string {
		t.Helper()
		return r.problemCode(t)
	}

	if r := postSwitch(e, nil, map[string]any{"role": "platform"}, true); r.status != http.StatusUnauthorized ||
		problemOf(r) != "unauthenticated" {
		t.Fatalf("without a session: %d %s", r.status, r.body)
	}
	if r := u.startSwitch(single, map[string]any{"role": "platform"}); r.status != http.StatusBadRequest || problemOf(r) != "invalid_request" {
		t.Fatalf("single-role session: %d %s", r.status, r.body)
	}
	if r := u.startSwitch(orgCookie, map[string]any{"role": "organization"}); r.status != http.StatusBadRequest ||
		problemOf(r) != "invalid_request" {
		t.Fatalf("the active side: %d %s", r.status, r.body)
	}
	if r := u.startSwitch(orgCookie, map[string]any{"role": "platform", "return_to": "https://evil.example/"}); r.status != http.StatusBadRequest ||
		problemOf(r) != "invalid_request" {
		t.Fatalf("absolute return_to: %d %s", r.status, r.body)
	}
	if r := postSwitch(e, orgCookie, map[string]any{"role": "platform"}, false); r.status != http.StatusForbidden ||
		problemOf(r) != "csrf_missing" {
		t.Fatalf("without CSRF header: %d %s", r.status, r.body)
	}

	e.sessions.mu.Lock()
	e.sessions.down = true
	e.sessions.mu.Unlock()
	r := u.startSwitch(orgCookie, map[string]any{"role": "platform"})
	e.sessions.mu.Lock()
	e.sessions.down = false
	e.sessions.mu.Unlock()
	if r.status != http.StatusServiceUnavailable || problemOf(r) != "session_store_unavailable" {
		t.Fatalf("session store down: %d %s", r.status, r.body)
	}

	sid := u.session(orgCookie).SID
	e.sessions.mu.Lock()
	delete(e.sessions.records, sid)
	e.sessions.mu.Unlock()
	r = u.startSwitch(orgCookie, map[string]any{"role": "platform"})
	cleared := false
	for _, c := range (&http.Response{Header: r.header}).Cookies() {
		cleared = cleared || (c.Name == admin.SessionCookie && c.MaxAge < 0)
	}
	if r.status != http.StatusUnauthorized || problemOf(r) != "unauthenticated" || !cleared {
		t.Fatalf("ended session: %d %s, cookie cleared %v", r.status, r.body, cleared)
	}
	if got := u.logins(); len(got) != 1 {
		t.Fatalf("refused switches recorded events: %v", got)
	}
}

// TestRoleSwitchNotGranted: a switch whose role the fresh groups claim no longer grants is refused with
// role_not_granted and one denied admin.login; the previous session stays. A switch state of another user is a plain
// sign-in of the token's user.
func TestRoleSwitchNotGranted(t *testing.T) {
	w := newLoginWorld(t, nil)
	e := w.e
	acme := e.acme.String()

	t.Run("platform role removed meanwhile", func(t *testing.T) {
		u := newTwoRoles(w)
		orgCookie := u.signIn(u.both())
		sid := u.session(orgCookie).SID
		before := len(e.sessions.records)
		start := u.startSwitch(orgCookie, map[string]any{"role": "platform"})
		if start.status != http.StatusOK {
			t.Fatalf("switch: %d %s", start.status, start.body)
		}
		res := u.complete(start, u.claims(organization.RoleGroup(w.slug, organization.GroupAdmins)))
		if res.Code != http.StatusFound || res.Header().Get("Location") != "/login-denied?reason=role_not_granted" || cookieFrom(res) != nil {
			t.Fatalf("callback: %d %s", res.Code, res.Header().Get("Location"))
		}
		if got := u.logins(); len(got) != 2 || got[1] != acme+"|denied|-|-|role_not_granted" {
			t.Fatalf("events %v", got)
		}
		if !u.hasRecord(sid) || len(e.sessions.records) != before {
			t.Fatalf("records: previous present %v, %d records, want %d", u.hasRecord(sid), len(e.sessions.records), before)
		}
		if m := u.me(orgCookie); m.Role != adminapi.MeRoleOrgAdmin {
			t.Fatalf("previous session after the refusal: %s", m.Role)
		}
	})
	t.Run("switch state of another user", func(t *testing.T) {
		u := newTwoRoles(w)
		orgCookie := u.signIn(u.both())
		sid := u.session(orgCookie).SID
		start := u.startSwitch(orgCookie, map[string]any{"role": "platform"})
		if start.status != http.StatusOK {
			t.Fatalf("switch: %d %s", start.status, start.body)
		}
		other := newTwoRoles(w)
		res := u.complete(start, other.both())
		c := cookieFrom(res)
		if res.Code != http.StatusFound || c == nil {
			t.Fatalf("callback: %d %s", res.Code, res.Header().Get("Location"))
		}
		if s := other.session(c); s.Sub != other.sub || s.Role != "org_admin" || s.Org != e.acme || s.AltRole != "platform_admin" {
			t.Fatalf("session of the other user %+v", s)
		}
		if !u.hasRecord(sid) {
			t.Fatal("a foreign switch state ended the session")
		}
		if got := other.logins(); len(got) != 1 || got[0] != acme+"|success|-|admin_account|-" {
			t.Fatalf("events of the other user %v", got)
		}
	})
}

// TestMeAlternateRole: alternate_role is null for API tokens and single-role sessions, and PATCH /api/v1/me answers
// the same alternate_role as GET (ADR 0045 decision 3).
func TestMeAlternateRole(t *testing.T) {
	w := newLoginWorld(t, nil)
	e := w.e
	u := newTwoRoles(w)
	if m := u.me(e.session(e.acme, "org_admin")); m.AlternateRole != nil {
		t.Fatalf("single-role organization session: %+v", m.AlternateRole)
	}
	if m := u.me(e.platformSession()); m.AlternateRole != nil {
		t.Fatalf("single-role platform session: %+v", m.AlternateRole)
	}
	alice := e.session(e.acme, "org_admin")
	token := e.createAPIToken("acme", alice, "ci", adminapi.ApiTokenRoleOrgAdmin)
	r := e.do(call{method: "GET", path: "/api/v1/me", headers: bearer(token.Secret)})
	if r.status != http.StatusOK || !strings.Contains(string(r.body), `"alternate_role":null`) {
		t.Fatalf("API token: %d %s", r.status, r.body)
	}
	dual := u.signIn(u.both())
	r = e.do(call{method: "PATCH", path: "/api/v1/me", cookie: dual, body: map[string]any{"locale": "de"}})
	var m adminapi.Me
	if r.status != http.StatusOK {
		t.Fatalf("PATCH /api/v1/me: %d %s", r.status, r.body)
	}
	r.decode(t, &m)
	if m.AlternateRole == nil || m.AlternateRole.Role != adminapi.MeAlternateRoleRolePlatformAdmin || m.AlternateRole.OrganizationSlug != nil {
		t.Fatalf("PATCH alternate_role %+v", m.AlternateRole)
	}
}

// countRevoked counts the admin.sessions_revoked events of the accounts.
func countRevoked(t *testing.T, e *env, ids ...uuid.UUID) int {
	t.Helper()
	n := 0
	for _, id := range ids {
		var c int
		if err := e.super.QueryRow(context.Background(), `SELECT count(*) FROM action WHERE code = 'admin.sessions_revoked'
			AND target->>'id' = $1`, id.String()).Scan(&c); err != nil {
			t.Fatal(err)
		}
		n += c
	}
	return n
}
