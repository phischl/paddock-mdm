package admin_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/sessions"
	"github.com/phischl/paddock-mdm/server/internal/transport/http/admin"
	"github.com/phischl/paddock-mdm/server/internal/transport/http/admin/adminapi"
)

// cleared reports whether the response clears the session cookie.
func cleared(h http.Header) bool {
	for _, c := range (&http.Response{Header: h}).Cookies() {
		if c.Name == admin.SessionCookie && c.MaxAge < 0 {
			return true
		}
	}
	return false
}

// sessionOf opens a session cookie.
func (e *env) sessionOf(c *http.Cookie) admin.Session {
	e.t.Helper()
	var sess admin.Session
	if err := e.keys.Open(admin.SessionCookie, c.Value, &sess); err != nil {
		e.t.Fatal(err)
	}
	return sess
}

// TestServerSideSessions covers plan M8s decision 14: a cookie is only valid with its record, of the current
// generation and of the same account, role and organization; an unreachable store answers 503 and keeps the cookie;
// API tokens never read the store; a re-issued cookie extends the record; logout deletes it.
func TestServerSideSessions(t *testing.T) {
	e := newEnv(t)
	me := func(c *http.Cookie) result { return e.do(call{method: "GET", path: "/api/v1/me", cookie: c}) }

	alice := e.session(e.acme, principal.RoleOrgAdmin)
	if r := me(alice); r.status != http.StatusOK {
		t.Fatalf("session with its record: %d %s", r.status, r.body)
	}

	sess := e.sessionOf(alice)
	if err := e.sessions.Delete(context.Background(), sess.SID, sess.PID); err != nil {
		t.Fatal(err)
	}
	if r := me(alice); r.status != http.StatusUnauthorized || r.problemCode(t) != "unauthenticated" || !cleared(r.header) {
		t.Fatalf("cookie without its record: %d %s %v", r.status, r.body, r.header.Values("Set-Cookie"))
	}

	for name, edit := range map[string]func(*sessions.Record){
		"another account":      func(r *sessions.Record) { r.AccountID = uuid.Must(uuid.NewV7()) },
		"another role":         func(r *sessions.Record) { r.Role = string(principal.RoleOrgAuditor) },
		"another organization": func(r *sessions.Record) { r.Org = e.globex },
	} {
		c := e.session(e.acme, principal.RoleOrgAdmin)
		s := e.sessionOf(c)
		e.sessions.mu.Lock()
		rec := e.sessions.records[s.SID]
		edit(&rec)
		e.sessions.records[s.SID] = rec
		e.sessions.mu.Unlock()
		if r := me(c); r.status != http.StatusUnauthorized || !cleared(r.header) {
			t.Errorf("record of %s: %d", name, r.status)
		}
	}

	bob := e.session(e.acme, principal.RoleOrgAuditor)
	if _, err := e.sessions.EndAll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if r := me(bob); r.status != http.StatusUnauthorized || !cleared(r.header) {
		t.Fatalf("session of an older generation: %d", r.status)
	}
	carol := e.session(e.acme, principal.RoleOrgAdmin)
	if r := me(carol); r.status != http.StatusOK {
		t.Fatalf("session of the current generation: %d", r.status)
	}

	token := e.createAPIToken("acme", carol, "sessions", adminapi.ApiTokenRoleOrgAuditor)
	e.sessions.down = true
	req := httptest.NewRequest(http.MethodGet, "https://admin.test/api/v1/me", nil)
	req.AddCookie(carol)
	rec := httptest.NewRecorder()
	e.handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), `"session_store_unavailable"`) || cleared(rec.Header()) {
		t.Fatalf("store unreachable: %d %s %v", rec.Code, rec.Body, rec.Header().Values("Set-Cookie"))
	}
	calls := e.sessions.calls
	if r := e.do(call{method: "GET", path: "/api/v1/me", headers: bearer(token.Secret)}); r.status != http.StatusOK {
		t.Fatalf("API token while the store is unreachable: %d %s", r.status, r.body)
	}
	if e.sessions.calls != calls {
		t.Fatal("an API token request read the session store")
	}
	e.sessions.down = false
	if r := me(carol); r.status != http.StatusOK {
		t.Fatalf("the cookie after the store is back: %d", r.status)
	}

	idle := e.sessionOf(carol)
	idle.Idle = time.Now().Add(-6 * time.Minute).Unix()
	v, err := e.keys.Seal(admin.SessionCookie, idle)
	if err != nil {
		t.Fatal(err)
	}
	touched := len(e.sessions.touched)
	if r := me(&http.Cookie{Name: admin.SessionCookie, Value: v}); r.status != http.StatusOK || len(e.sessions.touched) != touched+1 ||
		e.sessions.touched[touched] != idle.SID {
		t.Fatalf("re-issued cookie: %d, touched %v", r.status, e.sessions.touched)
	}

	req = httptest.NewRequest(http.MethodPost, "https://admin.test/api/auth/logout", nil)
	req.Header.Set("X-Paddock-CSRF", "1")
	req.AddCookie(carol)
	rec = httptest.NewRecorder()
	e.handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !cleared(rec.Header()) {
		t.Fatalf("logout: %d %s", rec.Code, rec.Body)
	}
	if r := me(carol); r.status != http.StatusUnauthorized {
		t.Fatalf("the cookie after logout: %d", r.status)
	}
}

// TestEndAllSessions covers plan M8s decision 16: a platform administrator with a step-up ends every session (the
// own one included) and the event is recorded; without step-up and for organization administrators it is refused.
func TestEndAllSessions(t *testing.T) {
	e := newEnv(t)
	root := e.platformSession()
	alice := e.session(e.acme, principal.RoleOrgAdmin)

	r := e.do(call{method: "POST", path: "/api/platform/v1/sessions/end-all", cookie: root})
	if r.status != http.StatusForbidden || r.problemCode(t) != "step_up_required" {
		t.Fatalf("without step-up: %d %s", r.status, r.body)
	}
	e.expectEvent(r, "platform.sessions_ended:denied:step_up_required")

	r = e.do(call{method: "POST", path: "/api/platform/v1/sessions/end-all", cookie: e.steppedUp(alice, time.Now())})
	if r.status != http.StatusForbidden || r.problemCode(t) != "forbidden" {
		t.Fatalf("organization administrator: %d %s", r.status, r.body)
	}
	e.expectEvent(r, "platform.sessions_ended:denied:forbidden")

	stepped := e.steppedUp(root, time.Now())
	r = e.do(call{method: "POST", path: "/api/platform/v1/sessions/end-all", cookie: stepped})
	var ended adminapi.SessionsEnded
	r.decode(t, &ended)
	if r.status != http.StatusOK || ended.Generation != 1 {
		t.Fatalf("end all: %d %s", r.status, r.body)
	}
	e.expectEvent(r, "platform.sessions_ended:success:")
	for name, c := range map[string]*http.Cookie{"own": stepped, "other": alice} {
		if r := e.do(call{method: "GET", path: "/api/v1/me", cookie: c}); r.status != http.StatusUnauthorized {
			t.Errorf("%s session after end all: %d", name, r.status)
		}
	}
}
