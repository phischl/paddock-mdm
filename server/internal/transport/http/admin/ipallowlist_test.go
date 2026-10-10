package admin_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/pgtest"
	"github.com/phischl/paddock-mdm/server/internal/transport/http/admin"
	"github.com/phischl/paddock-mdm/server/internal/transport/http/admin/adminapi"
)

// allowlistEnv is the handler test environment with the IP allow list and its guard installed, as serveAPI does.
type allowlistEnv struct {
	*env
	guard *admin.IPGuard
}

func newAllowlistEnv(t *testing.T) *allowlistEnv {
	t.Helper()
	ctx := context.Background()
	platform, err := db.NewPlatformPool(ctx, pgtest.SharedPaddock(t).Platform, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(platform.Close)
	var guard *admin.IPGuard
	e := newEnvWith(t, func(d *admin.Deps) {
		list := app.NewIPAllowlist(d.Runner, platform, nil)
		guard = admin.NewIPGuard(list.Load, nil, nil, false)
		list.AfterChange(func(ctx context.Context) { _ = guard.Reload(ctx) })
		d.IPAllowlist, d.IPGuard = list, guard
	})
	// The table is platform-wide: start from and leave an empty list, with the guard following.
	clear := func() {
		if _, err := e.super.Exec(ctx, "DELETE FROM ip_allowlist_entry"); err != nil {
			t.Fatal(err)
		}
		if err := guard.Reload(ctx); err != nil {
			t.Fatal(err)
		}
	}
	clear()
	t.Cleanup(clear)
	return &allowlistEnv{env: e, guard: guard}
}

// TestIPAllowlistEndpoints: step-up, the consequence confirmations, duplicates, the list and exactly one audit event
// per attempt (plan M7a decisions 12 and 16). httptest requests come from 192.0.2.1.
func TestIPAllowlistEndpoints(t *testing.T) {
	e := newAllowlistEnv(t)
	root := e.platformSession()
	su := e.steppedUp(root, time.Now())
	const base = "/api/platform/v1/ip-allowlist"

	r := e.do(call{method: "POST", path: base, cookie: root, body: map[string]string{"cidr": "192.0.2.0/24", "label": "test"}})
	if r.status != http.StatusForbidden || r.problemCode(t) != "step_up_required" {
		t.Fatalf("without step-up: %d %s", r.status, r.body)
	}
	e.expectEvent(r, "platform.ip_allowlist_changed:denied:step_up_required")

	r = e.do(call{method: "POST", path: base, cookie: su, body: map[string]string{"cidr": "198.51.100.0/24", "label": "office"}})
	if r.status != http.StatusConflict || r.problemCode(t) != "lockout_confirmation_required" {
		t.Fatalf("first entry excluding the caller: %d %s", r.status, r.body)
	}
	e.expectEvent(r, "platform.ip_allowlist_changed:failure:lockout_confirmation_required")
	if l := e.do(call{method: "GET", path: base, cookie: root}); !strings.Contains(string(l.body), `"total":0`) {
		t.Fatalf("nothing changed: %s", l.body)
	}

	r = e.do(call{method: "POST", path: base, cookie: su, body: map[string]string{"cidr": "10.0.0.1/8", "label": "bad"}})
	if r.status != http.StatusBadRequest || !strings.Contains(string(r.body), "use 10.0.0.0/8") {
		t.Fatalf("host bits: %d %s", r.status, r.body)
	}
	e.expectEvent(r, "platform.ip_allowlist_changed:failure:invalid_request")
	r = e.do(call{method: "POST", path: base + "?confirm=bogus", cookie: su, skipReqCheck: true,
		body: map[string]string{"cidr": "192.0.2.0/24", "label": "test"}})
	if r.status != http.StatusBadRequest || r.problemCode(t) != "invalid_request" {
		t.Fatalf("unknown confirm: %d %s", r.status, r.body)
	}
	e.expectEvent(r, "platform.ip_allowlist_changed:failure:invalid_request")
	r = e.do(call{method: "POST", path: base, cookie: su, rawBody: "{", skipReqCheck: true})
	if r.status != http.StatusBadRequest {
		t.Fatalf("malformed body: %d %s", r.status, r.body)
	}
	e.expectEvent(r, "platform.ip_allowlist_changed:failure:invalid_request")
	r = e.do(call{method: "POST", path: base, cookie: su, noCSRF: true, skipReqCheck: true, body: map[string]string{"cidr": "192.0.2.0/24", "label": "test"}})
	if r.status != http.StatusForbidden || r.problemCode(t) != "csrf_missing" {
		t.Fatalf("without CSRF header: %d %s", r.status, r.body)
	}
	e.expectEvent(r, "platform.ip_allowlist_changed:denied:csrf_missing")

	r = e.do(call{method: "POST", path: base, cookie: su, body: map[string]string{"cidr": "192.0.2.0/24", "label": " test "}})
	if r.status != http.StatusCreated {
		t.Fatalf("own range: %d %s", r.status, r.body)
	}
	var mine adminapi.IpAllowlistEntry
	r.decode(t, &mine)
	if !mine.CoversCaller || mine.Label != "test" || mine.CreatedBy != "root@test" || r.header.Get("Location") != base+"/"+mine.Id.String() {
		t.Fatalf("created %+v location %q", mine, r.header.Get("Location"))
	}
	e.expectEvent(r, "platform.ip_allowlist_changed:success:")

	// The list is on now: the test client (192.0.2.1) is covered, another address is refused before the session.
	if g := e.do(call{method: "GET", path: "/api/v1/me", cookie: root}); g.status != http.StatusOK {
		t.Fatalf("covered caller: %d", g.status)
	}
	r = e.do(call{method: "POST", path: base, cookie: su, body: map[string]string{"cidr": "198.51.100.0/24", "label": "office"}})
	if r.status != http.StatusCreated {
		t.Fatalf("second entry: %d %s", r.status, r.body)
	}
	var office adminapi.IpAllowlistEntry
	r.decode(t, &office)
	if office.CoversCaller {
		t.Fatal("office covers the caller")
	}
	r = e.do(call{method: "POST", path: base, cookie: su, body: map[string]string{"cidr": "198.51.100.0/24", "label": "again"}})
	if r.status != http.StatusConflict || r.problemCode(t) != "already_exists" {
		t.Fatalf("duplicate: %d %s", r.status, r.body)
	}
	e.expectEvent(r, "platform.ip_allowlist_changed:failure:already_exists")

	l := e.do(call{method: "GET", path: base + "?sort=-cidr&q=offi", cookie: root})
	var page struct {
		Items []adminapi.IpAllowlistEntry `json:"items"`
		Total int                         `json:"total"`
		Sort  string                      `json:"sort"`
	}
	l.decode(t, &page)
	if l.status != http.StatusOK || page.Total != 1 || len(page.Items) != 1 || page.Items[0].Id != office.Id || page.Sort != "-cidr" {
		t.Fatalf("list: %d %s", l.status, l.body)
	}
	l = e.do(call{method: "GET", path: base + "?q=192.0", cookie: root})
	l.decode(t, &page)
	if page.Total != 1 || page.Items[0].Id != mine.Id {
		t.Fatalf("search by cidr: %s", l.body)
	}
	if g := e.do(call{method: "GET", path: base + "/" + office.Id.String(), cookie: root}); g.status != http.StatusOK {
		t.Fatalf("get: %d %s", g.status, g.body)
	}
	if g := e.do(call{method: "GET", path: base + "/" + uuid.NewString(), cookie: root}); g.status != http.StatusNotFound {
		t.Fatalf("get unknown: %d", g.status)
	}

	r = e.do(call{method: "PATCH", path: base + "/" + office.Id.String(), cookie: su, body: map[string]string{"label": "branch"}})
	if r.status != http.StatusOK || !strings.Contains(string(r.body), `"label":"branch"`) {
		t.Fatalf("patch: %d %s", r.status, r.body)
	}
	e.expectEvent(r, "platform.ip_allowlist_changed:success:")
	r = e.do(call{method: "PATCH", path: base + "/" + office.Id.String(), cookie: su, body: map[string]string{}})
	if r.status != http.StatusBadRequest {
		t.Fatalf("empty patch: %d %s", r.status, r.body)
	}
	e.expectEvent(r, "platform.ip_allowlist_changed:failure:invalid_request")
	r = e.do(call{method: "PATCH", path: base + "/" + mine.Id.String(), cookie: su, body: map[string]string{"cidr": "203.0.113.0/24"}})
	if r.status != http.StatusConflict || r.problemCode(t) != "lockout_confirmation_required" {
		t.Fatalf("moving the own range away: %d %s", r.status, r.body)
	}
	r = e.do(call{method: "PATCH", path: base + "/" + uuid.NewString(), cookie: su, body: map[string]string{"label": "x"}})
	if r.status != http.StatusNotFound {
		t.Fatalf("patch unknown: %d", r.status)
	}
	e.expectEvent(r, "platform.ip_allowlist_changed:failure:not_found")

	r = e.do(call{method: "DELETE", path: base + "/" + mine.Id.String(), cookie: su})
	if r.status != http.StatusConflict || r.problemCode(t) != "lockout_confirmation_required" {
		t.Fatalf("removing the own coverage: %d %s", r.status, r.body)
	}
	e.expectEvent(r, "platform.ip_allowlist_changed:failure:lockout_confirmation_required")
	r = e.do(call{method: "DELETE", path: base + "/" + office.Id.String(), cookie: su})
	if r.status != http.StatusNoContent {
		t.Fatalf("delete office: %d %s", r.status, r.body)
	}
	e.expectEvent(r, "platform.ip_allowlist_changed:success:")
	r = e.do(call{method: "DELETE", path: base + "/" + office.Id.String(), cookie: su})
	if r.status != http.StatusNotFound {
		t.Fatalf("delete again: %d", r.status)
	}
	r = e.do(call{method: "DELETE", path: base + "/" + mine.Id.String(), cookie: su})
	if r.status != http.StatusConflict || r.problemCode(t) != "disable_confirmation_required" {
		t.Fatalf("removing the last entry: %d %s", r.status, r.body)
	}
	r = e.do(call{method: "DELETE", path: base + "/" + mine.Id.String() + "?confirm=lockout", cookie: su})
	if r.status != http.StatusConflict || r.problemCode(t) != "disable_confirmation_required" {
		t.Fatalf("the wrong confirmation: %d %s", r.status, r.body)
	}
	r = e.do(call{method: "DELETE", path: base + "/" + mine.Id.String() + "?confirm=disable", cookie: su})
	if r.status != http.StatusNoContent {
		t.Fatalf("switching off: %d %s", r.status, r.body)
	}
	e.expectEvent(r, "platform.ip_allowlist_changed:success:")
	if l := e.do(call{method: "GET", path: base, cookie: root}); !strings.Contains(string(l.body), `"total":0`) {
		t.Fatalf("list after: %s", l.body)
	}
}

// TestIPAllowlistEnforcement: once the list excludes the client, sessions and API tokens are refused before any use
// case runs, and the portal answers plain text (plan M7a decision 17, AC1).
func TestIPAllowlistEnforcement(t *testing.T) {
	e := newAllowlistEnv(t)
	root := e.platformSession()
	su := e.steppedUp(root, time.Now())
	alice := e.session(e.acme, principal.RoleOrgAdmin)
	token := e.createAPIToken("acme", alice, "ci", adminapi.ApiTokenRoleOrgAdmin)
	const base = "/api/platform/v1/ip-allowlist"

	// Platform operations are sessions only: a token is forbidden, with one denied event for a write.
	if r := e.do(call{method: "GET", path: base, headers: bearer(token.Secret)}); r.status != http.StatusForbidden {
		t.Fatalf("token list: %d %s", r.status, r.body)
	}
	r := e.do(call{method: "POST", path: base, headers: bearer(token.Secret), body: map[string]string{"cidr": "192.0.2.0/24", "label": "x"}})
	if r.status != http.StatusForbidden || r.problemCode(t) != "forbidden" {
		t.Fatalf("token write: %d %s", r.status, r.body)
	}
	e.expectEvent(r, "platform.ip_allowlist_changed:denied:forbidden")
	r = e.do(call{method: "POST", path: base, cookie: e.steppedUp(alice, time.Now()), body: map[string]string{"cidr": "192.0.2.0/24", "label": "x"}})
	if r.status != http.StatusForbidden || r.problemCode(t) != "forbidden" {
		t.Fatalf("org admin write: %d %s", r.status, r.body)
	}
	e.expectEvent(r, "platform.ip_allowlist_changed:denied:forbidden")

	// Lock the test client out on purpose (confirmed), then everything is refused.
	r = e.do(call{method: "POST", path: base + "?confirm=lockout", cookie: su, body: map[string]string{"cidr": "198.51.100.0/24", "label": "elsewhere"}})
	if r.status != http.StatusCreated {
		t.Fatalf("confirmed lockout: %d %s", r.status, r.body)
	}
	e.expectEvent(r, "platform.ip_allowlist_changed:success:")
	for _, c := range []call{
		{method: "GET", path: "/api/v1/me", cookie: root},
		{method: "GET", path: "/api/v1/me", headers: bearer(token.Secret)},
		{method: "GET", path: "/api/platform/v1/organizations", cookie: root},
	} {
		r := e.do(c)
		if r.status != http.StatusForbidden || r.problemCode(t) != "ip_not_allowed" || r.header.Get("Cache-Control") != "no-store" {
			t.Fatalf("%s %s while locked out: %d %s", c.method, c.path, r.status, r.body)
		}
	}
	r = e.do(call{method: "POST", path: base, cookie: su, body: map[string]string{"cidr": "192.0.2.0/24", "label": "x"}})
	if r.status != http.StatusForbidden || r.problemCode(t) != "ip_not_allowed" {
		t.Fatalf("write while locked out: %d %s", r.status, r.body)
	}
	if got := e.events(r.header.Get("X-Request-Id")); len(got) != 0 {
		t.Fatalf("a request refused by the guard records no action event: %v", got)
	}
	rec := httptest.NewRecorder()
	e.handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "https://admin.test/", nil))
	if rec.Code != http.StatusForbidden || rec.Header().Get("Content-Type") != "text/plain; charset=utf-8" || rec.Body.String() != "403 Forbidden\n" {
		t.Fatalf("portal while locked out: %d %q %s", rec.Code, rec.Body.String(), rec.Header().Get("Content-Type"))
	}
}
