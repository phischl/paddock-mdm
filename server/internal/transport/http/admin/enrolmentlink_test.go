package admin_test

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
	"github.com/phischl/paddock-mdm/server/internal/domain/organization"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/ports"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/pgtest"
	"github.com/phischl/paddock-mdm/server/internal/transport/http/admin"
	"github.com/phischl/paddock-mdm/server/internal/transport/http/admin/adminapi"
)

// actionParams returns the params of the action recorded for a request as JSON text.
func (e *env) actionParams(r result) string {
	e.t.Helper()
	var v string
	if err := e.super.QueryRow(context.Background(), "SELECT coalesce(params::text, '') FROM action WHERE correlation_id = $1",
		r.header.Get("X-Request-Id")).Scan(&v); err != nil {
		e.t.Fatal(err)
	}
	return v
}

// localUser creates a local user of org through the API as admin and returns its ID.
func (e *env) localUser(org uuid.UUID, admin *http.Cookie, name string) uuid.UUID {
	e.t.Helper()
	domain := "l" + org.String()[24:] + ".test"
	if res := e.domains(org, domain); res.status != http.StatusOK {
		e.t.Fatalf("domains: %d %s", res.status, res.body)
	}
	created := e.do(call{method: "POST", path: "/api/v1/users", cookie: admin, body: map[string]any{
		"username": name + "@" + domain, "display_name": name,
	}})
	if created.status != http.StatusCreated {
		e.t.Fatalf("create: %d %s", created.status, created.body)
	}
	var c adminapi.UserCreated
	created.decode(e.t, &c)
	return c.User.Id
}

// TestUserEnrolmentLink is the API part of gate MF3 (plan M12h-2 decision 7, §8): an organization administrator gets
// a one-time sign-in setup link for a user of the organization only with a step-up; the link is returned with its
// expiry and never recorded; every other role and every other organization is refused, each attempt with exactly one
// event.
func TestUserEnrolmentLink(t *testing.T) {
	e := newEnv(t)
	alice := e.session(e.acme, principal.RoleOrgAdmin)
	user := e.localUser(e.acme, alice, "erin")
	path := "/api/v1/users/" + user.String() + "/enrolment-link"
	stepped := e.steppedUp(alice, time.Now())

	noStepUp := e.do(call{method: "POST", path: path, cookie: alice})
	if noStepUp.status != http.StatusForbidden || noStepUp.problemCode(t) != "step_up_required" {
		t.Fatalf("without a step-up: %d %s", noStepUp.status, noStepUp.body)
	}
	e.expectEvent(noStepUp, "user.enrolment_link_created:denied:step_up_required")

	before := time.Now()
	created := e.do(call{method: "POST", path: path, cookie: stepped})
	if created.status != http.StatusCreated {
		t.Fatalf("with a step-up: %d %s", created.status, created.body)
	}
	e.expectEvent(created, "user.enrolment_link_created:success:")
	var l adminapi.UserEnrolmentLink
	created.decode(t, &l)
	pk := e.authentikPK(user)
	if l.Link != "https://auth.test/if/flow/paddock-recovery/?flow_token="+pk ||
		l.ExpiresAt.Before(before.Add(ports.RecoveryLinkValidity).Add(-time.Second)) ||
		l.ExpiresAt.After(time.Now().Add(ports.RecoveryLinkValidity)) {
		t.Fatalf("link %+v", l)
	}
	if got := created.header.Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control %q, want no-store", got)
	}
	// previous_links_revoked is the only key besides the username, so no key can carry the link.
	params := e.actionParams(created)
	var keys map[string]any
	if err := json.Unmarshal([]byte(params), &keys); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(params, `"username": "erin@`) || len(keys) != 2 || keys["previous_links_revoked"] == nil ||
		strings.Contains(params, "flow_token") || strings.Contains(params, "auth.test") {
		t.Fatalf("params %s, want the username and the count of older links and never the link", params)
	}

	operator := e.steppedUp(e.session(e.acme, principal.RoleOrgOperator), time.Now())
	if res := e.do(call{method: "POST", path: path, cookie: operator}); res.status != http.StatusForbidden || res.problemCode(t) != "forbidden" {
		t.Fatalf("operator: %d %s", res.status, res.body)
	} else {
		e.expectEvent(res, "user.enrolment_link_created:denied:forbidden")
	}
	auditor := e.steppedUp(e.session(e.acme, principal.RoleOrgAuditor), time.Now())
	if res := e.do(call{method: "POST", path: path, cookie: auditor}); res.status != http.StatusForbidden {
		t.Fatalf("auditor: %d %s", res.status, res.body)
	}
	carol := e.steppedUp(e.session(e.globex, principal.RoleOrgAdmin), time.Now())
	cross := e.do(call{method: "POST", path: path, cookie: carol})
	if cross.status != http.StatusNotFound || cross.problemCode(t) != "not_found" {
		t.Fatalf("another organization: %d %s", cross.status, cross.body)
	}
	e.expectEvent(cross, "user.enrolment_link_created:failure:not_found")
	if res := e.do(call{method: "POST", path: "/api/v1/users/" + uuid.NewString() + "/enrolment-link", cookie: stepped}); res.status != http.StatusNotFound {
		t.Fatalf("unknown user: %d", res.status)
	}

	// Authentik down: 502, and the attempt is recorded as failure.
	e.idp.fail = true
	down := e.do(call{method: "POST", path: path, cookie: stepped})
	e.idp.fail = false
	if down.status != http.StatusBadGateway {
		t.Fatalf("Authentik down: %d %s", down.status, down.body)
	}
	e.expectEvent(down, "user.enrolment_link_created:failure:upstream_unavailable")
}

// TestUserEnrolmentLinkDisabledUser: a user deactivated in Authentik or locked gets no link (409 invalid_state).
func TestUserEnrolmentLinkDisabledUser(t *testing.T) {
	e := newEnv(t)
	alice := e.session(e.acme, principal.RoleOrgAdmin)
	stepped := e.steppedUp(alice, time.Now())
	user := e.localUser(e.acme, alice, "frank")
	path := "/api/v1/users/" + user.String() + "/enrolment-link"
	pk := e.authentikPK(user)

	e.idp.mu.Lock()
	e.idp.inactive[pk] = true
	e.idp.mu.Unlock()
	inactive := e.do(call{method: "POST", path: path, cookie: stepped})
	if inactive.status != http.StatusConflict || inactive.problemCode(t) != "invalid_state" {
		t.Fatalf("deactivated: %d %s", inactive.status, inactive.body)
	}
	e.expectEvent(inactive, "user.enrolment_link_created:failure:invalid_state")
	e.idp.mu.Lock()
	delete(e.idp.inactive, pk)
	e.idp.mu.Unlock()

	if res := e.do(call{method: "POST", path: "/api/v1/users/" + user.String() + "/lock", cookie: alice}); res.status != http.StatusOK {
		t.Fatalf("lock: %d %s", res.status, res.body)
	}
	locked := e.do(call{method: "POST", path: path, cookie: stepped})
	if locked.status != http.StatusConflict || locked.problemCode(t) != "invalid_state" {
		t.Fatalf("locked: %d %s", locked.status, locked.body)
	}
	e.expectEvent(locked, "user.enrolment_link_created:failure:invalid_state")
}

// TestUserEnrolmentLinkPlatformAdministrator (plan M12h-2 amendment f, ADR 0045): an account that is also a direct
// member of paddock.platform.admins gets no link from an organization administrator (409 invalid_state, one failure
// event), while an account that is only an organization administrator still gets one.
func TestUserEnrolmentLinkPlatformAdministrator(t *testing.T) {
	e := newEnv(t)
	alice := e.session(e.acme, principal.RoleOrgAdmin)
	stepped := e.steppedUp(alice, time.Now())
	dual := e.localUser(e.acme, alice, "gina")
	orgAdmin := e.localUser(e.acme, alice, "hank")
	slug := e.slug(e.acme)
	e.idp.mu.Lock()
	e.idp.roleGroups = map[string][]ports.IdentityUser{
		organization.PlatformAdminsGroup():                     {{PK: e.authentikPK(dual), Active: true}},
		organization.RoleGroup(slug, organization.GroupAdmins): {{PK: e.authentikPK(dual)}, {PK: e.authentikPK(orgAdmin)}},
	}
	e.idp.mu.Unlock()

	refused := e.do(call{method: "POST", path: "/api/v1/users/" + dual.String() + "/enrolment-link", cookie: stepped})
	if refused.status != http.StatusConflict || refused.problemCode(t) != "invalid_state" ||
		!strings.Contains(string(refused.body), "platform administrators receive their setup link from the host operator") {
		t.Fatalf("platform administrator: %d %s", refused.status, refused.body)
	}
	e.expectEvent(refused, "user.enrolment_link_created:failure:invalid_state")
	if strings.Contains(string(refused.body), "flow_token") {
		t.Fatalf("refusal carries a link: %s", refused.body)
	}

	allowed := e.do(call{method: "POST", path: "/api/v1/users/" + orgAdmin.String() + "/enrolment-link", cookie: stepped})
	if allowed.status != http.StatusCreated {
		t.Fatalf("organization administrator: %d %s", allowed.status, allowed.body)
	}
	e.expectEvent(allowed, "user.enrolment_link_created:success:")
}

// TestUserEnrolmentLinkPlatformListingFails (plan M12h-2 amendment f point 4): when only the platform administrator
// listing fails while the account lookup and the link would succeed, the request fails closed with 502, one failure
// event and no link.
func TestUserEnrolmentLinkPlatformListingFails(t *testing.T) {
	e := newEnv(t)
	alice := e.session(e.acme, principal.RoleOrgAdmin)
	stepped := e.steppedUp(alice, time.Now())
	user := e.localUser(e.acme, alice, "ivy")

	e.idp.mu.Lock()
	e.idp.failRoleGroups = true
	e.idp.mu.Unlock()
	res := e.do(call{method: "POST", path: "/api/v1/users/" + user.String() + "/enrolment-link", cookie: stepped})
	if res.status != http.StatusBadGateway || res.problemCode(t) != "upstream_unavailable" {
		t.Fatalf("listing failure: %d %s", res.status, res.body)
	}
	e.expectEvent(res, "user.enrolment_link_created:failure:upstream_unavailable")
	if strings.Contains(string(res.body), "flow_token") {
		t.Fatalf("listing failure carries a link: %s", res.body)
	}
}

// TestUserEnrolmentLinkEndsOlderLinks (plan M12h-2 amendment f point 1): every link of an account ends the account's
// older ones first, and the event says how many it ended: the new user's password link ends none, the first setup
// link ends the password link, the second ends the first.
func TestUserEnrolmentLinkEndsOlderLinks(t *testing.T) {
	e := newEnv(t)
	alice := e.session(e.acme, principal.RoleOrgAdmin)
	stepped := e.steppedUp(alice, time.Now())
	domain := "l" + e.acme.String()[24:] + ".test"
	if res := e.domains(e.acme, domain); res.status != http.StatusOK {
		t.Fatalf("domains: %d %s", res.status, res.body)
	}
	created := e.do(call{method: "POST", path: "/api/v1/users", cookie: alice, body: map[string]any{
		"username": "jack@" + domain, "display_name": "jack",
	}})
	if created.status != http.StatusCreated {
		t.Fatalf("create: %d %s", created.status, created.body)
	}
	if params := e.actionParams(created); !strings.Contains(params, `"previous_links_revoked": 0`) {
		t.Fatalf("user.created params %s, want previous_links_revoked 0", params)
	}
	var c adminapi.UserCreated
	created.decode(t, &c)
	pk := e.authentikPK(c.User.Id)
	path := "/api/v1/users/" + c.User.Id.String() + "/enrolment-link"
	for i := range 2 {
		res := e.do(call{method: "POST", path: path, cookie: stepped})
		if res.status != http.StatusCreated {
			t.Fatalf("link %d: %d %s", i+1, res.status, res.body)
		}
		e.expectEvent(res, "user.enrolment_link_created:success:")
		if params := e.actionParams(res); !strings.Contains(params, `"previous_links_revoked": 1`) {
			t.Fatalf("link %d params %s, want previous_links_revoked 1", i+1, params)
		}
	}
	e.idp.mu.Lock()
	open, attrs := e.idp.links[pk], e.idp.attrs[pk]
	e.idp.mu.Unlock()
	if open != 1 {
		t.Fatalf("%d open links, want only the newest", open)
	}
	// Only the host command lets a link set a password on an account Paddock did not create (plan M12h-2 amendment f
	// addendum point 3).
	if _, ok := attrs[ports.AttrPasswordByLink]; ok {
		t.Fatalf("the portal set %s: %v", ports.AttrPasswordByLink, attrs)
	}
}

// TestUserEnrolmentLinkRevocationFails (plan M12h-2 amendment f point 1): when the older links cannot be ended, no new
// link is issued: 502 upstream_unavailable, one failure event without previous_links_revoked, and the older link is
// the only one. A new local user is not created either, as when its link fails.
func TestUserEnrolmentLinkRevocationFails(t *testing.T) {
	e := newEnv(t)
	alice := e.session(e.acme, principal.RoleOrgAdmin)
	stepped := e.steppedUp(alice, time.Now())
	user := e.localUser(e.acme, alice, "kim")
	pk := e.authentikPK(user)

	e.idp.mu.Lock()
	e.idp.failRevoke = true
	e.idp.mu.Unlock()
	res := e.do(call{method: "POST", path: "/api/v1/users/" + user.String() + "/enrolment-link", cookie: stepped})
	if res.status != http.StatusBadGateway || res.problemCode(t) != "upstream_unavailable" {
		t.Fatalf("revocation fails: %d %s", res.status, res.body)
	}
	e.expectEvent(res, "user.enrolment_link_created:failure:upstream_unavailable")
	if params := e.actionParams(res); strings.Contains(params, "previous_links_revoked") || strings.Contains(string(res.body), "flow_token") {
		t.Fatalf("params %s, body %s: want neither a count nor a link", params, res.body)
	}
	e.idp.mu.Lock()
	open := e.idp.links[pk]
	e.idp.mu.Unlock()
	if open != 1 {
		t.Fatalf("%d open links, want only the password link of the creation", open)
	}

	domain := "l" + e.acme.String()[24:] + ".test"
	created := e.do(call{method: "POST", path: "/api/v1/users", cookie: alice, body: map[string]any{
		"username": "lena@" + domain, "display_name": "lena",
	}})
	if created.status != http.StatusBadGateway {
		t.Fatalf("create while revocation fails: %d %s", created.status, created.body)
	}
	e.expectEvent(created, "user.created:failure:upstream_unavailable")
	e.idp.mu.Lock()
	defer e.idp.mu.Unlock()
	for _, u := range e.idp.users {
		if u.Username == "lena@"+domain {
			t.Fatalf("the identity provider user stayed after the failed creation")
		}
	}
}

// TestEnrolmentLinkRefusedForDeletingOrganization (PDK-1112): once an organization is deleting, its administrator gets
// no sign-in setup link even with a step-up: 403 organization_inactive, the identity provider is not asked to end or
// create a link, and the attempt is recorded once as organization.inactive_denied in the platform pseudo-organization
// and adds no event to the deleting organization.
func TestEnrolmentLinkRefusedForDeletingOrganization(t *testing.T) {
	e := newEnv(t)
	org := e.org("leaving")
	alice := e.session(org, principal.RoleOrgAdmin)
	user := e.localUser(org, alice, "nora")
	pk := e.authentikPK(user)
	stepped := e.steppedUp(alice, time.Now())
	e.idp.mu.Lock()
	linksBefore := e.idp.links[pk]
	e.idp.mu.Unlock()
	if linksBefore != 1 {
		t.Fatalf("%d open links before, want the password link of the creation", linksBefore)
	}
	if _, err := e.super.Exec(context.Background(), `UPDATE organization SET status = 'deleting',
		deletion_requested_at = now(), deletion_requested_by = 'platform admin', deletion_reason = 'contract ended',
		delete_after = now(), offboarding_step = 'database' WHERE id = $1`, org); err != nil {
		t.Fatal(err)
	}
	if err := e.orgPool.RefreshOrganizationStatus(context.Background()); err != nil {
		t.Fatal(err)
	}
	inOrg := func() int {
		var n int
		if err := e.super.QueryRow(context.Background(), "SELECT count(*) FROM action WHERE organization_id = $1", org).
			Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	// The user's creation was recorded in the organization while it was active.
	eventsBefore := inOrg()

	res := e.do(call{method: "POST", path: "/api/v1/users/" + user.String() + "/enrolment-link", cookie: stepped})
	if res.status != http.StatusForbidden || res.problemCode(t) != "organization_inactive" {
		t.Fatalf("deleting organization: %d %s, want 403 organization_inactive", res.status, res.body)
	}
	if strings.Contains(string(res.body), "flow_token") {
		t.Fatalf("the refusal carries a link: %s", res.body)
	}
	e.idp.mu.Lock()
	linksAfter := e.idp.links[pk]
	e.idp.mu.Unlock()
	if linksAfter != linksBefore {
		t.Fatalf("open links %d after the refusal, want %d: the identity provider ended or created a link", linksAfter, linksBefore)
	}
	var events int
	var attempted, status string
	if err := e.super.QueryRow(context.Background(), `SELECT count(*), coalesce(max(params->>'attempted_code'), ''),
		coalesce(max(params->>'status'), '') FROM action WHERE code = 'organization.inactive_denied'
		AND organization_id = $1 AND outcome = 'denied' AND error_code = 'organization_inactive'
		AND params->>'organization_id' = $2`, audit.PlatformOrganizationID, org.String()).
		Scan(&events, &attempted, &status); err != nil {
		t.Fatal(err)
	}
	if events != 1 || attempted != "user.enrolment_link_created" || status != "deleting" {
		t.Errorf("platform events: %d, attempted %q, status %q; want one user.enrolment_link_created, deleting",
			events, attempted, status)
	}
	if after := inOrg(); after != eventsBefore {
		t.Errorf("events in the deleting organization: %d after the refusal, want %d", after, eventsBefore)
	}
}

// markedDirectory lists role group members with their enrolment marks for the announcement.
type markedDirectory struct {
	*fakeIdP
	members map[string][]ports.IdentityUser
}

func (d *markedDirectory) RoleGroupsMembers(_ context.Context, names []string) (map[string][]ports.IdentityUser, error) {
	out := map[string][]ports.IdentityUser{}
	for _, n := range names {
		if m, ok := d.members[n]; ok {
			out[n] = m
		}
	}
	return out, nil
}

func (d *markedDirectory) PortalRoleGroupNames(context.Context) ([]string, error) {
	var out []string
	for n := range d.members {
		out = append(out, n)
	}
	return out, nil
}

// TestMeMFAEnrolmentNotice (ADR 0053 decision 6): after the seed, GET and PATCH /api/v1/me carry the announcement with
// the count of the organization's marked administrators, or of every marked administrator for the platform
// administrator; another organization's administrator never counts acme's; API tokens never see it.
func TestMeMFAEnrolmentNotice(t *testing.T) {
	var dir *markedDirectory
	e := newEnvWith(t, func(d *admin.Deps) {
		pool, err := db.NewPlatformPool(context.Background(), pgtest.SharedPaddock(t).Platform, db.Options{})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(pool.Close)
		dir = &markedDirectory{fakeIdP: newFakeIdP(), members: map[string][]ports.IdentityUser{}}
		d.MFANotices = app.NewMFAEnrolmentNotices(pool, dir, dir)
	})
	seeded := time.Now().Add(-time.Hour).UTC().Truncate(time.Second)
	if _, err := e.super.Exec(context.Background(), `INSERT INTO platform_mfa_enrolment (id, first_attempt_at, seeded_at)
		VALUES (true, $1, $1) ON CONFLICT (id) DO UPDATE SET first_attempt_at = $1, seeded_at = $1`, seeded); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = e.super.Exec(context.Background(), "DELETE FROM platform_mfa_enrolment") })
	slug := e.slug(e.acme)
	dir.members[organization.RoleGroup(slug, organization.GroupAdmins)] = []ports.IdentityUser{{PK: "1", MFAEnrolAtLogin: true},
		{PK: "2"}}
	dir.members[organization.PlatformAdminsGroup()] = []ports.IdentityUser{{PK: "3", MFAEnrolAtLogin: true}}
	dir.members[organization.RoleGroup(e.slug(e.globex), organization.GroupAdmins)] = []ports.IdentityUser{{PK: "4"}}

	until := seeded.Add(app.MFAEnrolmentNoticePeriod)
	for name, c := range map[string]struct {
		cookie *http.Cookie
		want   int
	}{
		"organization administrator": {e.session(e.acme, principal.RoleOrgAdmin), 1},
		"organization operator":      {e.session(e.acme, principal.RoleOrgOperator), 1},
		"platform administrator":     {e.platformSession(), 2},
		// Another organization never sees acme's marked administrator: its own role groups have none.
		"administrator of another organization": {e.session(e.globex, principal.RoleOrgAdmin), 0},
	} {
		var me adminapi.Me
		res := e.do(call{method: "GET", path: "/api/v1/me", cookie: c.cookie})
		res.decode(t, &me)
		if n := me.MfaEnrolmentNotice; res.status != http.StatusOK || n == nil || n.Pending != c.want || !n.Until.Equal(until) {
			t.Fatalf("%s: %d %+v, want pending %d until %s", name, res.status, n, c.want, until)
		}
		patched := e.do(call{method: "PATCH", path: "/api/v1/me", cookie: c.cookie, body: map[string]any{"theme": "dark"}})
		patched.decode(t, &me)
		if me.MfaEnrolmentNotice == nil || me.MfaEnrolmentNotice.Pending != c.want {
			t.Fatalf("%s: PATCH %d %+v", name, patched.status, me.MfaEnrolmentNotice)
		}
	}
	token := e.createAPIToken("acme", e.steppedUp(e.session(e.acme, principal.RoleOrgAdmin), time.Now()), "notice", adminapi.ApiTokenRoleOrgAuditor)
	var me adminapi.Me
	res := e.do(call{method: "GET", path: "/api/v1/me", headers: bearer(token.Secret)})
	res.decode(t, &me)
	if res.status != http.StatusOK || me.MfaEnrolmentNotice != nil {
		t.Fatalf("API token: %d %+v, want no announcement", res.status, me.MfaEnrolmentNotice)
	}
}
