package app_test

import (
	"context"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/domain/organization"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/ports"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/problem"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/pgtest"
)

// linkDirectory is a directory that creates one-time links and knows deactivated users.
type linkDirectory struct {
	*directory
	mu       sync.Mutex
	inactive map[string]bool
	links    []string // pks a link was created for
	linkFail error
	// open counts the unexpired links per pk; revokeFail makes ending them fail.
	open       map[string]int
	revokeFail error
	// connected are the pks with an upstream source connection; connFail makes the lookup fail. attrs are the
	// attributes set per pk; a nil value removes one, as in Authentik.
	connected map[string]bool
	connFail  error
	attrs     map[string]map[string]any
}

func (d *linkDirectory) HasSourceConnection(_ context.Context, pk string) (bool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.connected[pk], d.connFail
}

func (d *linkDirectory) SetUserAttribute(_ context.Context, pk, key string, value any) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.attrs[pk] == nil {
		d.attrs[pk] = map[string]any{}
	}
	if value == nil {
		delete(d.attrs[pk], key)
		return nil
	}
	d.attrs[pk][key] = value
	return nil
}

func (d *linkDirectory) RevokeRecoveryLinks(_ context.Context, pk string) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.revokeFail != nil {
		return 0, d.revokeFail
	}
	n := d.open[pk]
	delete(d.open, pk)
	return n, nil
}

func (d *linkDirectory) UserActive(_ context.Context, pk string) (bool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return !d.inactive[pk], nil
}

func (d *linkDirectory) RecoveryLink(_ context.Context, pk string) (string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.linkFail != nil {
		return "", d.linkFail
	}
	d.links = append(d.links, pk)
	d.open[pk]++
	return "https://auth.test/if/flow/paddock-recovery/?flow_token=secret-" + pk, nil
}

type linkWorld struct {
	super *pgx.Conn
	dir   *linkDirectory
	links *app.PlatformEnrolmentLinks
	corr  string
}

func newLinkWorld(t *testing.T) *linkWorld {
	t.Helper()
	env := pgtest.SharedPaddock(t)
	ctx := context.Background()
	worker, err := db.NewOrgPool(ctx, env.Worker, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(worker.Close)
	platform, err := db.NewPlatformPool(ctx, env.Platform, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(platform.Close)
	super, err := pgx.Connect(ctx, env.Super)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = super.Close(ctx) })
	dir := &linkDirectory{directory: newDirectory(), inactive: map[string]bool{}, open: map[string]int{},
		connected: map[string]bool{}, attrs: map[string]map[string]any{}}
	dir.roleGroups = map[string][]ports.IdentityUser{
		organization.PlatformAdminsGroup(): {{PK: "1", Username: "root@example.test", Active: true}, {PK: "2", Username: "off@example.test"},
			{PK: "4", Username: "synced@example.test", Active: true}},
		organization.RoleGroup("acme", organization.GroupAdmins): {{PK: "3", Username: "alice@acme.test", Active: true}},
	}
	dir.inactive["2"] = true
	corr := "corr-link-" + uuid.NewString()
	runner := app.NewActionRunner(worker, platform, func(context.Context) string { return corr })
	dir.connected["4"] = true
	links := app.NewPlatformEnrolmentLinks(runner, dir, dir)
	links.SetClock(func() time.Time { return time.Date(2026, 11, 15, 10, 0, 0, 0, time.UTC) })
	return &linkWorld{super: super, dir: dir, links: links, corr: corr}
}

// event returns the one platform.enrolment_link_created event of the world as "outcome error_code actor org", its
// params and the event count.
func (w *linkWorld) event(t *testing.T) (string, string, int) {
	t.Helper()
	rows, err := w.super.Query(context.Background(), `SELECT outcome || ' ' || coalesce(error_code, '-') || ' ' ||
		(actor->>'type') || ':' || (actor->>'display') || ' ' || organization_id::text, params::text
		FROM action WHERE code = 'platform.enrolment_link_created' AND correlation_id = $1`, w.corr)
	if err != nil {
		t.Fatal(err)
	}
	type row struct{ Event, Params string }
	got, err := pgx.CollectRows(rows, pgx.RowToStructByPos[row])
	if err != nil {
		t.Fatal(err)
	}
	if len(got) == 0 {
		return "", "", 0
	}
	return got[0].Event, got[0].Params, len(got)
}

// TestPlatformEnrolmentLink (ADR 0053 decision 1): the host command creates a 24-hour link for a direct member of
// paddock.platform.admins and records exactly one event without the link in the platform pseudo-organization.
func TestPlatformEnrolmentLink(t *testing.T) {
	w := newLinkWorld(t)
	l, err := w.links.CreateCLI(context.Background(), " root@example.test ")
	if err != nil {
		t.Fatal(err)
	}
	if l.Link != "https://auth.test/if/flow/paddock-recovery/?flow_token=secret-1" ||
		!l.ExpiresAt.Equal(time.Date(2026, 11, 16, 10, 0, 0, 0, time.UTC)) {
		t.Fatalf("link %+v", l)
	}
	ev, params, n := w.event(t)
	if n != 1 || ev != "success - system:paddock-server admin "+platformOrg {
		t.Fatalf("%d events, %q, want one success of paddock-server admin in the platform pseudo-organization", n, ev)
	}
	if !strings.Contains(params, `"username": "root@example.test"`) || strings.Contains(params, "secret") ||
		strings.Contains(params, "flow_token") {
		t.Fatalf("params %s, want the username and never the link", params)
	}
}

// TestPlatformEnrolmentLinkPasswordByLink (plan M12h-2 amendment f addendum points 1 and 6): the host command marks a
// hand-created platform administrator so the link may set a password, before the link is issued (passkey_only
// false); an account connected to an upstream source is not marked and its link sets up only the passkey
// (passkey_only true).
func TestPlatformEnrolmentLinkPasswordByLink(t *testing.T) {
	t.Run("hand-created account", func(t *testing.T) {
		w := newLinkWorld(t)
		l, err := w.links.CreateCLI(context.Background(), "root@example.test")
		if err != nil || l.PasskeyOnly {
			t.Fatalf("CreateCLI: %+v %v, want a link that may set a password", l, err)
		}
		if got := w.dir.attrs["1"][ports.AttrPasswordByLink]; got != true {
			t.Fatalf("attribute %v, want true", got)
		}
		if _, params, n := w.event(t); n != 1 || !strings.Contains(params, `"passkey_only": false`) {
			t.Fatalf("%d events, params %s, want passkey_only false", n, params)
		}
	})
	t.Run("account with an upstream source", func(t *testing.T) {
		w := newLinkWorld(t)
		l, err := w.links.CreateCLI(context.Background(), "synced@example.test")
		if err != nil || !l.PasskeyOnly || len(w.dir.links) != 1 {
			t.Fatalf("CreateCLI: %+v %v, want a passkey-only link", l, err)
		}
		if v := w.dir.attrs["4"][ports.AttrPasswordByLink]; v != nil {
			t.Fatalf("attribute %v, want none", v)
		}
		if _, params, n := w.event(t); n != 1 || !strings.Contains(params, `"passkey_only": true`) {
			t.Fatalf("%d events, params %s, want passkey_only true", n, params)
		}
	})
	t.Run("connected after an earlier mark", func(t *testing.T) {
		w := newLinkWorld(t)
		w.dir.attrs["4"] = map[string]any{ports.AttrPasswordByLink: true}
		l, err := w.links.CreateCLI(context.Background(), "synced@example.test")
		if err != nil || !l.PasskeyOnly {
			t.Fatalf("CreateCLI: %+v %v, want a passkey-only link", l, err)
		}
		if v, ok := w.dir.attrs["4"][ports.AttrPasswordByLink]; ok {
			t.Fatalf("attribute %v, want the earlier mark removed", v)
		}
		if _, params, n := w.event(t); n != 1 || !strings.Contains(params, `"passkey_only": true`) {
			t.Fatalf("%d events, params %s, want passkey_only true", n, params)
		}
	})
	t.Run("source lookup fails", func(t *testing.T) {
		w := newLinkWorld(t)
		w.dir.open["1"] = 1
		w.dir.connFail = problem.UpstreamUnavailable
		if _, err := w.links.CreateCLI(context.Background(), "root@example.test"); !errors.Is(err, problem.UpstreamUnavailable) {
			t.Fatalf("CreateCLI: %v, want upstream_unavailable", err)
		}
		if len(w.dir.links) != 0 || len(w.dir.attrs) != 0 || w.dir.open["1"] != 1 {
			t.Fatalf("links %v, attributes %v, open %d: want nothing changed", w.dir.links, w.dir.attrs, w.dir.open["1"])
		}
		ev, params, n := w.event(t)
		if n != 1 || ev != "failure upstream_unavailable system:paddock-server admin "+platformOrg ||
			strings.Contains(params, "passkey_only") || strings.Contains(params, "previous_links_revoked") {
			t.Fatalf("%d events, %q %s, want one failure without passkey_only", n, ev, params)
		}
	})
	t.Run("deactivated account", func(t *testing.T) {
		w := newLinkWorld(t)
		if _, err := w.links.CreateCLI(context.Background(), "off@example.test"); !errors.Is(err, problem.InvalidState) {
			t.Fatalf("CreateCLI: %v, want invalid_state", err)
		}
		if len(w.dir.attrs) != 0 {
			t.Fatalf("attributes set %v on a deactivated account", w.dir.attrs)
		}
	})
}

// TestPlatformEnrolmentLinkRefusals (ADR 0053 decision 1): no link for an account that is not a direct member of
// paddock.platform.admins (an organization administrator, an unknown name), nor for a deactivated platform
// administrator; each attempt records exactly one failure.
func TestPlatformEnrolmentLinkRefusals(t *testing.T) {
	for name, c := range map[string]struct {
		username string
		want     error
		code     string
	}{
		"organization administrator": {"alice@acme.test", app.ErrNotPlatformAdministrator, "invalid_state"},
		"unknown account":            {"nobody@example.test", app.ErrNotPlatformAdministrator, "invalid_state"},
		"deactivated":                {"off@example.test", problem.InvalidState, "invalid_state"},
		"identity provider fails":    {"root@example.test", problem.UpstreamUnavailable, "upstream_unavailable"},
	} {
		t.Run(name, func(t *testing.T) {
			w := newLinkWorld(t)
			if name == "identity provider fails" {
				w.dir.linkFail = problem.UpstreamUnavailable
			}
			if _, err := w.links.CreateCLI(context.Background(), c.username); !errors.Is(err, c.want) {
				t.Fatalf("CreateCLI(%s): %v, want %v", c.username, err, c.want)
			}
			if len(w.dir.links) != 0 {
				t.Fatalf("links created for %v", w.dir.links)
			}
			ev, _, n := w.event(t)
			if n != 1 || ev != "failure "+c.code+" system:paddock-server admin "+platformOrg {
				t.Fatalf("%d events, %q, want one failure %s", n, ev, c.code)
			}
		})
	}
	t.Run("platform group missing", func(t *testing.T) {
		w := newLinkWorld(t)
		w.dir.roleGroupFail = map[string]error{organization.PlatformAdminsGroup(): ports.ErrGroupNotFound}
		if _, err := w.links.CreateCLI(context.Background(), "root@example.test"); !errors.Is(err, app.ErrNotPlatformAdministrator) {
			t.Fatalf("CreateCLI: %v", err)
		}
		if ev, _, n := w.event(t); n != 1 || ev != "failure invalid_state system:paddock-server admin "+platformOrg {
			t.Fatalf("%d events, %q, want one failure invalid_state", n, ev)
		}
	})
}

// paramsOfEvents returns the params of every platform.enrolment_link_created event of the world, oldest first.
func (w *linkWorld) paramsOfEvents(t *testing.T) []string {
	t.Helper()
	rows, err := w.super.Query(context.Background(), `SELECT outcome || ' ' || params::text FROM action
		WHERE code = 'platform.enrolment_link_created' AND correlation_id = $1 ORDER BY id`, w.corr)
	if err != nil {
		t.Fatal(err)
	}
	got, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		t.Fatal(err)
	}
	return got
}

// TestPlatformEnrolmentLinkEndsOlderLinks (plan M12h-2 amendment f point 1): the host command ends the account's
// older links before it creates a new one, so only the newest works, and each event says how many it ended.
func TestPlatformEnrolmentLinkEndsOlderLinks(t *testing.T) {
	w := newLinkWorld(t)
	for range 2 {
		if _, err := w.links.CreateCLI(context.Background(), "root@example.test"); err != nil {
			t.Fatal(err)
		}
	}
	if w.dir.open["1"] != 1 {
		t.Fatalf("%d open links, want only the newest", w.dir.open["1"])
	}
	got := w.paramsOfEvents(t)
	if len(got) != 2 || !strings.Contains(got[0], `"previous_links_revoked": 0`) ||
		!strings.Contains(got[1], `"previous_links_revoked": 1`) {
		t.Fatalf("events %v, want 0 then 1 older links ended", got)
	}
}

// TestPlatformEnrolmentLinkRevocationFails (plan M12h-2 amendment f point 1): when the older links cannot be ended the
// host command creates no link and records exactly one failure upstream_unavailable without a count.
func TestPlatformEnrolmentLinkRevocationFails(t *testing.T) {
	w := newLinkWorld(t)
	w.dir.open["1"] = 1
	w.dir.revokeFail = problem.UpstreamUnavailable
	if _, err := w.links.CreateCLI(context.Background(), "root@example.test"); !errors.Is(err, problem.UpstreamUnavailable) {
		t.Fatalf("CreateCLI: %v, want upstream_unavailable", err)
	}
	if len(w.dir.links) != 0 || w.dir.open["1"] != 1 {
		t.Fatalf("links created %v, open %d: want none created and the older one untouched", w.dir.links, w.dir.open["1"])
	}
	ev, params, n := w.event(t)
	if n != 1 || ev != "failure upstream_unavailable system:paddock-server admin "+platformOrg ||
		strings.Contains(params, "previous_links_revoked") {
		t.Fatalf("%d events, %q %s, want one failure upstream_unavailable without a count", n, ev, params)
	}
}

// noticeWorld is the announcement of ADR 0053 decision 6 against the shared database.
type noticeWorld struct {
	super   *pgx.Conn
	dir     *directory
	groups  *mfaIdP
	notices *app.MFAEnrolmentNotices
	now     time.Time
	ctx     context.Context
}

func newNoticeWorld(t *testing.T, seeded *time.Time) *noticeWorld {
	t.Helper()
	w := newMFAWorld(t)
	if seeded != nil {
		if _, err := w.super.Exec(context.Background(),
			"INSERT INTO platform_mfa_enrolment (id, first_attempt_at, seeded_at) VALUES (true, $1, $1)", *seeded); err != nil {
			t.Fatal(err)
		}
	}
	env := pgtest.SharedPaddock(t)
	platform, err := db.NewPlatformPool(context.Background(), env.Platform, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(platform.Close)
	nw := &noticeWorld{super: w.super, dir: w.dir, groups: w.idp, now: time.Now()}
	nw.notices = app.NewMFAEnrolmentNotices(platform, w.dir, w.idp)
	nw.notices.SetClock(func() time.Time { return nw.now })
	// An organization administrator's request: the announcement reads the platform's seed marker all the same.
	nw.ctx = principal.With(context.Background(), principal.Principal{Kind: principal.KindAdmin, ID: uuid.New(),
		Role: principal.RoleOrgAdmin, OrganizationID: uuid.New()})
	return nw
}

func (w *noticeWorld) member(group, pk string, marked bool) {
	if !slices.Contains(w.groups.groups, group) {
		w.groups.groups = append(w.groups.groups, group)
	}
	w.dir.roleGroups[group] = append(w.dir.roleGroups[group], ports.IdentityUser{PK: pk, Username: "u" + pk, Active: true,
		MFAEnrolAtLogin: marked})
}

// TestMFAEnrolmentNotice (ADR 0053 decision 6, MFA-R3): 30 days after the seed every administrator sees the
// announcement with the count of accounts still marked, per organization for an organization role and across every
// portal role group for the platform administrator; none before the seed and none after the 30 days.
func TestMFAEnrolmentNotice(t *testing.T) {
	seeded := time.Now().Add(-48 * time.Hour).UTC().Truncate(time.Microsecond)
	w := newNoticeWorld(t, &seeded)
	w.member(organization.RoleGroup("acme", organization.GroupAdmins), "1", true)
	w.member(organization.RoleGroup("acme", organization.GroupOperators), "2", false)
	// One account in two role groups counts once.
	w.member(organization.RoleGroup("acme", organization.GroupAuditors), "1", true)
	w.member(organization.RoleGroup("acme", organization.GroupAuditors), "3", true)
	w.member(organization.RoleGroup("globex", organization.GroupAdmins), "4", true)
	w.member(organization.PlatformAdminsGroup(), "5", true)
	until := seeded.Add(app.MFAEnrolmentNoticePeriod)

	for slug, want := range map[string]int{"acme": 2, "globex": 1, "": 4, "other": 0} {
		n, err := w.notices.Notice(w.ctx, slug)
		if err != nil || n == nil || n.Pending != want || !n.Until.Equal(until) {
			t.Fatalf("notice of %q: %+v %v, want pending %d until %s", slug, n, err, want, until)
		}
	}
	// The count is kept for a minute: a mark cleared meanwhile shows at the next read after that.
	calls := w.dir.roleGroupCalls
	w.dir.roleGroups[organization.RoleGroup("globex", organization.GroupAdmins)][0].MFAEnrolAtLogin = false
	if n, _ := w.notices.Notice(w.ctx, "globex"); n.Pending != 1 || w.dir.roleGroupCalls != calls {
		t.Fatalf("cached notice %+v after %d listings, want 1 without a listing", n, w.dir.roleGroupCalls-calls)
	}
	w.now = w.now.Add(time.Minute)
	if n, _ := w.notices.Notice(w.ctx, "globex"); n.Pending != 0 {
		t.Fatalf("notice after a minute %+v, want 0", n)
	}
	// Past the 30 days nothing is read and nothing is shown.
	w.now = until
	calls = w.dir.roleGroupCalls
	if n, err := w.notices.Notice(w.ctx, "acme"); n != nil || err != nil || w.dir.roleGroupCalls != calls {
		t.Fatalf("notice after the period: %+v %v", n, err)
	}
}

// TestMFAEnrolmentNoticeBeforeSeedAndOnFailure: no announcement before the seed completed; an identity provider that
// cannot be listed is an error the handler turns into no announcement.
func TestMFAEnrolmentNoticeBeforeSeedAndOnFailure(t *testing.T) {
	w := newNoticeWorld(t, nil)
	w.member(organization.RoleGroup("acme", organization.GroupAdmins), "1", true)
	if n, err := w.notices.Notice(w.ctx, "acme"); n != nil || err != nil {
		t.Fatalf("before the seed: %+v %v", n, err)
	}
	seeded := time.Now().Add(-time.Hour).UTC()
	if _, err := w.super.Exec(context.Background(),
		"INSERT INTO platform_mfa_enrolment (id, first_attempt_at, seeded_at) VALUES (true, $1, $1)", seeded); err != nil {
		t.Fatal(err)
	}
	w.dir.fail = errors.New("identity provider down")
	if n, err := w.notices.Notice(w.ctx, "acme"); n != nil || err == nil {
		t.Fatalf("listing fails: %+v %v, want an error", n, err)
	}
	// The failure is kept briefly: the next page loads show no notice and do not list again.
	w.dir.fail = nil
	calls := w.dir.roleGroupCalls
	w.now = w.now.Add(29 * time.Second)
	if n, err := w.notices.Notice(w.ctx, "acme"); n != nil || err != nil || w.dir.roleGroupCalls != calls {
		t.Fatalf("within 30 s of the failure: %+v %v after %d listings, want nothing without a listing", n, err,
			w.dir.roleGroupCalls-calls)
	}
	w.now = w.now.Add(time.Second)
	if n, err := w.notices.Notice(w.ctx, "acme"); err != nil || n == nil || n.Pending != 1 {
		t.Fatalf("30 s after the failure: %+v %v", n, err)
	}
}
