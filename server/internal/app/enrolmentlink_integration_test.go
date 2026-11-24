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
	// groups are the direct groups of each username besides its role groups (dir.roleGroups); lookupFail makes
	// finding an account fail.
	groups     map[string][]string
	lookupFail error
}

func (d *linkDirectory) UserByUsername(_ context.Context, username string) (ports.IdentityUser, []string, bool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.lookupFail != nil {
		return ports.IdentityUser{}, nil, false, d.lookupFail
	}
	var u ports.IdentityUser
	groups := slices.Clone(d.groups[username])
	found := len(groups) > 0
	for name, members := range d.roleGroups {
		for _, m := range members {
			if m.Username == username {
				u, found = m, true
				groups = append(groups, name)
			}
		}
	}
	if u.PK == "" {
		u = ports.IdentityUser{PK: "pk-" + username, Username: username, Active: true}
	}
	return u, groups, found, nil
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
	// org is the organization of the role groups of slug; ghost is a slug no Paddock organization has.
	org         uuid.UUID
	slug, ghost string
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
	org := uuid.New()
	slug, ghost := "l"+org.String()[24:], "g"+org.String()[24:]
	if _, err := super.Exec(ctx, "INSERT INTO organization (id, slug, name, status) VALUES ($1, $2, 'Links', 'active')", org, slug); err != nil {
		t.Fatal(err)
	}
	dir := &linkDirectory{directory: newDirectory(), inactive: map[string]bool{}, open: map[string]int{},
		connected: map[string]bool{}, attrs: map[string]map[string]any{}, groups: map[string][]string{}}
	both := ports.IdentityUser{PK: "7", Username: "both@acme.test", Active: true}
	dir.roleGroups = map[string][]ports.IdentityUser{
		organization.PlatformAdminsGroup(): {{PK: "1", Username: "root@example.test", Active: true}, {PK: "2", Username: "off@example.test"},
			{PK: "4", Username: "synced@example.test", Active: true}, both},
		organization.RoleGroup(slug, organization.GroupAdmins): {{PK: "3", Username: "alice@acme.test", Active: true}, both,
			{PK: "8", Username: "twice@acme.test", Active: true}, {PK: "9", Username: "scim@acme.test", Active: true}},
		organization.RoleGroup(slug, organization.GroupOperators): {{PK: "5", Username: "olga@acme.test", Active: true},
			{PK: "8", Username: "twice@acme.test", Active: true}},
		organization.RoleGroup(slug, organization.GroupAuditors): {{PK: "6", Username: "audrey@acme.test", Active: true},
			{PK: "11", Username: "offaudit@acme.test"}},
		organization.RoleGroup(ghost, organization.GroupAdmins): {{PK: "10", Username: "ghost@acme.test", Active: true}},
	}
	dir.groups["plain@acme.test"] = []string{organization.RootGroup(slug), organization.LockedGroup(slug),
		organization.LocalUserGroup(slug, "staff")}
	dir.inactive["2"] = true
	dir.inactive["11"] = true
	corr := "corr-link-" + uuid.NewString()
	runner := app.NewActionRunner(worker, platform, func(context.Context) string { return corr })
	dir.connected["4"] = true
	dir.connected["9"] = true
	links := app.NewPlatformEnrolmentLinks(runner, platform, dir, dir)
	links.SetClock(func() time.Time { return time.Date(2026, 11, 15, 10, 0, 0, 0, time.UTC) })
	return &linkWorld{super: super, dir: dir, links: links, corr: corr, org: org, slug: slug, ghost: ghost}
}

// target returns the target type of the one platform.enrolment_link_created event of the world.
func (w *linkWorld) target(t *testing.T) string {
	t.Helper()
	var typ string
	if err := w.super.QueryRow(context.Background(), `SELECT target->>'type' FROM action
		WHERE code = 'platform.enrolment_link_created' AND correlation_id = $1`, w.corr).Scan(&typ); err != nil {
		t.Fatal(err)
	}
	return typ
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

// TestPlatformEnrolmentLinkRefusals (ADR 0053 decision 1, plan M12h-2 amendment f addendum b): no link for an account
// that holds no portal role (an unknown name, an account in no role group, or in the role group of an organization
// Paddock does not have), for an account whose role assignment is ambiguous (role groups of two organizations, also
// for a platform administrator, or two roles of one organization; the refusal names the reason and the fix), nor for
// a deactivated administrator; nothing is marked and each attempt records exactly one failure.
func TestPlatformEnrolmentLinkRefusals(t *testing.T) {
	deactivated := problem.InvalidState.WithDetail("the user is deactivated in the identity provider")
	for name, c := range map[string]struct {
		username string
		want     error
		code     string
	}{
		"unknown account":                             {"nobody@example.test", app.ErrNoPortalRole, "invalid_state"},
		"in no role group":                            {"plain@acme.test", app.ErrNoPortalRole, "invalid_state"},
		"organization unknown":                        {"ghost@acme.test", app.ErrNoPortalRole, "invalid_state"},
		"blank name":                                  {" ", app.ErrNoPortalRole, "invalid_state"},
		"two roles of one organization":               {"twice@acme.test", app.ErrAmbiguousPortalRole, "invalid_state"},
		"two organizations":                           {"alice@acme.test", app.ErrAmbiguousPortalRole, "invalid_state"},
		"platform administrator in two organizations": {"both@acme.test", app.ErrAmbiguousPortalRole, "invalid_state"},
		"deactivated":                                 {"off@example.test", deactivated, "invalid_state"},
		"deactivated organization user":               {"offaudit@acme.test", deactivated, "invalid_state"},
		"identity provider fails":                     {"root@example.test", problem.UpstreamUnavailable, "upstream_unavailable"},
		"account lookup fails":                        {"alice@acme.test", problem.UpstreamUnavailable, "upstream_unavailable"},
	} {
		t.Run(name, func(t *testing.T) {
			w := newLinkWorld(t)
			switch name {
			case "identity provider fails":
				w.dir.linkFail = problem.UpstreamUnavailable
			case "account lookup fails":
				w.dir.lookupFail = problem.UpstreamUnavailable
			case "two organizations":
				w.dir.groups["alice@acme.test"] = []string{organization.RoleGroup("other-org", organization.GroupAdmins)}
			case "platform administrator in two organizations":
				w.dir.groups["both@acme.test"] = []string{organization.RoleGroup("other-org", organization.GroupAdmins)}
			}
			_, err := w.links.CreateCLI(context.Background(), c.username)
			if !errors.Is(err, c.want) {
				t.Fatalf("CreateCLI(%s): %v, want %v", c.username, err, c.want)
			}
			// errors.Is matches a problem by its code alone: the detail tells the refusals apart.
			if c.code == "invalid_state" && err.Error() != c.want.Error() {
				t.Fatalf("CreateCLI(%s): %q, want %q", c.username, err, c.want)
			}
			if len(w.dir.links) != 0 {
				t.Fatalf("links created for %v", w.dir.links)
			}
			if c.code == "invalid_state" && len(w.dir.attrs) != 0 {
				t.Fatalf("attributes set %v on a refused account", w.dir.attrs)
			}
			ev, _, n := w.event(t)
			if n != 1 || ev != "failure "+c.code+" system:paddock-server admin "+platformOrg {
				t.Fatalf("%d events, %q, want one failure %s", n, ev, c.code)
			}
		})
	}
}

// TestPlatformEnrolmentLinkRefusalDetails: the ambiguity refusal names its reason and the fix, and differs from the
// refusal of an account without a portal role.
func TestPlatformEnrolmentLinkRefusalDetails(t *testing.T) {
	amb := app.ErrAmbiguousPortalRole.Error()
	for _, want := range []string{"ambiguous", "several organizations", "several role groups", "remove the extra group memberships"} {
		if !strings.Contains(amb, want) {
			t.Fatalf("ambiguity refusal %q lacks %q", amb, want)
		}
	}
	if none := app.ErrNoPortalRole.Error(); none == amb || !strings.Contains(none, "holds no portal role") {
		t.Fatalf("no-role refusal %q, want its own detail", none)
	}
}

// TestPlatformEnrolmentLinkOrganizationAccount (plan M12h-2 amendment f addendum b, PDK-1055): the host command also
// creates the link of a direct member of an organization's admins, operators or auditors group. A hand-created account
// is marked so the link sets a password and the passkey (passkey_only false); an account an upstream source (here
// SCIM) provisioned is not marked, loses an earlier mark and gets a passkey-only link. The event stays in the platform
// pseudo-organization and names the account's organization in organization_id.
func TestPlatformEnrolmentLinkOrganizationAccount(t *testing.T) {
	for _, c := range []struct{ username, pk string }{
		{"alice@acme.test", "3"}, {"olga@acme.test", "5"}, {"audrey@acme.test", "6"},
	} {
		t.Run(c.username, func(t *testing.T) {
			w := newLinkWorld(t)
			l, err := w.links.CreateCLI(context.Background(), c.username)
			if err != nil || l.PasskeyOnly || !slices.Equal(w.dir.links, []string{c.pk}) {
				t.Fatalf("CreateCLI: %+v %v, links %v, want a link for %s that may set a password", l, err, w.dir.links, c.pk)
			}
			if got := w.dir.attrs[c.pk][ports.AttrPasswordByLink]; got != true {
				t.Fatalf("attribute %v, want true", got)
			}
			ev, params, n := w.event(t)
			if n != 1 || ev != "success - system:paddock-server admin "+platformOrg ||
				!strings.Contains(params, `"organization_id": "`+w.org.String()+`"`) ||
				!strings.Contains(params, `"passkey_only": false`) {
				t.Fatalf("%d events, %q %s, want one success in the platform pseudo-organization naming %s", n, ev, params, w.org)
			}
			if typ := w.target(t); typ != "user" {
				t.Fatalf("target type %q, want user", typ)
			}
		})
	}
	t.Run("SCIM-provisioned account", func(t *testing.T) {
		w := newLinkWorld(t)
		l, err := w.links.CreateCLI(context.Background(), "scim@acme.test")
		if err != nil || !l.PasskeyOnly {
			t.Fatalf("CreateCLI: %+v %v, want a passkey-only link", l, err)
		}
		if v, ok := w.dir.attrs["9"][ports.AttrPasswordByLink]; ok {
			t.Fatalf("attribute %v, want none", v)
		}
		if _, params, n := w.event(t); n != 1 || !strings.Contains(params, `"passkey_only": true`) ||
			!strings.Contains(params, `"organization_id": "`+w.org.String()+`"`) {
			t.Fatalf("%d events, params %s, want passkey_only true and the organization", n, params)
		}
	})
	t.Run("SCIM-claimed after an earlier mark", func(t *testing.T) {
		w := newLinkWorld(t)
		w.dir.attrs["9"] = map[string]any{ports.AttrPasswordByLink: true}
		l, err := w.links.CreateCLI(context.Background(), "scim@acme.test")
		if err != nil || !l.PasskeyOnly {
			t.Fatalf("CreateCLI: %+v %v, want a passkey-only link", l, err)
		}
		if v, ok := w.dir.attrs["9"][ports.AttrPasswordByLink]; ok {
			t.Fatalf("attribute %v, want the earlier mark removed", v)
		}
	})
	t.Run("platform and organization role", func(t *testing.T) {
		w := newLinkWorld(t)
		if _, err := w.links.CreateCLI(context.Background(), "both@acme.test"); err != nil {
			t.Fatal(err)
		}
		if _, params, n := w.event(t); n != 1 || !strings.Contains(params, `"organization_id": "`+w.org.String()+`"`) {
			t.Fatalf("%d events, params %s, want the organization", n, params)
		}
		if typ := w.target(t); typ != "platform_admin" {
			t.Fatalf("target type %q, want platform_admin", typ)
		}
	})
	t.Run("platform administrator", func(t *testing.T) {
		w := newLinkWorld(t)
		if _, err := w.links.CreateCLI(context.Background(), "root@example.test"); err != nil {
			t.Fatal(err)
		}
		if _, params, n := w.event(t); n != 1 || strings.Contains(params, "organization_id") {
			t.Fatalf("%d events, params %s, want no organization", n, params)
		}
		if typ := w.target(t); typ != "platform_admin" {
			t.Fatalf("target type %q, want platform_admin", typ)
		}
	})
}

// TestPlatformEnrolmentLinkDeletingOrganization (PDK-1112): the host command issues no link for an account of an
// organization that is being deleted or was deleted: invalid_state before the identity provider is asked to end or
// create a link or to mark the account, recorded as one failure in the platform pseudo-organization. A deleting
// organization is named in the event; a deleted one no longer holds its slug, so its role group belongs to no
// organization (ErrNoPortalRole).
func TestPlatformEnrolmentLinkDeletingOrganization(t *testing.T) {
	for _, c := range []struct {
		name, status string
		want         error
		named        bool
	}{
		{"deleting", `status = 'deleting', deletion_requested_at = now(), deletion_requested_by = 'platform admin',
			deletion_reason = 'contract ended', delete_after = now(), offboarding_step = 'database'`,
			app.ErrPortalAccountOrganizationOffboarding, true},
		{"deleted", `status = 'deleted', deleted_at = now(), deletion_requested_at = now(), deletion_requested_by = 'platform admin',
			deletion_reason = 'contract ended', delete_after = now()`, app.ErrNoPortalRole, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			w := newLinkWorld(t)
			if _, err := w.super.Exec(context.Background(), "UPDATE organization SET "+c.status+" WHERE id = $1", w.org); err != nil {
				t.Fatal(err)
			}
			w.dir.open["3"] = 1
			_, err := w.links.CreateCLI(context.Background(), "alice@acme.test")
			if !errors.Is(err, problem.InvalidState) || !errors.Is(err, c.want) {
				t.Fatalf("CreateCLI: %v, want %v", err, c.want)
			}
			if len(w.dir.links) != 0 || w.dir.open["3"] != 1 || len(w.dir.attrs["3"]) != 0 {
				t.Fatalf("links %v, open %v, attributes %v: want the identity provider untouched", w.dir.links, w.dir.open, w.dir.attrs)
			}
			ev, params, n := w.event(t)
			if n != 1 || ev != "failure invalid_state system:paddock-server admin "+platformOrg ||
				strings.Contains(params, `"organization_id": "`+w.org.String()+`"`) != c.named ||
				strings.Contains(params, "passkey_only") || strings.Contains(params, "previous_links_revoked") {
				t.Fatalf("%d events, %q %s, want one invalid_state failure, naming %s: %v", n, ev, params, w.org, c.named)
			}
		})
	}
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
