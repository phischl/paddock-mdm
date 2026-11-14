package app_test

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/domain/software"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/problem"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/pgtest"
)

// softwareTargetsWorld is an organization with a user, a user group the user is a member of, an APT entry and the
// use cases of the catalog, its sources and the device status, plus a second organization with its own user.
type softwareTargetsWorld struct {
	h                                 privilegesHarness
	catalog                           *app.SoftwareCatalog
	sources                           *app.SoftwareSources
	status                            *app.SoftwareStatus
	steppedUp, operator, auditor      principal.Principal
	user, other, group, entry, device uuid.UUID
	foreignOrg, foreignUser           uuid.UUID
	foreignGroup                      uuid.UUID
	foreignAdmin                      principal.Principal
	suffix                            string
}

func newSoftwareTargetsWorld(t *testing.T) softwareTargetsWorld {
	t.Helper()
	h := newPrivilegesHarness(t)
	pool, err := db.NewOrgPool(context.Background(), pgtest.SharedPaddock(t).API, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	w := softwareTargetsWorld{
		h: h, catalog: app.NewSoftwareCatalog(h.runner, pool), sources: app.NewSoftwareSources(h.runner, pool),
		status:    app.NewSoftwareStatus(pool),
		steppedUp: h.account(t, principal.RoleOrgAdmin, true), operator: h.account(t, principal.RoleOrgOperator, false),
		auditor: h.account(t, principal.RoleOrgAuditor, false),
		user:    uuid.Must(uuid.NewV7()), other: uuid.Must(uuid.NewV7()), group: uuid.Must(uuid.NewV7()),
		device: uuid.Must(uuid.NewV7()), foreignOrg: uuid.Must(uuid.NewV7()), foreignUser: uuid.Must(uuid.NewV7()),
		foreignGroup: uuid.Must(uuid.NewV7()),
	}
	w.foreignAdmin = principal.Principal{Kind: principal.KindAdmin, ID: uuid.Must(uuid.NewV7()), Subject: uuid.NewString(),
		Display: "foreign admin", Role: principal.RoleOrgAdmin, OrganizationID: w.foreignOrg, IP: "192.0.2.2",
		StepUpAt: time.Now()}
	suffix := uuid.NewString()[:8]
	for _, stmt := range []struct {
		sql  string
		args []any
	}{
		{"INSERT INTO app_user (id, organization_id, username, source) VALUES ($1, $2, $3, 'local')", []any{w.user, h.org, "alice-" + suffix + "@acme.test"}},
		{"INSERT INTO app_user (id, organization_id, username, source) VALUES ($1, $2, $3, 'local')", []any{w.other, h.org, "bob-" + suffix + "@acme.test"}},
		{"INSERT INTO user_group (id, organization_id, slug, name, source) VALUES ($1, $2, 'design', 'Design', 'local')", []any{w.group, h.org}},
		{"INSERT INTO user_group_member (organization_id, group_id, user_id) VALUES ($1, $2, $3)", []any{h.org, w.group, w.user}},
		{"INSERT INTO device (id, organization_id, hostname, state) VALUES ($1, $2, 'laptop', 'active')", []any{w.device, h.org}},
		{"INSERT INTO organization (id, slug, name, status) VALUES ($1, $2, 'Foreign', 'active')", []any{w.foreignOrg, "foreign-" + uuid.NewString()[:8]}},
		{"INSERT INTO app_user (id, organization_id, username, source) VALUES ($1, $2, $3, 'local')", []any{w.foreignUser, w.foreignOrg, "eve-" + suffix + "@foreign.test"}},
		{"INSERT INTO user_group (id, organization_id, slug, name, source) VALUES ($1, $2, 'design', 'Design', 'local')", []any{w.foreignGroup, w.foreignOrg}},
		{`INSERT INTO admin_account (id, organization_id, authentik_sub, username, display_name, role)
			VALUES ($1, $2, $3, 'foreign admin', 'foreign admin', 'org_admin')`, []any{w.foreignAdmin.ID, w.foreignOrg, w.foreignAdmin.Subject}},
	} {
		if _, err := h.super.Exec(context.Background(), stmt.sql, stmt.args...); err != nil {
			t.Fatalf("%s: %v", stmt.sql, err)
		}
	}
	entry, err := w.catalog.Create(w.ctx(w.operator), app.EntryInput{Name: "Inkscape",
		Packages: []software.PackageRef{{Distribution: "ubuntu", Release: "*", Architecture: "*", Package: "inkscape"}}})
	if err != nil {
		t.Fatal(err)
	}
	w.entry, w.suffix = entry.ID, suffix
	return w
}

func (w softwareTargetsWorld) ctx(p principal.Principal) context.Context {
	return principal.With(context.Background(), p)
}

// TestSoftwareAssignmentTargets (plan M13b decisions 1, 4 and 6, §6.4): an assignment targets a user or a user group of
// the organization, never two targets and never another organization's; the audit params name the target; the target
// cannot change; the list filters by target; a user-targeted assignment is not shown as organization-wide on a device.
func TestSoftwareAssignmentTargets(t *testing.T) {
	w := newSoftwareTargetsWorld(t)
	h := w.h
	op := w.ctx(w.operator)

	direct, err := w.catalog.CreateAssignment(op, app.AssignmentInput{CatalogEntryID: &w.entry, UserID: &w.user,
		Intent: software.IntentAvailable, Reason: "design team"})
	if err != nil {
		t.Fatal(err)
	}
	if !direct.UserID.Valid || direct.UserID.UUID != w.user || direct.UserGroupID.Valid || direct.DeviceGroupID.Valid ||
		direct.Intent != software.IntentAvailable || direct.UpdateRule != software.UpdateLatest {
		t.Fatalf("user assignment %+v", direct)
	}
	ev := h.lastEvent(t)
	if ev.Params["target"] != "user" || ev.Params["user_id"] != w.user.String() || ev.Params["user_group_id"] != nil ||
		ev.Params["device_group_id"] != nil || ev.Target.Display != "Inkscape → alice-"+w.suffix+"@acme.test" {
		t.Fatalf("user assignment event %+v", ev)
	}
	viaGroup, err := w.catalog.CreateAssignment(op, app.AssignmentInput{CatalogEntryID: &w.entry, UserGroupID: &w.group,
		Intent: software.IntentRequired})
	if err != nil {
		t.Fatal(err)
	}
	if ev := h.lastEvent(t); ev.Params["target"] != "user_group" || ev.Params["user_group_id"] != w.group.String() ||
		ev.Target.Display != "Inkscape → Design" {
		t.Fatalf("user group assignment event %+v", ev)
	}

	got := h.during(t, func() {
		for name, c := range map[string]struct {
			in   app.AssignmentInput
			want error
		}{
			"two targets": {app.AssignmentInput{CatalogEntryID: &w.entry, UserID: &w.other, UserGroupID: &w.group,
				Intent: software.IntentAvailable}, problem.InvalidRequest},
			"available with a version": {app.AssignmentInput{CatalogEntryID: &w.entry, UserID: &w.other,
				Intent: software.IntentAvailable, Version: new("1.0")}, problem.InvalidRequest},
			"second assignment to the user": {app.AssignmentInput{CatalogEntryID: &w.entry, UserID: &w.user,
				Intent: software.IntentForbid}, problem.AlreadyExists},
			"user of another organization": {app.AssignmentInput{CatalogEntryID: &w.entry, UserID: &w.foreignUser,
				Intent: software.IntentAvailable}, problem.NotFound},
			"user group of another organization": {app.AssignmentInput{CatalogEntryID: &w.entry, UserGroupID: &w.foreignGroup,
				Intent: software.IntentAvailable}, problem.NotFound},
			"unknown user": {app.AssignmentInput{CatalogEntryID: &w.entry, UserID: new(uuid.New()),
				Intent: software.IntentAvailable}, problem.NotFound},
		} {
			if _, err := w.catalog.CreateAssignment(op, c.in); !errors.Is(err, c.want) {
				t.Errorf("%s = %v, want %v", name, err, c.want)
			}
		}
	})
	if len(got) != 6 || slices.ContainsFunc(got, func(a string) bool {
		return a[:len("software_assignment.created:failure")] != "software_assignment.created:failure"
	}) {
		t.Fatalf("refused assignments recorded %v", got)
	}

	if _, err := w.catalog.UpdateAssignment(op, direct.ID, app.AssignmentInput{UserID: &w.other, Intent: software.IntentAvailable}); !errors.Is(err, problem.InvalidRequest) {
		t.Fatalf("target change = %v", err)
	}
	if _, err := w.catalog.UpdateAssignment(op, direct.ID, app.AssignmentInput{UserGroupID: &w.group, Intent: software.IntentAvailable}); !errors.Is(err, problem.InvalidRequest) {
		t.Fatalf("target change to a group = %v", err)
	}
	updated, err := w.catalog.UpdateAssignment(op, direct.ID, app.AssignmentInput{Intent: software.IntentHold})
	if err != nil || updated.Intent != software.IntentHold || updated.UserID.UUID != w.user {
		t.Fatalf("update = %+v, %v", updated, err)
	}
	if ev := h.lastEvent(t); ev.Params["target"] != "user" || ev.Params["user_id"] != w.user.String() || ev.Params["old_intent"] != "available" {
		t.Fatalf("update event %+v", ev)
	}

	orgWide, err := w.catalog.CreateAssignment(op, app.AssignmentInput{CatalogEntryID: &w.entry, Intent: software.IntentAvailable})
	if err != nil {
		t.Fatal(err)
	}
	if ev := h.lastEvent(t); ev.Params["target"] != "organization" {
		t.Fatalf("organization-wide event %+v", ev)
	}
	list := func(q app.SoftwareAssignmentQuery) []uuid.UUID {
		t.Helper()
		q.Page = app.ListPage{Sort: "-created_at", Limit: 25}
		page, err := w.catalog.ListAssignments(w.ctx(w.auditor), q)
		if err != nil {
			t.Fatal(err)
		}
		var ids []uuid.UUID
		for _, a := range page.Items {
			ids = append(ids, a.ID)
		}
		if len(ids) != page.Count {
			t.Fatalf("listed %d of a count of %d", len(ids), page.Count)
		}
		return ids
	}
	for name, c := range map[string]struct {
		q    app.SoftwareAssignmentQuery
		want []uuid.UUID
	}{
		"all":                     {app.SoftwareAssignmentQuery{}, []uuid.UUID{orgWide.ID, viaGroup.ID, direct.ID}},
		"target user":             {app.SoftwareAssignmentQuery{Target: new("user")}, []uuid.UUID{direct.ID}},
		"target user_group":       {app.SoftwareAssignmentQuery{Target: new("user_group")}, []uuid.UUID{viaGroup.ID}},
		"target organization":     {app.SoftwareAssignmentQuery{Target: new("organization")}, []uuid.UUID{orgWide.ID}},
		"target device_group":     {app.SoftwareAssignmentQuery{Target: new("device_group")}, nil},
		"user_id":                 {app.SoftwareAssignmentQuery{UserID: &w.user}, []uuid.UUID{direct.ID}},
		"user_group_id":           {app.SoftwareAssignmentQuery{UserGroupID: &w.group}, []uuid.UUID{viaGroup.ID}},
		"user_id of another user": {app.SoftwareAssignmentQuery{UserID: &w.other}, nil},
	} {
		if got := list(c.q); !slices.Equal(got, c.want) {
			t.Errorf("%s: listed %v, want %v", name, got, c.want)
		}
	}

	// The device has no owner and is in no group: of the three assignments only the organization-wide one applies, and
	// without an os-release no package resolves.
	managed, err := w.status.DeviceManagedSoftware(w.ctx(w.auditor), w.device, app.DeviceManagedSoftwareQuery{
		Page: app.ListPage{Sort: "name", Limit: 25}})
	if err != nil {
		t.Fatal(err)
	}
	if len(managed.Items) != 1 || managed.Items[0].CatalogEntryID != w.entry || managed.Items[0].State != "not_applicable" {
		t.Fatalf("managed software of the device %+v", managed.Items)
	}
	if err := w.catalog.DeleteAssignment(w.ctx(w.auditor), orgWide.ID); !errors.Is(err, problem.Forbidden) {
		t.Fatal(err)
	}
	if err := w.catalog.DeleteAssignment(op, orgWide.ID); err != nil {
		t.Fatal(err)
	}
	managed, err = w.status.DeviceManagedSoftware(w.ctx(w.auditor), w.device, app.DeviceManagedSoftwareQuery{
		Page: app.ListPage{Sort: "name", Limit: 25}})
	if err != nil || len(managed.Items) != 0 {
		t.Fatalf("a user or user-group assignment applied to a device without owners: %+v, %v", managed.Items, err)
	}

	if err := w.catalog.DeleteAssignment(op, viaGroup.ID); err != nil {
		t.Fatal(err)
	}
	if ev := h.lastEvent(t); ev.Params["target"] != "user_group" || ev.Params["user_group_id"] != w.group.String() ||
		ev.Params["user_id"] != nil || ev.Params["intent"] != "required" {
		t.Fatalf("delete event %+v", ev)
	}

	// Isolation: another organization's administrator sees none of these assignments, and deleting the user removes
	// the user's assignment.
	if _, err := w.catalog.GetAssignment(w.ctx(w.foreignAdmin), direct.ID); !errors.Is(err, problem.NotFound) {
		t.Fatalf("foreign read = %v", err)
	}
	if _, err := h.super.Exec(context.Background(), "DELETE FROM app_user WHERE id = $1", w.user); err != nil {
		t.Fatal(err)
	}
	if _, err := w.catalog.GetAssignment(w.ctx(w.auditor), direct.ID); !errors.Is(err, problem.NotFound) {
		t.Fatalf("the deleted user's assignment = %v", err)
	}
}

// TestUserSoftware (plan M13b decision 6, §6.1): GET /users/{id}/software lists the assignments that target the user
// directly or through a user group, neither the organization's nor another user's; it sorts and filters by intent,
// and a missing user or another organization's is not found.
func TestUserSoftware(t *testing.T) {
	w := newSoftwareTargetsWorld(t)
	op := w.ctx(w.operator)
	second, err := w.catalog.Create(op, app.EntryInput{Name: "Blender",
		Packages: []software.PackageRef{{Distribution: "ubuntu", Release: "*", Architecture: "*", Package: "blender"}}})
	if err != nil {
		t.Fatal(err)
	}
	third, err := w.catalog.Create(op, app.EntryInput{Name: "Calibre",
		Packages: []software.PackageRef{{Distribution: "ubuntu", Release: "*", Architecture: "*", Package: "calibre"}}})
	if err != nil {
		t.Fatal(err)
	}
	assign := func(in app.AssignmentInput) uuid.UUID {
		t.Helper()
		a, err := w.catalog.CreateAssignment(op, in)
		if err != nil {
			t.Fatal(err)
		}
		return a.ID
	}
	direct := assign(app.AssignmentInput{CatalogEntryID: &w.entry, UserID: &w.user, Intent: software.IntentAvailable})
	viaGroup := assign(app.AssignmentInput{CatalogEntryID: &second.ID, UserGroupID: &w.group, Intent: software.IntentRequired,
		Reason: "rendering"})
	assign(app.AssignmentInput{CatalogEntryID: &third.ID, Intent: software.IntentAvailable})
	assign(app.AssignmentInput{CatalogEntryID: &third.ID, UserID: &w.other, Intent: software.IntentForbid})

	list := func(p principal.Principal, user uuid.UUID, sort string, intent *string) (app.Listed[app.UserSoftware], error) {
		return w.catalog.UserSoftware(w.ctx(p), user, app.UserSoftwareQuery{Page: app.ListPage{Sort: sort, Limit: 25}, Intent: intent})
	}
	page, err := list(w.auditor, w.user, "name", nil)
	if err != nil {
		t.Fatal(err)
	}
	if page.Count != 2 || len(page.Items) != 2 {
		t.Fatalf("listed %+v", page)
	}
	if a, b := page.Items[0], page.Items[1]; a.ID != viaGroup || a.Name != "Blender" || a.Intent != software.IntentRequired ||
		a.UserGroupID.UUID != w.group || a.UserGroupName != "Design" || a.Reason != "rendering" ||
		b.ID != direct || b.Name != "Inkscape" || b.Intent != software.IntentAvailable || b.UserGroupID.Valid || b.UserGroupName != "" {
		t.Fatalf("items %+v", page.Items)
	}
	if page, err := list(w.auditor, w.user, "-name", nil); err != nil || page.Items[0].ID != direct {
		t.Fatalf("-name: %+v, %v", page.Items, err)
	}
	if page, err := list(w.auditor, w.user, "intent", nil); err != nil || page.Items[0].ID != direct {
		t.Fatalf("intent: %+v, %v", page.Items, err)
	}
	if page, err := list(w.auditor, w.user, "name", new(software.IntentRequired)); err != nil || page.Count != 1 || page.Items[0].ID != viaGroup {
		t.Fatalf("intent filter: %+v, %v", page, err)
	}
	if page, err := list(w.auditor, w.other, "name", nil); err != nil || page.Count != 1 || page.Items[0].Intent != software.IntentForbid {
		t.Fatalf("the other user: %+v, %v", page, err)
	}

	if _, err := list(w.auditor, uuid.New(), "name", nil); !errors.Is(err, problem.NotFound) {
		t.Fatalf("unknown user = %v", err)
	}
	if _, err := list(w.foreignAdmin, w.user, "name", nil); !errors.Is(err, problem.NotFound) {
		t.Fatalf("another organization's user = %v", err)
	}
	if page, err := list(w.foreignAdmin, w.foreignUser, "name", nil); err != nil || page.Count != 0 {
		t.Fatalf("the foreign organization's own user: %+v, %v", page, err)
	}
}

// TestFlatpakSources (plan M13b decisions 3 and 5): a Flatpak remote needs a step-up like every source, has exactly
// one URI and no suites, and its kind never changes; its entries name Flatpak applications only, and an APT source's
// entries never do.
func TestFlatpakSources(t *testing.T) {
	w := newSoftwareTargetsWorld(t)
	h := w.h
	key := sourceKey(t, "ed25519.asc")
	flathub := software.SourceInput{Kind: software.SourceKindFlatpak, Slug: "flathub", Name: "Flathub",
		URIs: []string{"https://dl.flathub.org/repo/"}, SigningKey: key, Fingerprint: sourceEd25519FP}
	admin := h.account(t, principal.RoleOrgAdmin, false)
	if _, err := w.sources.Create(w.ctx(admin), flathub); !errors.Is(err, problem.StepUpRequired) {
		t.Fatalf("create without step-up = %v", err)
	}
	if ev := h.lastEvent(t); ev.Params["kind"] != "flatpak" {
		t.Fatalf("denied create event %+v", ev)
	}
	src, err := w.sources.Create(w.ctx(w.steppedUp), flathub)
	if err != nil {
		t.Fatal(err)
	}
	if src.Kind != software.SourceKindFlatpak || len(src.Suites) != 0 || len(src.Components) != 0 {
		t.Fatalf("created %+v", src.SoftwareSource)
	}
	if ev := h.lastEvent(t); ev.Params["kind"] != "flatpak" {
		t.Fatalf("created event %+v", ev)
	}
	twoURIs := flathub
	twoURIs.Slug, twoURIs.Name, twoURIs.URIs = "two", "Two", []string{"https://a.example/repo/", "https://b.example/repo/"}
	if _, err := w.sources.Create(w.ctx(w.steppedUp), twoURIs); !errors.Is(err, problem.InvalidRequest) {
		t.Fatalf("two URIs = %v", err)
	}
	apt, err := w.sources.Create(w.ctx(w.steppedUp), software.SourceInput{Slug: "vendor", Name: "Vendor",
		URIs: []string{"https://apt.vendor.example/"}, Suites: []string{"stable"}, Components: []string{"main"},
		SigningKey: key, Fingerprint: sourceEd25519FP})
	if err != nil || apt.Kind != software.SourceKindAPT {
		t.Fatalf("apt source %+v, %v", apt.SoftwareSource, err)
	}

	for name, c := range map[string]struct {
		id   uuid.UUID
		kind string
	}{"apt to flatpak": {apt.ID, software.SourceKindFlatpak}, "flatpak to apt": {src.ID, software.SourceKindAPT}} {
		if _, err := w.sources.Update(w.ctx(w.steppedUp), c.id, app.SourceUpdate{Kind: new(c.kind)}); !errors.Is(err, problem.InvalidRequest) {
			t.Errorf("%s = %v", name, err)
		}
	}
	if _, err := w.sources.Update(w.ctx(w.steppedUp), src.ID, app.SourceUpdate{Kind: new(software.SourceKindFlatpak), Name: new("Flathub EU")}); err != nil {
		t.Fatalf("update naming the same kind = %v", err)
	}
	if ev := h.lastEvent(t); ev.Params["kind"] != "flatpak" {
		t.Fatalf("updated event %+v", ev)
	}
	if _, err := w.sources.Update(w.ctx(w.steppedUp), src.ID, app.SourceUpdate{Suites: &[]string{"stable"}}); !errors.Is(err, problem.InvalidRequest) {
		t.Fatalf("a suite on a flatpak source = %v", err)
	}

	gimp := []software.PackageRef{{Distribution: "ubuntu", Release: "*", Architecture: "*", FlatpakRef: "org.gimp.GIMP"}}
	nano := []software.PackageRef{{Distribution: "ubuntu", Release: "*", Architecture: "*", Package: "nano"}}
	for name, in := range map[string]app.EntryInput{
		"flatpak_ref on an apt source":           {Name: "GIMP apt", SourceID: &apt.ID, Packages: gimp},
		"flatpak_ref without a source":           {Name: "GIMP plain", Packages: gimp},
		"apt package on a flatpak source":        {Name: "Nano flatpak", SourceID: &src.ID, Packages: nano},
		"flatpak_ref and package in one element": {Name: "Both", SourceID: &src.ID, Packages: []software.PackageRef{{Distribution: "ubuntu", Release: "*", Architecture: "*", FlatpakRef: "org.gimp.GIMP", Package: "gimp"}}},
	} {
		if _, err := w.catalog.Create(w.ctx(w.operator), in); !errors.Is(err, problem.InvalidRequest) {
			t.Errorf("%s = %v", name, err)
		}
	}
	entry, err := w.catalog.Create(w.ctx(w.operator), app.EntryInput{Name: "GIMP", SourceID: &src.ID, Packages: gimp})
	if err != nil {
		t.Fatal(err)
	}
	stored, err := software.DecodePackages(entry.Packages)
	if err != nil || len(stored) != 1 || stored[0].FlatpakRef != "org.gimp.GIMP" || stored[0].Scope != software.ScopeSystem || stored[0].Package != "" {
		t.Fatalf("stored references %+v, %v", stored, err)
	}
	if _, err := w.catalog.Update(w.ctx(w.operator), entry.ID, app.EntryInput{Name: "GIMP", SourceID: &apt.ID, Packages: gimp}); !errors.Is(err, problem.InvalidRequest) {
		t.Fatalf("moving a flatpak entry to an apt source = %v", err)
	}
	user := []software.PackageRef{{Distribution: "ubuntu", Release: "*", Architecture: "*", FlatpakRef: "org.gimp.GIMP", Scope: software.ScopeUser}}
	if _, err := w.catalog.Update(w.ctx(w.operator), entry.ID, app.EntryInput{Name: "GIMP", SourceID: &src.ID, Packages: user}); err != nil {
		t.Fatalf("user scope = %v", err)
	}
	if _, err := w.catalog.CreateAssignment(w.ctx(w.operator), app.AssignmentInput{CatalogEntryID: &entry.ID, UserGroupID: &w.group,
		Intent: software.IntentAvailable}); err != nil {
		t.Fatalf("available user-scope flatpak for a user group = %v", err)
	}
}
