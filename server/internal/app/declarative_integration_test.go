package app_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/domain/declarative"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/problem"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/pgtest"
)

// configHarness is the harness of the declarative configuration tests.
type configHarness struct {
	tokenHarness
	config *app.Declarative
}

func newConfigHarness(t *testing.T) configHarness {
	t.Helper()
	h := newTokenHarness(t)
	pool, err := db.NewOrgPool(context.Background(), pgtest.SharedPaddock(t).API, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	return configHarness{tokenHarness: h, config: app.NewDeclarative(h.runner, pool)}
}

func (h configHarness) export(t *testing.T, p principal.Principal) declarative.Document {
	t.Helper()
	doc, err := h.config.Export(principal.With(context.Background(), p))
	if err != nil {
		t.Fatal(err)
	}
	return doc
}

func raw(t *testing.T, doc declarative.Document) []byte {
	t.Helper()
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func (h configHarness) count(t *testing.T, sql string, args ...any) int {
	t.Helper()
	var n int
	if err := h.super.QueryRow(context.Background(), sql, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestDeclarativeExportApplyRoundTrip(t *testing.T) {
	h := newConfigHarness(t)
	admin := h.account(t, principal.RoleOrgAdmin, false)
	ctx := principal.With(context.Background(), admin)
	doc := h.export(t, admin)
	if doc.Settings == nil || doc.Settings.Login == nil || doc.Settings.Updates == nil || doc.DeviceGroups == nil ||
		doc.PermissionProfiles == nil || doc.ManagedFiles == nil || doc.ManagedUnits == nil || doc.PackageHolds == nil ||
		doc.ProfileAssignments == nil {
		t.Fatalf("export lacks sections: %+v", doc)
	}
	if err := declarative.ValidateJSON(raw(t, doc)); err != nil {
		t.Fatalf("the export violates the schema: %v", err)
	}
	var plan declarative.Plan
	got := h.during(t, func() {
		var err error
		if plan, err = h.config.Plan(ctx, raw(t, doc)); err != nil {
			t.Fatal(err)
		}
	})
	if len(plan.Changes) != 0 || len(got) != 0 {
		t.Fatalf("dry run of the export: plan %+v, actions %v", plan, got)
	}
	got = h.during(t, func() {
		id, plan, err := h.config.Apply(ctx, raw(t, doc), "")
		if err != nil || id != uuid.Nil || len(plan.Changes) != 0 {
			t.Fatalf("Apply = %s, %+v, %v", id, plan, err)
		}
	})
	if len(got) != 1 || got[0] != "config.applied:success:" {
		t.Fatalf("actions %v", got)
	}
	_, events := h.recorded(t, h.corr)
	if ev := events[len(events)-1]; ev.Params["change_set_id"] != nil || ev.Params["created"] != float64(0) || ev.Target != nil {
		t.Fatalf("empty apply event %+v", ev)
	}
	if n := h.count(t, "SELECT count(*) FROM change_set WHERE organization_id = $1", h.org); n != 0 {
		t.Fatalf("%d change sets after an empty apply", n)
	}
}

func TestDeclarativeApplyChanges(t *testing.T) {
	h := newConfigHarness(t)
	admin := h.account(t, principal.RoleOrgAdmin, false)
	ctx := principal.With(context.Background(), admin)
	hold := uuid.Must(uuid.NewV7())
	if _, err := h.super.Exec(context.Background(), "INSERT INTO package_hold (id, organization_id, package, reason) VALUES ($1, $2, 'firefox', '')", hold, h.org); err != nil {
		t.Fatal(err)
	}
	doc := h.export(t, admin)
	*doc.DeviceGroups = append(*doc.DeviceGroups, declarative.DeviceGroup{Name: "laptops"})
	*doc.ManagedFiles = append(*doc.ManagedFiles, declarative.ManagedFile{Path: "/etc/motd", DeviceGroup: strPtr("laptops"), Mode: "0644",
		Owner: "root", Group: "root", Content: "managed by paddock"})
	doc.Settings.Updates.SecurityDailyAt = "02:15"
	*doc.PackageHolds = []declarative.PackageHold{}

	plan, err := h.config.Plan(ctx, raw(t, doc))
	if err != nil {
		t.Fatal(err)
	}
	if plan.Created != 2 || plan.Updated != 1 || plan.Deleted != 1 {
		t.Fatalf("dry run %+v", plan)
	}
	if n := h.count(t, "SELECT count(*) FROM managed_file WHERE organization_id = $1", h.org); n != 0 {
		t.Fatal("the dry run applied changes")
	}

	var id uuid.UUID
	got := h.during(t, func() {
		if id, plan, err = h.config.Apply(ctx, raw(t, doc), ""); err != nil {
			t.Fatal(err)
		}
	})
	if len(got) != 1 || got[0] != "config.applied:success:" || id == uuid.Nil {
		t.Fatalf("actions %v, change set %s", got, id)
	}
	_, events := h.recorded(t, h.corr)
	ev := events[len(events)-1]
	if ev.Params["change_set_id"] != id.String() || ev.Params["created"] != float64(2) || ev.Params["deleted"] != float64(1) ||
		ev.Target == nil || ev.Target.Type != "change_set" {
		t.Fatalf("event %+v", ev)
	}
	if n := h.count(t, "SELECT count(*) FROM managed_file f JOIN device_group g ON g.id = f.device_group_id WHERE f.organization_id = $1 AND g.name = 'laptops'", h.org); n != 1 {
		t.Fatal("managed file not created in laptops")
	}
	if n := h.count(t, "SELECT count(*) FROM package_hold WHERE id = $1", hold); n != 0 {
		t.Fatal("hold not deleted")
	}
	if n := h.count(t, "SELECT count(*) FROM organization_update_settings WHERE organization_id = $1 AND security_daily_at = '02:15'", h.org); n != 1 {
		t.Fatal("update settings not changed")
	}
	if n := h.count(t, "SELECT count(*) FROM outbox WHERE organization_id = $1 AND subject = $2", h.org, "state."+h.org.String()); n != 1 {
		t.Fatalf("%d state changes, want exactly one", n)
	}
	cs, err := h.config.GetChangeSet(ctx, id)
	if err != nil || cs.Source != app.ChangeSetSourceSession || cs.CreatedN != 2 || cs.DeletedN != 1 ||
		strings.Join(cs.Sections, ",") != "device_groups,managed_files,package_holds,settings.updates" {
		t.Fatalf("change set %+v, %v", cs, err)
	}
	if strings.Contains(string(cs.Plan), "managed by paddock") {
		t.Fatal("the change set carries file content")
	}
	list, err := h.config.ListChangeSets(ctx, app.ChangeSetQuery{Page: app.ListPage{Sort: "-applied_at", Limit: 10}})
	if err != nil || list.Count != 1 || list.Items[0].ID != id {
		t.Fatalf("ListChangeSets = %+v, %v", list, err)
	}
	if again := h.export(t, admin); len(declarative.Diff(again, doc).Changes) != 0 {
		t.Fatalf("export after apply differs: %+v", declarative.Diff(again, doc))
	}
}

func TestDeclarativeApplyIsAtomic(t *testing.T) {
	h := newConfigHarness(t)
	admin := h.account(t, principal.RoleOrgAdmin, false)
	ctx := principal.With(context.Background(), admin)
	doc := h.export(t, admin)
	*doc.ManagedFiles = append(*doc.ManagedFiles, declarative.ManagedFile{Path: "/etc/ok.conf", Mode: "0644", Owner: "root", Group: "root"})
	*doc.ManagedUnits = append(*doc.ManagedUnits, declarative.ManagedUnit{Unit: "paddockd.service", Enabled: true, Active: true})
	for name, apply := range map[string]func() error{
		"dry run": func() error { _, err := h.config.Plan(ctx, raw(t, doc)); return err },
		"apply":   func() error { _, _, err := h.config.Apply(ctx, raw(t, doc), ""); return err },
	} {
		err := apply()
		if !errors.Is(err, problem.UnitNotAllowed) || !strings.HasPrefix(problem.From(err).Detail, "/managed_units/0: ") {
			t.Fatalf("%s = %v, want unit_not_allowed at /managed_units/0", name, err)
		}
	}
	if n := h.count(t, "SELECT count(*) FROM managed_file WHERE organization_id = $1", h.org); n != 0 {
		t.Fatal("a refused apply left a managed file")
	}
	if got := h.actions(t); len(got) != 1 || got[0] != "config.applied:failure:unit_not_allowed" {
		t.Fatalf("actions %v", got)
	}

	bad := strings.Replace(string(raw(t, doc)), `"mode":"0644"`, `"mode":"999"`, 1)
	_, _, err := h.config.Apply(ctx, []byte(bad), "")
	if !errors.Is(err, problem.InvalidDocument) || !strings.Contains(problem.From(err).Detail, "/managed_files/0/mode") {
		t.Fatalf("schema violation = %v", err)
	}
	dup := h.export(t, admin)
	*dup.DeviceGroups = append(*dup.DeviceGroups, declarative.DeviceGroup{Name: "a"}, declarative.DeviceGroup{Name: " a"})
	if _, err := h.config.Plan(ctx, raw(t, dup)); !errors.Is(err, problem.InvalidDocument) || !strings.Contains(err.Error(), "/device_groups/1") {
		t.Fatalf("duplicate after normalization = %v", err)
	}
	if _, err := h.config.Plan(ctx, make([]byte, app.MaxDocumentBytes+1)); !errors.Is(err, problem.InvalidRequest) {
		t.Fatalf("oversized document = %v", err)
	}
}

func TestDeclarativeRulesOfThePerResourceUseCases(t *testing.T) {
	h := newConfigHarness(t)
	admin := h.account(t, principal.RoleOrgAdmin, false)
	operator := h.account(t, principal.RoleOrgOperator, false)
	auditor := h.account(t, principal.RoleOrgAuditor, false)
	steppedUp := h.account(t, principal.RoleOrgAdmin, true)
	ctx := func(p principal.Principal) context.Context { return principal.With(context.Background(), p) }
	group := uuid.Must(uuid.NewV7())
	if _, err := h.super.Exec(context.Background(), "INSERT INTO device_group (id, organization_id, name) VALUES ($1, $2, 'kept')", group, h.org); err != nil {
		t.Fatal(err)
	}
	if _, err := h.super.Exec(context.Background(), `INSERT INTO enrollment_token (id, organization_id, name, secret_sha256, device_group_id,
		auto_approve, max_uses, expires_at, created_by) VALUES ($1, $2, 't', $3, $4, false, 1, now() + interval '1 day', $5)`,
		uuid.Must(uuid.NewV7()), h.org, []byte(uuid.NewString()), group, admin.ID); err != nil {
		t.Fatal(err)
	}
	base := h.export(t, admin)

	noGroups := base
	noGroups.DeviceGroups = &[]declarative.DeviceGroup{}
	if _, _, err := h.config.Apply(ctx(operator), raw(t, noGroups), ""); !errors.Is(err, problem.Forbidden) {
		t.Fatalf("operator deleting a device group = %v", err)
	}
	if _, _, err := h.config.Apply(ctx(admin), raw(t, noGroups), ""); !errors.Is(err, problem.InUse) {
		t.Fatalf("deleting a device group with an enrollment token = %v", err)
	}
	settings := h.export(t, admin)
	settings.Settings.Login.HelloEnabled = !settings.Settings.Login.HelloEnabled
	if _, _, err := h.config.Apply(ctx(operator), raw(t, settings), ""); !errors.Is(err, problem.Forbidden) {
		t.Fatalf("operator changing login settings = %v", err)
	}
	if _, err := h.config.Plan(ctx(auditor), raw(t, base)); !errors.Is(err, problem.Forbidden) {
		t.Fatalf("auditor dry run = %v", err)
	}
	schedule := h.export(t, admin)
	schedule.Settings.Updates.RegularSchedule = "Mon..Fri 04:00"
	if _, _, err := h.config.Apply(ctx(admin), raw(t, schedule), ""); !errors.Is(err, problem.InvalidSchedule) ||
		!strings.HasPrefix(problem.From(err).Detail, "/settings/updates: ") {
		t.Fatalf("invalid schedule = %v", err)
	}

	// A full profile and its assignment need a step-up; an API token never has one.
	full := h.export(t, admin)
	*full.PermissionProfiles = append(*full.PermissionProfiles, declarative.PermissionProfile{Name: "root", Class: "full",
		Commands: []string{}, RequirePassword: true, TimestampTimeoutMin: 5, Lecture: "once"})
	*full.ProfileAssignments = append(*full.ProfileAssignments, declarative.ProfileAssignment{Profile: "root",
		Subject: declarative.Subject{Type: "global"}, DeviceGroup: strPtr("kept")})
	token := h.create(t, steppedUp, "ci", principal.RoleOrgAdmin)
	tp, _, err := h.tokens.Authenticate(context.Background(), token.Secret, "")
	if err != nil {
		t.Fatal(err)
	}
	got := h.during(t, func() {
		if _, _, err := h.config.Apply(ctx(tp), raw(t, full), ""); !errors.Is(err, problem.StepUpRequired) {
			t.Errorf("token assigning a full profile = %v", err)
		}
	})
	if len(got) != 1 || got[0] != "config.applied:denied:step_up_required" {
		t.Fatalf("actions %v", got)
	}
	if n := h.count(t, "SELECT count(*) FROM permission_profile WHERE organization_id = $1", h.org); n != 0 {
		t.Fatal("the refused apply created the profile")
	}
	id, _, err := h.config.Apply(ctx(steppedUp), raw(t, full), "")
	if err != nil || id == uuid.Nil {
		t.Fatalf("stepped-up apply = %v", err)
	}
	cs, err := h.config.GetChangeSet(ctx(admin), id)
	if err != nil || !strings.Contains(string(cs.Actor), `"step_up": true`) || cs.Source != app.ChangeSetSourceSession {
		t.Fatalf("change set %+v, %v", cs, err)
	}

	// Subjects are resolved by slug and username.
	unknown := h.export(t, admin)
	*unknown.ProfileAssignments = append(*unknown.ProfileAssignments, declarative.ProfileAssignment{Profile: "root",
		Subject: declarative.Subject{Type: "group", Slug: "nobody"}})
	if _, err := h.config.Plan(ctx(steppedUp), raw(t, unknown)); !errors.Is(err, problem.InvalidRequest) ||
		!strings.Contains(err.Error(), `unknown group "nobody"`) {
		t.Fatalf("unknown group = %v", err)
	}

	// Changes made with a token are attributed to it.
	tokenDoc := h.export(t, admin)
	*tokenDoc.PackageHolds = append(*tokenDoc.PackageHolds, declarative.PackageHold{Package: "vim"})
	id, _, err = h.config.Apply(ctx(tp), raw(t, tokenDoc), "")
	if err != nil {
		t.Fatal(err)
	}
	cs, err = h.config.GetChangeSet(ctx(admin), id)
	if err != nil || cs.Source != app.ChangeSetSourceAPIToken || !strings.Contains(string(cs.Actor), `"type": "api_token"`) {
		t.Fatalf("token change set %+v, %v", cs, err)
	}
	list, err := h.config.ListChangeSets(ctx(auditor), app.ChangeSetQuery{Page: app.ListPage{Sort: "applied_at", Limit: 10}, Sources: []string{"api_token"}})
	if err != nil || list.Count != 1 || list.Items[0].ID != id {
		t.Fatalf("source filter = %+v, %v", list, err)
	}
}

func strPtr(s string) *string { return &s }

// TestDeclarativeNamesWithSeparators: an organization with profiles "lab:ops" and "ops", a group "lab", the global
// assignment of "lab:ops" and the assignment of "ops" in "lab" round-trips unchanged, and a document keeping only the
// second deletes the first instead of rewriting it (review 1 of PDK-008).
func TestDeclarativeNamesWithSeparators(t *testing.T) {
	h := newConfigHarness(t)
	admin := h.account(t, principal.RoleOrgAdmin, false)
	ctx := principal.With(context.Background(), admin)
	doc := h.export(t, admin)
	*doc.DeviceGroups = append(*doc.DeviceGroups, declarative.DeviceGroup{Name: "lab"}, declarative.DeviceGroup{Name: "lab:x"})
	none := func(name string) declarative.PermissionProfile {
		return declarative.PermissionProfile{Name: name, Class: "none", Commands: []string{}, RequirePassword: true, TimestampTimeoutMin: 5, Lecture: "once"}
	}
	*doc.PermissionProfiles = append(*doc.PermissionProfiles, none("lab:ops"), none("ops"))
	*doc.ProfileAssignments = append(*doc.ProfileAssignments,
		declarative.ProfileAssignment{Profile: "lab:ops", Subject: declarative.Subject{Type: "global"}},
		declarative.ProfileAssignment{Profile: "ops", Subject: declarative.Subject{Type: "global"}, DeviceGroup: strPtr("lab")})
	if _, _, err := h.config.Apply(ctx, raw(t, doc), ""); err != nil {
		t.Fatal(err)
	}
	if n := h.count(t, "SELECT count(*) FROM profile_assignment WHERE organization_id = $1", h.org); n != 2 {
		t.Fatalf("%d assignments, want 2", n)
	}

	exported := h.export(t, admin)
	plan, err := h.config.Plan(ctx, raw(t, exported))
	if err != nil || len(plan.Changes) != 0 {
		t.Fatalf("dry run of the unchanged export: %+v, %v", plan, err)
	}
	if id, plan, err := h.config.Apply(ctx, raw(t, exported), ""); err != nil || id != uuid.Nil || len(plan.Changes) != 0 {
		t.Fatalf("apply of the unchanged export: %s %+v %v", id, plan, err)
	}

	only := h.export(t, admin)
	kept := []declarative.ProfileAssignment{}
	for _, a := range *only.ProfileAssignments {
		if a.Profile == "ops" {
			kept = append(kept, a)
		}
	}
	*only.ProfileAssignments = kept
	if _, plan, err = h.config.Apply(ctx, raw(t, only), ""); err != nil || plan.Deleted != 1 || plan.Updated != 0 || plan.Created != 0 {
		t.Fatalf("apply keeping the group assignment: %+v, %v", plan, err)
	}
	var global int
	if err := h.super.QueryRow(context.Background(), `SELECT count(*) FROM profile_assignment a JOIN permission_profile p ON p.id = a.profile_id
		WHERE a.organization_id = $1 AND p.name = 'lab:ops'`, h.org).Scan(&global); err != nil || global != 0 {
		t.Fatalf("the global lab:ops assignment survived (%d, %v)", global, err)
	}
	if n := h.count(t, "SELECT count(*) FROM profile_assignment WHERE organization_id = $1", h.org); n != 1 {
		t.Fatalf("%d assignments, want 1", n)
	}
}

// TestDeclarativeGroupDeletionCascade (review 2 of PDK-008): deleting a device group removes its scoped files, units,
// holds and assignments (ON DELETE CASCADE). Each of them must appear as a deletion in the plan, otherwise the whole
// apply is refused: 409 in_use when their section is left out, 422 invalid_document when the document still lists
// one (unchanged or updated).
func TestDeclarativeGroupDeletionCascade(t *testing.T) {
	h := newConfigHarness(t)
	admin := h.account(t, principal.RoleOrgAdmin, false)
	ctx := principal.With(context.Background(), admin)
	seed := h.export(t, admin)
	*seed.DeviceGroups = append(*seed.DeviceGroups, declarative.DeviceGroup{Name: "lab"})
	*seed.PermissionProfiles = append(*seed.PermissionProfiles, declarative.PermissionProfile{Name: "p", Class: "none",
		Commands: []string{}, RequirePassword: true, TimestampTimeoutMin: 5, Lecture: "once"})
	*seed.ManagedFiles = append(*seed.ManagedFiles,
		declarative.ManagedFile{Path: "/etc/lab.conf", DeviceGroup: strPtr("lab"), Mode: "0644", Owner: "root", Group: "root", Content: "lab"},
		declarative.ManagedFile{Path: "/etc/all.conf", Mode: "0644", Owner: "root", Group: "root", Content: "all"})
	*seed.ManagedUnits = append(*seed.ManagedUnits, declarative.ManagedUnit{Unit: "lab.service", DeviceGroup: strPtr("lab"), Enabled: true, Active: true})
	*seed.PackageHolds = append(*seed.PackageHolds, declarative.PackageHold{Package: "vim", DeviceGroup: strPtr("lab")})
	*seed.ProfileAssignments = append(*seed.ProfileAssignments, declarative.ProfileAssignment{Profile: "p",
		Subject: declarative.Subject{Type: "global"}, DeviceGroup: strPtr("lab")})
	if _, _, err := h.config.Apply(ctx, raw(t, seed), ""); err != nil {
		t.Fatal(err)
	}
	rows := func() int {
		return h.count(t, `SELECT (SELECT count(*) FROM device_group WHERE organization_id = $1) + (SELECT count(*) FROM managed_file WHERE organization_id = $1)
			+ (SELECT count(*) FROM managed_unit WHERE organization_id = $1) + (SELECT count(*) FROM package_hold WHERE organization_id = $1)
			+ (SELECT count(*) FROM profile_assignment WHERE organization_id = $1)`, h.org)
	}
	before := rows()
	withoutLab := func() declarative.Document {
		d := h.export(t, admin)
		*d.DeviceGroups = []declarative.DeviceGroup{}
		return d
	}
	refused := func(name string, d declarative.Document, want *problem.Error, path string) {
		t.Helper()
		got := h.during(t, func() {
			if _, err := h.config.Plan(ctx, raw(t, d)); !errors.Is(err, want) || !strings.Contains(err.Error(), path) {
				t.Errorf("%s dry run = %v, want %s naming %s", name, err, want.Code, path)
			}
			if _, _, err := h.config.Apply(ctx, raw(t, d), ""); !errors.Is(err, want) || !strings.Contains(err.Error(), path) {
				t.Errorf("%s apply = %v, want %s naming %s", name, err, want.Code, path)
			}
		})
		if len(got) != 1 || got[0] != "config.applied:failure:"+want.Code {
			t.Errorf("%s: actions %v", name, got)
		}
		if rows() != before {
			t.Fatalf("%s changed something", name)
		}
	}

	// The scoped sections are left out: their rows would vanish outside the plan.
	omitted := declarative.Document{APIVersion: declarative.APIVersion, Kind: declarative.Kind, DeviceGroups: &[]declarative.DeviceGroup{}}
	refused("sections omitted", omitted, problem.InUse, `device group "lab"`)
	onlyFiles := withoutLab()
	onlyFiles.ManagedUnits, onlyFiles.PackageHolds, onlyFiles.ProfileAssignments = nil, nil, nil
	*onlyFiles.ManagedFiles = []declarative.ManagedFile{{Path: "/etc/all.conf", Mode: "0644", Owner: "root", Group: "root", Content: "all"}}
	refused("unit section omitted", onlyFiles, problem.InUse, `managed unit "lab.service"`)

	// The document still lists an item of the deleted group, unchanged or updated.
	unchanged := withoutLab()
	refused("unchanged file", unchanged, problem.InvalidDocument, "/managed_files/")
	updated := withoutLab()
	for i, f := range *updated.ManagedFiles {
		if f.DeviceGroup != nil {
			(*updated.ManagedFiles)[i].Content = "changed"
		}
	}
	refused("updated file", updated, problem.InvalidDocument, "/managed_files/")

	// The sections are present without the group's items: the plan lists every deletion, and its hash covers them.
	clean := withoutLab()
	*clean.ManagedFiles = []declarative.ManagedFile{{Path: "/etc/all.conf", Mode: "0644", Owner: "root", Group: "root", Content: "all"}}
	*clean.ManagedUnits = []declarative.ManagedUnit{}
	*clean.PackageHolds = []declarative.PackageHold{}
	*clean.ProfileAssignments = []declarative.ProfileAssignment{}
	plan, err := h.config.Plan(ctx, raw(t, clean))
	if err != nil {
		t.Fatal(err)
	}
	if plan.Deleted != 5 || plan.Created != 0 || plan.Updated != 0 {
		t.Fatalf("plan %+v, want the group and its file, unit, hold and assignment deleted", plan)
	}
	if _, applied, err := h.config.Apply(ctx, raw(t, clean), plan.SHA256()); err != nil || applied.SHA256() != plan.SHA256() {
		t.Fatalf("apply with the confirmed plan: %v", err)
	}
	if n := rows(); n != before-5 {
		t.Fatalf("%d rows, want %d", n, before-5)
	}
}

// TestDeclarativeMalformedExpectedPlanIsAudited (review 2 of PDK-008): a malformed expected_plan is one failure event.
func TestDeclarativeMalformedExpectedPlanIsAudited(t *testing.T) {
	h := newConfigHarness(t)
	admin := h.account(t, principal.RoleOrgAdmin, false)
	got := h.during(t, func() {
		if _, _, err := h.config.Apply(principal.With(context.Background(), admin), raw(t, h.export(t, admin)), "XYZ"); !errors.Is(err, problem.InvalidRequest) {
			t.Errorf("Apply = %v", err)
		}
	})
	if len(got) != 1 || got[0] != "config.applied:failure:invalid_request" {
		t.Fatalf("actions %v", got)
	}
}

// TestDeclarativeGroupWithMembers (PDK-014): a device group with member devices is not deleted, also not by a rename
// (delete and create), neither in a dry run nor in an apply; the members must be moved in the portal first.
func TestDeclarativeGroupWithMembers(t *testing.T) {
	h := newConfigHarness(t)
	admin := h.account(t, principal.RoleOrgAdmin, false)
	ctx := principal.With(context.Background(), admin)
	group, dev := uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())
	for _, q := range []struct {
		sql  string
		args []any
	}{
		{"INSERT INTO device_group (id, organization_id, name) VALUES ($1, $2, 'lab')", []any{group, h.org}},
		{"INSERT INTO device (id, organization_id, hostname, state) VALUES ($1, $2, 'h', 'active')", []any{dev, h.org}},
		{"INSERT INTO device_group_member (organization_id, device_group_id, device_id) VALUES ($1, $2, $3)", []any{h.org, group, dev}},
	} {
		if _, err := h.super.Exec(context.Background(), q.sql, q.args...); err != nil {
			t.Fatal(err)
		}
	}
	deleted := h.export(t, admin)
	*deleted.DeviceGroups = []declarative.DeviceGroup{}
	renamed := h.export(t, admin)
	*renamed.DeviceGroups = []declarative.DeviceGroup{{Name: "lab2"}}
	for name, d := range map[string]declarative.Document{"delete": deleted, "rename": renamed} {
		got := h.during(t, func() {
			if _, err := h.config.Plan(ctx, raw(t, d)); !errors.Is(err, problem.InUse) || !strings.Contains(err.Error(), `device group "lab" still has 1 member devices`) {
				t.Errorf("%s dry run = %v", name, err)
			}
			if _, _, err := h.config.Apply(ctx, raw(t, d), ""); !errors.Is(err, problem.InUse) {
				t.Errorf("%s apply = %v", name, err)
			}
		})
		if len(got) != 1 || got[0] != "config.applied:failure:in_use" {
			t.Errorf("%s: actions %v", name, got)
		}
	}
	if n := h.count(t, "SELECT count(*) FROM device_group_member WHERE device_group_id = $1", group); n != 1 {
		t.Fatal("the refused apply removed the membership")
	}
	if n := h.count(t, "SELECT count(*) FROM device_group WHERE organization_id = $1", h.org); n != 1 {
		t.Fatal("the rename created the new group")
	}
}
