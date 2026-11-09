package app_test

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/domain/configrollout"
	"github.com/phischl/paddock-mdm/server/internal/domain/declarative"
	"github.com/phischl/paddock-mdm/server/internal/domain/software"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/problem"
)

// softwareConfig is a document with the three software sections: an APT source, an entry from it and assignments to
// the organization and to device group lab.
func softwareConfig(t *testing.T) declarative.Document {
	t.Helper()
	return declarative.Document{
		APIVersion: declarative.APIVersion, Kind: declarative.Kind,
		DeviceGroups: &[]declarative.DeviceGroup{{Name: "lab"}},
		SoftwareSources: &[]declarative.SoftwareSource{{
			Slug: "vendor", Kind: "apt", Name: " Vendor ", URIs: []string{"https://apt.vendor.example/"}, Suites: []string{"stable"},
			Components: []string{"main"}, Architectures: []string{}, SigningKey: sourceKey(t, "ed25519.asc"),
			Fingerprint: strings.ToLower(sourceEd25519FP[:20]) + " " + strings.ToLower(sourceEd25519FP[20:]),
		}},
		SoftwareCatalog: &[]declarative.SoftwareCatalogEntry{{
			Name: "Browser", Category: "web", Source: strPtr("vendor"),
			Packages: []software.PackageRef{{Distribution: "ubuntu", Release: "*", Architecture: "*", Package: "browser"}},
		}},
		SoftwareAssignments: &[]declarative.SoftwareAssignment{
			{Entry: "Browser", Target: declarative.SoftwareTarget{Type: "organization"}, Intent: "required"},
			{Entry: "Browser", Target: declarative.SoftwareTarget{Type: "device_group", Name: "lab"}, Intent: "hold", Reason: "pinned for the lab"},
		},
	}
}

// TestDeclarativeSoftwareRoundTrip (plan M13c decision 1): an administrator with a step-up applies the three sections,
// the export carries them with the source's key and fingerprint in their stored form, and applying the export or the
// hand-written document again is an empty plan.
func TestDeclarativeSoftwareRoundTrip(t *testing.T) {
	h := newConfigHarness(t)
	ctx := principal.With(context.Background(), h.account(t, principal.RoleOrgAdmin, true))
	doc := softwareConfig(t)
	id, plan, err := h.config.Apply(ctx, raw(t, doc), "")
	if err != nil {
		t.Fatal(err)
	}
	if id == uuid.Nil || plan.Created != 5 || !slices.Equal(plan.RequiresStepUp, []string{declarative.SectionSoftwareSources}) {
		t.Fatalf("plan %+v", plan)
	}
	got := h.export(t, h.account(t, principal.RoleOrgAuditor, false))
	src := (*got.SoftwareSources)[0]
	if src.Name != "Vendor" || src.Fingerprint != sourceEd25519FP || !strings.HasPrefix(src.SigningKey, "-----BEGIN PGP PUBLIC KEY BLOCK-----") ||
		len(*got.SoftwareCatalog) != 1 || *(*got.SoftwareCatalog)[0].Source != "vendor" || len(*got.SoftwareAssignments) != 2 {
		t.Fatalf("export %+v %+v %+v", *got.SoftwareSources, *got.SoftwareCatalog, *got.SoftwareAssignments)
	}
	for _, a := range *got.SoftwareAssignments {
		if a.UpdateRule != "latest" {
			t.Fatalf("assignment %+v", a)
		}
	}
	for name, d := range map[string]declarative.Document{"export": got, "document": doc} {
		p, err := h.config.Plan(ctx, raw(t, d))
		if err != nil || len(p.Changes) != 0 {
			t.Fatalf("%s again: %+v, %v", name, p.Changes, err)
		}
	}

	wrong := softwareConfig(t)
	(*wrong.SoftwareSources)[0].Name = "Vendor 2"
	(*wrong.SoftwareSources)[0].Fingerprint = sourceRSA3072FP
	if _, _, err := h.config.Apply(ctx, raw(t, wrong), ""); !errors.Is(err, problem.FingerprintMismatch) ||
		!strings.HasPrefix(problem.From(err).Detail, "/software_sources/0: ") {
		t.Fatalf("fingerprint mismatch = %v", err)
	}
	unknown := softwareConfig(t)
	(*unknown.SoftwareAssignments)[0].Entry = "Editor"
	if _, _, err := h.config.Apply(ctx, raw(t, unknown), ""); !errors.Is(err, problem.InvalidRequest) {
		t.Fatalf("assignment of an unknown entry = %v", err)
	}
	// Deleting the entry while it has assignments is refused (A10-12).
	noEntry := softwareConfig(t)
	noEntry.SoftwareAssignments, noEntry.SoftwareCatalog = nil, &[]declarative.SoftwareCatalogEntry{}
	if _, _, err := h.config.Apply(ctx, raw(t, noEntry), ""); !errors.Is(err, problem.InUse) {
		t.Fatalf("entry deletion with assignments left = %v", err)
	}
	// Deleting the group without the section of its assignment is refused like its managed files.
	noGroup := h.export(t, h.account(t, principal.RoleOrgAdmin, false))
	noGroup.DeviceGroups = &[]declarative.DeviceGroup{}
	noGroup.SoftwareAssignments, noGroup.SoftwareCatalog, noGroup.SoftwareSources = nil, nil, nil
	if _, _, err := h.config.Apply(ctx, raw(t, noGroup), ""); !errors.Is(err, problem.InUse) {
		t.Fatalf("group deletion with a software assignment = %v", err)
	}
}

// TestDeclarativeSoftwareEntryUpdateFailureIsReported: a failing update of a catalog entry fails the apply and changes
// nothing. A category with trailing blanks passes validation (it is trimmed for the length check) but exceeds the
// column's limit as stored, so the UPDATE itself is refused.
func TestDeclarativeSoftwareEntryUpdateFailureIsReported(t *testing.T) {
	h := newConfigHarness(t)
	ctx := principal.With(context.Background(), h.account(t, principal.RoleOrgAdmin, true))
	doc := softwareConfig(t)
	if _, _, err := h.config.Apply(ctx, raw(t, doc), ""); err != nil {
		t.Fatal(err)
	}
	(*doc.SoftwareCatalog)[0].Category = strings.Repeat("c", software.MaxCategoryLength) + " "
	if _, _, err := h.config.Apply(ctx, raw(t, doc), ""); err == nil || !strings.Contains(err.Error(), "category") {
		t.Fatalf("apply with a refused entry update = %v, want the update's own constraint error", err)
	}
	got := h.export(t, h.account(t, principal.RoleOrgAdmin, false))
	if c := (*got.SoftwareCatalog)[0].Category; c != "web" {
		t.Fatalf("category after the refused update = %q", c)
	}
}

// TestDeclarativeSoftwareSourceStepUp (plan M13c decision 2, ADR 0034 decision 3): a plan with a source change needs
// an organization administrator with a fresh step-up for the whole apply. An API token's apply is refused and applies
// nothing, its dry run names the section; without a source change the token applies.
func TestDeclarativeSoftwareSourceStepUp(t *testing.T) {
	h := newConfigHarness(t)
	admin := h.account(t, principal.RoleOrgAdmin, false)
	steppedUp := h.account(t, principal.RoleOrgAdmin, true)
	operator := h.account(t, principal.RoleOrgOperator, true)
	token := h.create(t, steppedUp, "ci", principal.RoleOrgAdmin)
	tp, _, err := h.tokens.Authenticate(context.Background(), token.Secret, "")
	if err != nil {
		t.Fatal(err)
	}
	ctx := func(p principal.Principal) context.Context { return principal.With(context.Background(), p) }
	doc := softwareConfig(t)

	plan, err := h.config.Plan(ctx(tp), raw(t, doc))
	if err != nil || !slices.Equal(plan.RequiresStepUp, []string{declarative.SectionSoftwareSources}) {
		t.Fatalf("token dry run = %+v, %v", plan.RequiresStepUp, err)
	}
	for name, c := range map[string]struct {
		p    principal.Principal
		want *problem.Error
	}{
		"api token":          {tp, problem.StepUpRequired},
		"admin without step": {admin, problem.StepUpRequired},
		"operator":           {operator, problem.Forbidden},
	} {
		if _, _, err := h.config.Apply(ctx(c.p), raw(t, doc), plan.SHA256()); !errors.Is(err, c.want) {
			t.Fatalf("%s apply = %v, want %s", name, err, c.want.Code)
		}
	}
	if n := h.count(t, "SELECT count(*) FROM device_group WHERE organization_id = $1", h.org); n != 0 {
		t.Fatalf("a refused apply left %d device groups", n)
	}
	if _, _, err := h.config.Apply(ctx(steppedUp), raw(t, doc), plan.SHA256()); err != nil {
		t.Fatal(err)
	}
	var stepUp bool
	if err := h.super.QueryRow(context.Background(), "SELECT (actor->>'step_up')::boolean FROM change_set WHERE organization_id = $1 ORDER BY id DESC LIMIT 1",
		h.org).Scan(&stepUp); err != nil || !stepUp {
		t.Fatalf("change set actor step_up = %v, %v", stepUp, err)
	}

	// The two-step: CI changes everything but sources with its token.
	next := h.export(t, admin)
	(*next.SoftwareAssignments)[0].Intent = "available"
	plan, err = h.config.Plan(ctx(tp), raw(t, next))
	if err != nil || plan.RequiresStepUp != nil || plan.Updated != 1 {
		t.Fatalf("token dry run without a source change = %+v, %v", plan, err)
	}
	if _, _, err := h.config.Apply(ctx(tp), raw(t, next), plan.SHA256()); err != nil {
		t.Fatalf("token apply without a source change = %v", err)
	}
}

// softwareUseCases are the per-resource software use cases on the harness pool.
func softwareUseCases(h writeHarness) (*app.SoftwareSources, *app.SoftwareCatalog) {
	return app.NewSoftwareSources(h.runner, h.pool), app.NewSoftwareCatalog(h.runner, h.pool)
}

// TestSoftwareWritesRecordChangeSets (plan M13c decision 3): every per-resource write of a source, an entry or an
// assignment records a change set with the before item, and the revert of an assignment change restores the row.
func TestSoftwareWritesRecordChangeSets(t *testing.T) {
	h := newWriteHarness(t)
	sources, catalog := softwareUseCases(h)
	admin := principal.With(context.Background(), h.account(t, principal.RoleOrgAdmin, true))
	src, err := sources.Create(admin, software.SourceInput{Slug: "vendor", Name: "Vendor", URIs: []string{"https://apt.vendor.example/"},
		Suites: []string{"stable"}, Components: []string{"main"}, SigningKey: sourceKey(t, "ed25519.asc"), Fingerprint: sourceEd25519FP})
	if err != nil {
		t.Fatal(err)
	}
	if cs := h.lastChangeSet(t); len(cs.plan.Changes) != 1 || cs.plan.Changes[0].Section != declarative.SectionSoftwareSources ||
		!slices.Equal(cs.plan.RequiresStepUp, []string{declarative.SectionSoftwareSources}) {
		t.Fatalf("source change set %+v", cs.plan)
	}
	entry, err := catalog.Create(admin, app.EntryInput{Name: "Browser", SourceID: &src.ID,
		Packages: []software.PackageRef{{Distribution: "ubuntu", Release: "*", Architecture: "*", Package: "browser"}}})
	if err != nil {
		t.Fatal(err)
	}
	if cs := h.lastChangeSet(t); len(cs.plan.Changes) != 1 || cs.plan.Changes[0].Section != declarative.SectionSoftwareCatalog {
		t.Fatalf("entry change set %+v", cs.plan)
	}
	a, err := catalog.CreateAssignment(admin, app.AssignmentInput{CatalogEntryID: &entry.ID, Intent: "required"})
	if err != nil {
		t.Fatal(err)
	}
	key := `[null,"Browser","organization",null]`
	if cs := h.lastChangeSet(t); len(cs.plan.Changes) != 1 || cs.plan.Changes[0].Key != key || len(cs.before) != 0 {
		t.Fatalf("assignment change set %+v", cs.plan)
	}
	if _, err := catalog.UpdateAssignment(admin, a.ID, app.AssignmentInput{Intent: "forbid", Reason: "banned"}); err != nil {
		t.Fatal(err)
	}
	cs := h.lastChangeSet(t)
	var before struct {
		ID     string `json:"id"`
		Intent string `json:"intent"`
	}
	if err := json.Unmarshal(cs.before[declarative.SectionSoftwareAssignments][key], &before); err != nil ||
		before.Intent != "required" || before.ID != a.ID.String() {
		t.Fatalf("before %s, %v", cs.before[declarative.SectionSoftwareAssignments][key], err)
	}
	plan, err := revertPlan(admin, h, cs.id)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := h.config.Revert(admin, cs.id, plan.SHA256(), app.RevertOptions{}); err != nil {
		t.Fatal(err)
	}
	var intent, reason string
	if err := h.super.QueryRow(context.Background(), "SELECT intent, reason FROM software_assignment WHERE catalog_entry_id = $1",
		entry.ID).Scan(&intent, &reason); err != nil || intent != "required" || reason != "" {
		t.Fatalf("after the revert: %s %q, %v", intent, reason, err)
	}
	n := h.changeSets(t)
	if err := catalog.DeleteAssignment(admin, a.ID); err != nil {
		t.Fatal(err)
	}
	if err := catalog.Delete(admin, entry.ID); err != nil {
		t.Fatal(err)
	}
	if h.changeSets(t) != n+2 {
		t.Fatal("assignment and entry deletion recorded no change sets")
	}
	if cs := h.lastChangeSet(t); cs.plan.Deleted != 1 || cs.plan.Changes[0].Section != declarative.SectionSoftwareCatalog {
		t.Fatalf("entry deletion plan %+v, want the entry alone", cs.plan)
	}
}

// TestSoftwareEntryDeletionNeedsNoAssignments (plan M13c amendment 2026-11-09, A10-12): an entry that still has
// assignments cannot be deleted, per resource or by a document, even one that deletes the assignments too; the 409
// names them. Their removal is staged like every assignment change; once the rollout is done the entry's deletion is a
// change of the catalog alone, which no device sees.
func TestSoftwareEntryDeletionNeedsNoAssignments(t *testing.T) {
	h := newRolloutHarness(t)
	_, catalog := softwareUseCases(h.writeHarness)
	account := h.account(t, principal.RoleOrgAdmin, true)
	admin := principal.With(context.Background(), account)
	entry, err := catalog.Create(admin, app.EntryInput{Name: "Browser",
		Packages: []software.PackageRef{{Distribution: "ubuntu", Release: "*", Architecture: "*", Package: "browser"}}})
	if err != nil {
		t.Fatal(err)
	}
	group := h.group(t, h.org)
	for _, in := range []app.AssignmentInput{{CatalogEntryID: &entry.ID, Intent: "required"},
		{CatalogEntryID: &entry.ID, DeviceGroupID: &group, Intent: "forbid"}} {
		if _, err := catalog.CreateAssignment(admin, in); err != nil {
			t.Fatal(err)
		}
	}
	enableRollouts(t, h.writeHarness, []int{50, 100}, nil)
	assignments := func() int {
		return h.count(t, "SELECT count(*) FROM software_assignment WHERE catalog_entry_id = $1", entry.ID)
	}

	named := `catalog entry "Browser" still has 2 assignments (device group "g-` + group.String() + `", organization)`
	err = catalog.Delete(admin, entry.ID)
	if !errors.Is(err, problem.InUse) || !strings.HasPrefix(problem.From(err).Detail, named+"; remove them first") {
		t.Fatalf("per-resource deletion with assignments = %v", err)
	}
	if ev := h.lastEvent(t); ev["name"] != "Browser" || ev["assignment_count"] != float64(2) {
		t.Fatalf("refused deletion event %+v", ev)
	}
	doc := h.export(t, account)
	*doc.SoftwareCatalog, *doc.SoftwareAssignments = []declarative.SoftwareCatalogEntry{}, []declarative.SoftwareAssignment{}
	prefix := "/" + declarative.SectionSoftwareCatalog + ` (delete ["Browser"]): ` + named
	if _, err := h.config.Plan(admin, raw(t, doc)); !errors.Is(err, problem.InUse) || !strings.HasPrefix(problem.From(err).Detail, prefix) {
		t.Fatalf("plan of a document deleting the entry and its assignments = %v", err)
	}
	if _, _, err := h.config.Apply(admin, raw(t, doc), ""); !errors.Is(err, problem.InUse) || !strings.HasPrefix(problem.From(err).Detail, prefix) {
		t.Fatalf("document deleting the entry and its assignments = %v", err)
	}
	if n := assignments(); n != 2 || h.rollouts(t) != 0 {
		t.Fatalf("refusals left %d assignments and %d rollouts", n, h.rollouts(t))
	}

	doc = h.export(t, account)
	*doc.SoftwareAssignments = []declarative.SoftwareAssignment{}
	if _, _, err := h.config.Apply(admin, raw(t, doc), ""); err != nil {
		t.Fatal(err)
	}
	r := h.rollout(t, h.lastChangeSet(t).id)
	if !r.present || r.status != configrollout.StatusRunning || assignments() != 0 {
		t.Fatalf("removal of the assignments not staged: %+v", r)
	}
	if err := catalog.Delete(admin, entry.ID); !errors.Is(err, problem.RolloutConflict) {
		t.Fatalf("deletion while the removal rolls out = %v", err)
	}
	if _, err := h.api.Complete(h.admin, r.id); err != nil {
		t.Fatal(err)
	}
	if err := catalog.Delete(admin, entry.ID); err != nil {
		t.Fatal(err)
	}
	cs := h.lastChangeSet(t)
	if len(cs.plan.Changes) != 1 || cs.plan.Changes[0].Section != declarative.SectionSoftwareCatalog ||
		len(configrollout.StagedKeys(cs.plan)) != 0 || h.rollouts(t) != 1 {
		t.Fatalf("entry deletion after the removal %+v, %d rollouts", cs.plan, h.rollouts(t))
	}
}

// TestSoftwareAssignmentRollout (ADR 0033 amendment 2026-11-05): with rollouts enabled an assignment change is staged,
// entries and sources stay immediate, the staged entry is a resource of the rollout, a failed software status of it on
// devices of the wave halts the rollout, and the revert ends the rollout and restores the assignments.
func TestSoftwareAssignmentRollout(t *testing.T) {
	h := newRolloutHarness(t)
	sources, catalog := softwareUseCases(h.writeHarness)
	admin := principal.With(context.Background(), h.account(t, principal.RoleOrgAdmin, true))
	enableRollouts(t, h.writeHarness, []int{50, 100}, nil)
	src, err := sources.Create(admin, software.SourceInput{Slug: "vendor", Name: "Vendor", URIs: []string{"https://apt.vendor.example/"},
		Suites: []string{"stable"}, Components: []string{"main"}, SigningKey: sourceKey(t, "ed25519.asc"), Fingerprint: sourceEd25519FP})
	if err != nil {
		t.Fatal(err)
	}
	entry, err := catalog.Create(admin, app.EntryInput{Name: "Browser", SourceID: &src.ID,
		Packages: []software.PackageRef{{Distribution: "ubuntu", Release: "*", Architecture: "*", Package: "browser"}}})
	if err != nil {
		t.Fatal(err)
	}
	if n := h.rollouts(t); n != 0 {
		t.Fatalf("source and entry started %d rollouts", n)
	}
	a, err := catalog.CreateAssignment(admin, app.AssignmentInput{CatalogEntryID: &entry.ID, Intent: "required"})
	if err != nil {
		t.Fatal(err)
	}
	cs := h.lastChangeSet(t)
	r := h.rollout(t, cs.id)
	if !r.present || r.status != configrollout.StatusRunning || h.lastEvent(t)["rollout"] != app.RolloutStaged {
		t.Fatalf("rollout %+v", r)
	}
	if got := stagedAssignmentRows(t, h, r.id); len(got) != 1 || got[`[null,"Browser","organization",null]`] !=
		(configrollout.StagedAssignment{ID: a.ID, Entry: entry.ID}) {
		t.Fatalf("staged assignment rows of a creation %+v", got)
	}
	// The open rollout's rules: the staged key conflicts, a rename of its entry too, another assignment is running.
	if _, err := catalog.UpdateAssignment(admin, a.ID, app.AssignmentInput{Intent: "forbid"}); !errors.Is(err, problem.RolloutConflict) {
		t.Fatalf("update of the staged assignment = %v", err)
	}
	if _, err := catalog.Update(admin, entry.ID, app.EntryInput{Name: "Web browser", SourceID: &src.ID,
		Packages: []software.PackageRef{{Distribution: "ubuntu", Release: "*", Architecture: "*", Package: "browser"}}}); !errors.Is(err, problem.RolloutConflict) {
		t.Fatalf("rename of the staged entry = %v", err)
	}
	group := h.group(t, h.org)
	if _, err := catalog.CreateAssignment(admin, app.AssignmentInput{CatalogEntryID: &entry.ID, DeviceGroupID: &group, Intent: "hold"}); !errors.Is(err, problem.RolloutRunning) {
		t.Fatalf("second assignment = %v", err)
	}
	detail, err := h.api.Get(h.admin, r.id)
	if err != nil || !slices.Equal(detail.StagedResourceIDs, []string{app.SoftwareResourcePrefix + entry.ID.String()}) {
		t.Fatalf("staged resources %v, %v", detail.StagedResourceIDs, err)
	}

	now := time.Now()
	failed := func(d uuid.UUID, at time.Time) {
		h.exec(t, `INSERT INTO device_software_status (device_id, organization_id, catalog_entry_id, package, intent, state, reported_at)
			VALUES ($1, $2, $3, 'browser', 'required', 'failed', $4)`, d, h.org, entry.ID, at)
	}
	x, y, z := h.device(t, r.id, 50, true), h.device(t, r.id, 50, true), h.device(t, r.id, 50, true)
	for _, d := range []uuid.UUID{x, y, z} {
		h.report(t, d, r.id, 1, "applied", "enforce", "", now)
	}
	failed(x, now)
	failed(y, now.Add(-2*time.Hour)) // before the rollout started: does not count
	if err := h.worker.Evaluate(h.system, now); err != nil {
		t.Fatal(err)
	}
	if got := h.rollout(t, cs.id); got.status != configrollout.StatusRunning {
		t.Fatalf("halted with one counted failure: %+v", got)
	}
	failed(z, now)
	if err := h.worker.Evaluate(h.system, now); err != nil {
		t.Fatal(err)
	}
	if got := h.rollout(t, cs.id); got.status != configrollout.StatusHalted {
		t.Fatalf("not halted on two failed software statuses: %+v", got)
	}
	devices, err := h.api.ListDevices(h.admin, r.id, app.ConfigRolloutDeviceQuery{Page: app.ListPage{Limit: 100}})
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range devices.Items {
		want := d.DeviceID == x || d.DeviceID == z
		if got := slices.Contains(d.FailedResourceIDs, app.SoftwareResourcePrefix+entry.ID.String()); got != want {
			t.Fatalf("device %s failed resources %v", d.Hostname, d.FailedResourceIDs)
		}
	}

	plan, err := revertPlan(admin, h.writeHarness, cs.id)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := h.config.Revert(admin, cs.id, plan.SHA256(), app.RevertOptions{}); err != nil {
		t.Fatal(err)
	}
	if got := h.rollout(t, cs.id); got.status != configrollout.StatusReverted {
		t.Fatalf("rollout after the revert %+v", got)
	}
	if n := h.count(t, "SELECT count(*) FROM software_assignment WHERE organization_id = $1", h.org); n != 0 {
		t.Fatalf("%d assignments after the revert of their creation", n)
	}
}

// TestSoftwareStagedDeletionProtectsEntry: a staged assignment deletion has no live row, yet its entry may be neither
// renamed nor deleted while the rollout is open, or the deletion would leave the overlay and reach every device at once.
// A change of the entry that keeps its name stays immediate.
func TestSoftwareStagedDeletionProtectsEntry(t *testing.T) {
	h := newRolloutHarness(t)
	sources, catalog := softwareUseCases(h.writeHarness)
	admin := principal.With(context.Background(), h.account(t, principal.RoleOrgAdmin, true))
	src, err := sources.Create(admin, software.SourceInput{Slug: "vendor", Name: "Vendor", URIs: []string{"https://apt.vendor.example/"},
		Suites: []string{"stable"}, Components: []string{"main"}, SigningKey: sourceKey(t, "ed25519.asc"), Fingerprint: sourceEd25519FP})
	if err != nil {
		t.Fatal(err)
	}
	packages := []software.PackageRef{{Distribution: "ubuntu", Release: "*", Architecture: "*", Package: "browser"}}
	entry, err := catalog.Create(admin, app.EntryInput{Name: "Browser", SourceID: &src.ID, Packages: packages})
	if err != nil {
		t.Fatal(err)
	}
	a, err := catalog.CreateAssignment(admin, app.AssignmentInput{CatalogEntryID: &entry.ID, Intent: "required"})
	if err != nil {
		t.Fatal(err)
	}
	enableRollouts(t, h.writeHarness, []int{50, 100}, nil)
	if err := catalog.DeleteAssignment(admin, a.ID); err != nil {
		t.Fatal(err)
	}
	r := h.rollout(t, h.lastChangeSet(t).id)
	if !r.present || r.status != configrollout.StatusRunning {
		t.Fatalf("assignment deletion not staged: %+v", r)
	}
	if got := stagedAssignmentRows(t, h, r.id); len(got) != 1 || got[`[null,"Browser","organization",null]`] !=
		(configrollout.StagedAssignment{ID: a.ID, Entry: entry.ID}) {
		t.Fatalf("staged assignment rows of a deletion %+v", got)
	}
	if _, err := catalog.Update(admin, entry.ID, app.EntryInput{Name: "Web browser", SourceID: &src.ID, Packages: packages}); !errors.Is(err, problem.RolloutConflict) {
		t.Fatalf("rename of the entry of a staged deletion = %v", err)
	}
	if err := catalog.Delete(admin, entry.ID); !errors.Is(err, problem.RolloutConflict) {
		t.Fatalf("deletion of the entry of a staged deletion = %v", err)
	}
	if _, err := catalog.Update(admin, entry.ID, app.EntryInput{Name: "Browser", Description: "The browser", SourceID: &src.ID, Packages: packages}); err != nil {
		t.Fatalf("update that keeps the entry's name = %v", err)
	}
	detail, err := h.api.Get(h.admin, r.id)
	if err != nil || !slices.Equal(detail.StagedResourceIDs, []string{app.SoftwareResourcePrefix + entry.ID.String()}) {
		t.Fatalf("staged resources %v, %v", detail.StagedResourceIDs, err)
	}
}

// TestSoftwareRevertOfOpenRolloutDeletesEntry (A10-13): an open rollout whose change set created an entry and its
// assignment can always be reverted. Outside the revert the entry's deletion is still refused while it has an
// assignment; the revert deletes the assignment first, then the entry, and ends the rollout.
func TestSoftwareRevertOfOpenRolloutDeletesEntry(t *testing.T) {
	h := newRolloutHarness(t)
	_, catalog := softwareUseCases(h.writeHarness)
	account := h.account(t, principal.RoleOrgAdmin, true)
	admin := principal.With(context.Background(), account)
	enableRollouts(t, h.writeHarness, []int{50, 100}, nil)
	doc := h.export(t, account)
	doc.SoftwareCatalog = &[]declarative.SoftwareCatalogEntry{{Name: "Editor",
		Packages: []software.PackageRef{{Distribution: "ubuntu", Release: "*", Architecture: "*", Package: "editor"}}}}
	doc.SoftwareAssignments = &[]declarative.SoftwareAssignment{
		{Entry: "Editor", Target: declarative.SoftwareTarget{Type: "organization"}, Intent: "required"}}
	if _, _, err := h.config.Apply(admin, raw(t, doc), ""); err != nil {
		t.Fatal(err)
	}
	cs := h.lastChangeSet(t)
	r := h.rollout(t, cs.id)
	if !r.present || r.status != configrollout.StatusRunning {
		t.Fatalf("assignment of the new entry not staged: %+v", r)
	}
	h.exec(t, "UPDATE config_rollout SET status = 'halted' WHERE id = $1", r.id)
	rows := func(table string) int {
		return h.count(t, "SELECT count(*) FROM "+table+" WHERE organization_id = $1", h.org)
	}
	var entry uuid.UUID
	if err := h.super.QueryRow(context.Background(), "SELECT id FROM software_catalog_entry WHERE organization_id = $1", h.org).Scan(&entry); err != nil {
		t.Fatal(err)
	}
	if err := catalog.Delete(admin, entry); !errors.Is(err, problem.InUse) {
		t.Fatalf("deletion of the entry outside the revert = %v", err)
	}

	plan, err := revertPlan(admin, h.writeHarness, cs.id)
	if err != nil {
		t.Fatalf("revert dry run of the halted rollout = %v", err)
	}
	if _, _, err := h.config.Revert(admin, cs.id, plan.SHA256(), app.RevertOptions{}); err != nil {
		t.Fatalf("revert of the halted rollout = %v", err)
	}
	if got := h.rollout(t, cs.id); got.status != configrollout.StatusReverted {
		t.Fatalf("rollout after the revert %+v", got)
	}
	if e, a := rows("software_catalog_entry"), rows("software_assignment"); e != 0 || a != 0 {
		t.Fatalf("revert left %d entries and %d assignments", e, a)
	}
}

// TestSoftwareRevertOutsideOpenRolloutKeepsGuard (A10-13): only the revert of the open rollout's own change set may
// delete an assigned entry. A revert with no open rollout, or of a different change set while another rollout is
// open, keeps the in-use guard, so the revert dry run is refused as in use and nothing is deleted. Revert itself is not asserted: its plan hash is
// checked before the guard and a refused dry run yields no valid hash.
func TestSoftwareRevertOutsideOpenRolloutKeepsGuard(t *testing.T) {
	apply := func(t *testing.T, h rolloutHarness) (context.Context, storedChange) {
		t.Helper()
		account := h.account(t, principal.RoleOrgAdmin, true)
		admin := principal.With(context.Background(), account)
		doc := h.export(t, account)
		doc.SoftwareCatalog = &[]declarative.SoftwareCatalogEntry{{Name: "Editor",
			Packages: []software.PackageRef{{Distribution: "ubuntu", Release: "*", Architecture: "*", Package: "editor"}}}}
		doc.SoftwareAssignments = &[]declarative.SoftwareAssignment{
			{Entry: "Editor", Target: declarative.SoftwareTarget{Type: "organization"}, Intent: "required"}}
		if _, _, err := h.config.Apply(admin, raw(t, doc), ""); err != nil {
			t.Fatal(err)
		}
		return admin, h.lastChangeSet(t)
	}
	cases := []struct {
		name string
		open func(t *testing.T, h rolloutHarness)
	}{
		{"no open rollout", func(*testing.T, rolloutHarness) {}},
		{"other rollout open", func(t *testing.T, h rolloutHarness) {
			enableRollouts(t, h.writeHarness, []int{50, 100}, nil)
			h.stage(t, "/etc/acme/r3.conf")
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newRolloutHarness(t)
			admin, cs := apply(t, h)
			tc.open(t, h)
			if _, err := revertPlan(admin, h.writeHarness, cs.id); !errors.Is(err, problem.InUse) {
				t.Fatalf("revert dry run = %v", err)
			}
			for _, table := range []string{"software_catalog_entry", "software_assignment"} {
				if n := h.count(t, "SELECT count(*) FROM "+table+" WHERE organization_id = $1", h.org); n != 1 {
					t.Fatalf("%s rows after the refused revert = %d", table, n)
				}
			}
		})
	}
}

// TestSoftwareEntryRenameNotStaged: renaming an assigned entry keeps its assignment rows, so neither the old-name nor
// the new-name keys start a rollout (plan M13c decision 3).
func TestSoftwareEntryRenameNotStaged(t *testing.T) {
	h := newRolloutHarness(t)
	_, catalog := softwareUseCases(h.writeHarness)
	admin := principal.With(context.Background(), h.account(t, principal.RoleOrgAdmin, true))
	packages := []software.PackageRef{{Distribution: "ubuntu", Release: "*", Architecture: "*", Package: "editor"}}
	entry, err := catalog.Create(admin, app.EntryInput{Name: "Editor", Packages: packages})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := catalog.CreateAssignment(admin, app.AssignmentInput{CatalogEntryID: &entry.ID, Intent: "required"}); err != nil {
		t.Fatal(err)
	}
	enableRollouts(t, h.writeHarness, []int{50, 100}, nil)
	if _, err := catalog.Update(admin, entry.ID, app.EntryInput{Name: "Text editor", Packages: packages}); err != nil {
		t.Fatal(err)
	}
	if n, mode := h.rollouts(t), h.lastEvent(t)["rollout"]; n != 0 || mode != app.RolloutImmediate {
		t.Fatalf("rename of an assigned entry started %d rollouts, mode %v", n, mode)
	}
}

// stagedAssignmentRows reads the rows rollout recorded for its staged software assignment keys.
func stagedAssignmentRows(t *testing.T, h rolloutHarness, rollout uuid.UUID) map[string]configrollout.StagedAssignment {
	t.Helper()
	var raw []byte
	if err := h.super.QueryRow(context.Background(), "SELECT staged_assignments FROM config_rollout WHERE id = $1", rollout).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var out map[string]configrollout.StagedAssignment
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// TestSoftwareStagedUserAssignmentRow: the rollout of a user-targeted assignment records the user's ID, which the
// compiler matches instead of the username identity sync may change.
func TestSoftwareStagedUserAssignmentRow(t *testing.T) {
	h := newRolloutHarness(t)
	_, catalog := softwareUseCases(h.writeHarness)
	admin := principal.With(context.Background(), h.account(t, principal.RoleOrgAdmin, true))
	entry, err := catalog.Create(admin, app.EntryInput{Name: "Browser",
		Packages: []software.PackageRef{{Distribution: "ubuntu", Release: "*", Architecture: "*", Package: "browser"}}})
	if err != nil {
		t.Fatal(err)
	}
	user := uuid.Must(uuid.NewV7())
	h.exec(t, "INSERT INTO app_user (id, organization_id, authentik_pk, username, source) VALUES ($1, $2, 'pk-erin', 'erin@c.test', 'synced')", user, h.org)
	enableRollouts(t, h.writeHarness, []int{50, 100}, nil)
	a, err := catalog.CreateAssignment(admin, app.AssignmentInput{CatalogEntryID: &entry.ID, UserID: &user, Intent: "required"})
	if err != nil {
		t.Fatal(err)
	}
	r := h.rollout(t, h.lastChangeSet(t).id)
	if got := stagedAssignmentRows(t, h, r.id); len(got) != 1 || got[`[null,"Browser","user","erin@c.test"]`].ID != a.ID ||
		got[`[null,"Browser","user","erin@c.test"]`].Target == nil || *got[`[null,"Browser","user","erin@c.test"]`].Target != user {
		t.Fatalf("staged assignment rows %+v", got)
	}
}
