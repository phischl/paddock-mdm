package app_test

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/domain/declarative"
	"github.com/phischl/paddock-mdm/server/internal/domain/devicegroup"
	"github.com/phischl/paddock-mdm/server/internal/domain/software"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/problem"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/pgtest"
)

// TestMaintenanceWindows (PDK-809, plan M13c decision 4): write roles set and remove a device group's window with one
// audit event per attempt carrying every field, the ranges and the timezone are checked, a group without a window and
// another organization's group are not found.
func TestMaintenanceWindows(t *testing.T) {
	h := newPrivilegesHarness(t)
	pool, err := db.NewOrgPool(context.Background(), pgtest.SharedPaddock(t).API, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	groups := app.NewDeviceGroups(h.runner, pool)
	operator := h.account(t, principal.RoleOrgOperator, false)
	auditor := h.account(t, principal.RoleOrgAuditor, false)
	ctx := func(p principal.Principal) context.Context { return principal.With(context.Background(), p) }
	group := uuid.Must(uuid.NewV7())
	if _, err := h.super.Exec(context.Background(), `INSERT INTO device_group (id, organization_id, name) VALUES ($1, $2, 'night')`, group, h.org); err != nil {
		t.Fatal(err)
	}
	night := devicegroup.Window{Days: []int{5, 1, 2, 3, 4}, StartMinute: 1320, DurationMinutes: 180, Timezone: "Europe/Berlin"}

	got := h.during(t, func() {
		if _, err := groups.SetMaintenanceWindow(ctx(auditor), group, night); !errors.Is(err, problem.Forbidden) {
			t.Errorf("auditor set = %v", err)
		}
		bad := night
		bad.Timezone = "Mars/Olympus"
		if _, err := groups.SetMaintenanceWindow(ctx(operator), group, bad); !errors.Is(err, problem.InvalidRequest) {
			t.Errorf("unknown timezone = %v", err)
		}
		bad = night
		bad.DurationMinutes = 20
		if _, err := groups.SetMaintenanceWindow(ctx(operator), group, bad); !errors.Is(err, problem.InvalidRequest) {
			t.Errorf("short window = %v", err)
		}
		if err := groups.DeleteMaintenanceWindow(ctx(operator), group); !errors.Is(err, problem.NotFound) {
			t.Errorf("delete without a window = %v", err)
		}
		if _, err := groups.MaintenanceWindow(ctx(auditor), group); !errors.Is(err, problem.NotFound) {
			t.Errorf("get without a window = %v", err)
		}
	})
	want := []string{"device_group.maintenance_window_changed:denied:forbidden", "device_group.maintenance_window_changed:failure:invalid_request",
		"device_group.maintenance_window_changed:failure:invalid_request", "device_group.maintenance_window_removed:failure:not_found"}
	if !slices.Equal(got, want) {
		t.Fatalf("actions %v", got)
	}

	row, err := groups.SetMaintenanceWindow(ctx(operator), group, night)
	if err != nil {
		t.Fatalf("set = %v", err)
	}
	if w := app.WindowOf(row); !slices.Equal(w.Days, []int{1, 2, 3, 4, 5}) || w.StartMinute != 1320 || w.Timezone != "Europe/Berlin" {
		t.Fatalf("stored window %+v", w)
	}
	ev := h.lastEvent(t)
	if ev.Params["name"] != "night" || ev.Params["timezone"] != "Europe/Berlin" || ev.Params["duration_minutes"] != float64(180) ||
		ev.Params["old_timezone"] != nil || ev.Params["change_set_id"] == nil {
		t.Fatalf("changed event %+v", ev.Params)
	}
	weekend := devicegroup.Window{Days: []int{6, 7}, StartMinute: 0, DurationMinutes: 1440, Timezone: "UTC"}
	if _, err := groups.SetMaintenanceWindow(ctx(operator), group, weekend); err != nil {
		t.Fatalf("replace = %v", err)
	}
	if ev := h.lastEvent(t); ev.Params["timezone"] != "UTC" || ev.Params["old_timezone"] != "Europe/Berlin" || ev.Params["old_start_minute"] != float64(1320) {
		t.Fatalf("replaced event %+v", ev.Params)
	}
	if row, err := groups.MaintenanceWindow(ctx(auditor), group); err != nil || row.Timezone != "UTC" {
		t.Fatalf("get = %+v, %v", row, err)
	}

	// Another organization's group is not found, for reading and writing.
	other := uuid.Must(uuid.NewV7())
	otherGroup := uuid.Must(uuid.NewV7())
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := h.super.Exec(context.Background(), sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec("INSERT INTO organization (id, slug, name, status) VALUES ($1, $2, 'O', 'active')", other, "o"+other.String()[24:])
	exec("INSERT INTO device_group (id, organization_id, name) VALUES ($1, $2, 'foreign')", otherGroup, other)
	exec(`INSERT INTO device_group_maintenance_window (organization_id, device_group_id, days, start_minute, duration_minutes, timezone)
		VALUES ($1, $2, '{1}', 0, 60, 'UTC')`, other, otherGroup)
	if _, err := groups.MaintenanceWindow(ctx(auditor), otherGroup); !errors.Is(err, problem.NotFound) {
		t.Fatalf("foreign get = %v", err)
	}
	if _, err := groups.SetMaintenanceWindow(ctx(operator), otherGroup, night); !errors.Is(err, problem.NotFound) {
		t.Fatalf("foreign set = %v", err)
	}
	if err := groups.DeleteMaintenanceWindow(ctx(operator), otherGroup); !errors.Is(err, problem.NotFound) {
		t.Fatalf("foreign delete = %v", err)
	}

	if err := groups.DeleteMaintenanceWindow(ctx(operator), group); err != nil {
		t.Fatalf("delete = %v", err)
	}
	if ev := h.lastEvent(t); ev.Params["timezone"] != "UTC" || ev.Params["name"] != "night" {
		t.Fatalf("removed event %+v", ev.Params)
	}
	if _, err := groups.MaintenanceWindow(ctx(auditor), group); !errors.Is(err, problem.NotFound) {
		t.Fatalf("get after delete = %v", err)
	}
}

// TestUrgentSoftwareAssignment (PDK-809, plan M13c decision 7): urgent needs a reason of 2 to 500 characters and a
// fresh step-up, which an API token never has; the audit event carries urgent and the reason; an update keeps the flag
// only when it gives it again.
func TestUrgentSoftwareAssignment(t *testing.T) {
	h := newPrivilegesHarness(t)
	pool, err := db.NewOrgPool(context.Background(), pgtest.SharedPaddock(t).API, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	catalog := app.NewSoftwareCatalog(h.runner, pool)
	admin := h.account(t, principal.RoleOrgAdmin, false)
	steppedUp := h.account(t, principal.RoleOrgAdmin, true)
	ctx := func(p principal.Principal) context.Context { return principal.With(context.Background(), p) }
	entry, err := catalog.Create(ctx(admin), app.EntryInput{Name: "openssl-fix",
		Packages: []software.PackageRef{{Distribution: "ubuntu", Release: "*", Architecture: "*", Package: "openssl"}}})
	if err != nil {
		t.Fatal(err)
	}
	in := app.AssignmentInput{CatalogEntryID: &entry.ID, Intent: software.IntentRequired, Urgent: true}

	got := h.during(t, func() {
		if _, err := catalog.CreateAssignment(ctx(steppedUp), in); !errors.Is(err, problem.InvalidRequest) {
			t.Errorf("urgent without reason = %v", err)
		}
		in.Reason = "CVE-2026-0001"
		if _, err := catalog.CreateAssignment(ctx(admin), in); !errors.Is(err, problem.StepUpRequired) {
			t.Errorf("urgent without step-up = %v", err)
		}
	})
	if !slices.Equal(got, []string{"software_assignment.created:failure:invalid_request", "software_assignment.created:denied:step_up_required"}) {
		t.Fatalf("actions %v", got)
	}
	token := h.create(t, steppedUp, "ci", principal.RoleOrgOperator)
	tp, _, err := h.tokens.Authenticate(context.Background(), token.Secret, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := catalog.CreateAssignment(ctx(tp), in); !errors.Is(err, problem.StepUpRequired) ||
		!strings.Contains(problem.From(err).Detail, "API tokens") {
		t.Fatalf("token urgent = %v", err)
	}

	a, err := catalog.CreateAssignment(ctx(steppedUp), in)
	if err != nil {
		t.Fatalf("urgent with step-up = %v", err)
	}
	if !a.Urgent {
		t.Fatalf("stored assignment %+v", a)
	}
	if ev := h.lastEvent(t); ev.Params["urgent"] != true || ev.Params["reason"] != "CVE-2026-0001" || !ev.Actor.StepUp {
		t.Fatalf("created event %+v", ev)
	}

	// An update without urgent clears it and needs no step-up; setting it again does.
	plain := app.AssignmentInput{Intent: software.IntentRequired}
	if a, err = catalog.UpdateAssignment(ctx(admin), a.ID, plain); err != nil || a.Urgent {
		t.Fatalf("plain update = %+v, %v", a, err)
	}
	if ev := h.lastEvent(t); ev.Params["urgent"] != false || ev.Params["old_urgent"] != true {
		t.Fatalf("updated event %+v", ev.Params)
	}
	again := app.AssignmentInput{Intent: software.IntentRequired, Urgent: true, Reason: "CVE-2026-0002"}
	if _, err := catalog.UpdateAssignment(ctx(admin), a.ID, again); !errors.Is(err, problem.StepUpRequired) {
		t.Fatalf("urgent update without step-up = %v", err)
	}
	if a, err = catalog.UpdateAssignment(ctx(steppedUp), a.ID, again); err != nil || !a.Urgent {
		t.Fatalf("urgent update = %+v, %v", a, err)
	}
}

// TestDeclarativeMaintenanceWindow (PDK-809): a device group item carries its maintenance window; the export round
// trips it, the plan shows it as one field, an unknown timezone is refused, an item without it removes the stored
// window, and an apply keeps the urgent flag of an assignment, which the document does not carry, only through a
// reason change: an apply that changes what the assignment does clears it (plan M13c decision 7, no step-up).
func TestDeclarativeMaintenanceWindow(t *testing.T) {
	h := newConfigHarness(t)
	admin := h.account(t, principal.RoleOrgAdmin, false)
	steppedUp := h.account(t, principal.RoleOrgAdmin, true)
	ctx := principal.With(context.Background(), admin)
	doc := h.export(t, admin)
	*doc.DeviceGroups = append(*doc.DeviceGroups, declarative.DeviceGroup{Name: "windowed",
		MaintenanceWindow: &devicegroup.Window{Days: []int{3, 1}, StartMinute: 1380, DurationMinutes: 120, Timezone: "Europe/Berlin"}})
	if _, _, err := h.config.Apply(ctx, raw(t, doc), ""); err != nil {
		t.Fatal(err)
	}
	if n := h.count(t, `SELECT count(*) FROM device_group_maintenance_window w JOIN device_group g ON g.id = w.device_group_id
		WHERE g.name = 'windowed' AND w.days = '{1,3}' AND w.start_minute = 1380 AND w.updated_by = $1`, admin.ID); n != 1 {
		t.Fatal("window not stored")
	}
	exported := h.export(t, admin)
	if id, plan, err := h.config.Apply(ctx, raw(t, exported), ""); err != nil || id != uuid.Nil || len(plan.Changes) != 0 {
		t.Fatalf("re-applying the export = %v, %+v", err, plan)
	}

	for i, g := range *exported.DeviceGroups {
		if g.Name == "windowed" {
			(*exported.DeviceGroups)[i].MaintenanceWindow.Timezone = "Mars/Olympus"
		}
	}
	if _, _, err := h.config.Apply(ctx, raw(t, exported), ""); !errors.Is(err, problem.InvalidRequest) ||
		!strings.Contains(problem.From(err).Detail, "maintenance_window") {
		t.Fatalf("unknown timezone = %v", err)
	}
	for i, g := range *exported.DeviceGroups {
		if g.Name == "windowed" {
			(*exported.DeviceGroups)[i].MaintenanceWindow.Timezone = "UTC"
		}
	}
	plan, err := h.config.Plan(ctx, raw(t, exported))
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Changes) != 1 || len(plan.Changes[0].Fields) != 1 || plan.Changes[0].Fields[0].Name != "maintenance_window" ||
		plan.Changes[0].Fields[0].After != "1,3 23:00+120m UTC" {
		t.Fatalf("plan %+v", plan)
	}

	// An urgent assignment keeps its flag through an apply that changes only its reason.
	pool, err := db.NewOrgPool(context.Background(), pgtest.SharedPaddock(t).API, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	catalog := app.NewSoftwareCatalog(h.runner, pool)
	entry, err := catalog.Create(ctx, app.EntryInput{Name: "urgent-fix",
		Packages: []software.PackageRef{{Distribution: "ubuntu", Release: "*", Architecture: "*", Package: "openssl"}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := catalog.CreateAssignment(principal.With(context.Background(), steppedUp), app.AssignmentInput{
		CatalogEntryID: &entry.ID, Intent: software.IntentRequired, Urgent: true, Reason: "CVE-2026-0003"}); err != nil {
		t.Fatal(err)
	}
	withoutWindow := h.export(t, admin)
	for i, g := range *withoutWindow.DeviceGroups {
		if g.Name == "windowed" {
			(*withoutWindow.DeviceGroups)[i].MaintenanceWindow = nil
		}
	}
	for i, a := range *withoutWindow.SoftwareAssignments {
		if a.Entry == "urgent-fix" {
			(*withoutWindow.SoftwareAssignments)[i].Reason = "changed by the document"
		}
	}
	if _, _, err := h.config.Apply(ctx, raw(t, withoutWindow), ""); err != nil {
		t.Fatal(err)
	}
	if n := h.count(t, "SELECT count(*) FROM device_group_maintenance_window WHERE organization_id = $1", h.org); n != 0 {
		t.Fatal("an item without a window kept it")
	}
	if n := h.count(t, "SELECT count(*) FROM software_assignment WHERE organization_id = $1 AND urgent AND reason = 'changed by the document'", h.org); n != 1 {
		t.Fatal("the apply lifted the urgent flag")
	}

	repurposed := h.export(t, admin)
	for i, a := range *repurposed.SoftwareAssignments {
		if a.Entry == "urgent-fix" {
			(*repurposed.SoftwareAssignments)[i].Intent = software.IntentUninstall
		}
	}
	if _, _, err := h.config.Apply(ctx, raw(t, repurposed), ""); err != nil {
		t.Fatal(err)
	}
	if n := h.count(t, "SELECT count(*) FROM software_assignment WHERE organization_id = $1 AND NOT urgent AND intent = 'uninstall'", h.org); n != 1 {
		t.Fatal("an apply that changed the intent kept the urgent flag")
	}
}

// TestSoftwareRolloutWaitsForWindow (PDK-809, agent contract 6): a device that applied the bundle of a staged
// assignment but reports the staged entry pending/outside_window has not run the change and counts as pending, not
// applied; once it reports the entry installed it counts as applied.
func TestSoftwareRolloutWaitsForWindow(t *testing.T) {
	h := newRolloutHarness(t)
	_, catalog := softwareUseCases(h.writeHarness)
	admin := principal.With(context.Background(), h.account(t, principal.RoleOrgAdmin, true))
	enableRollouts(t, h.writeHarness, []int{50, 100}, nil)
	entry, err := catalog.Create(admin, app.EntryInput{Name: "Browser",
		Packages: []software.PackageRef{{Distribution: "ubuntu", Release: "*", Architecture: "*", Package: "browser"}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := catalog.CreateAssignment(admin, app.AssignmentInput{CatalogEntryID: &entry.ID, Intent: "required"}); err != nil {
		t.Fatal(err)
	}
	r := h.rollout(t, h.lastChangeSet(t).id)
	now := time.Now()
	waiting, done := h.device(t, r.id, 50, true), h.device(t, r.id, 50, true)
	for _, d := range []uuid.UUID{waiting, done} {
		h.report(t, d, r.id, 1, "applied", "enforce", "", now)
	}
	status := func(d uuid.UUID, state, reason string) {
		h.exec(t, `INSERT INTO device_software_status (device_id, organization_id, catalog_entry_id, package, intent, state, reason, reported_at)
			VALUES ($1, $2, $3, 'browser', 'required', $4, $5, $6)
			ON CONFLICT (device_id, catalog_entry_id, scope, username) DO UPDATE SET state = EXCLUDED.state, reason = EXCLUDED.reason`,
			d, h.org, entry.ID, state, reason, now)
	}
	status(waiting, "pending", "outside_window")
	status(done, "installed", "")
	counts := func() app.RolloutCounts {
		t.Helper()
		d, err := h.api.Get(h.admin, r.id)
		if err != nil {
			t.Fatal(err)
		}
		return d.Counts
	}
	if got := counts(); got.Applied != 1 || got.Pending != 1 || got.Failed != 0 {
		t.Fatalf("counts with a device waiting for its window %+v", got)
	}
	status(waiting, "installed", "")
	if got := counts(); got.Applied != 2 || got.Pending != 0 {
		t.Fatalf("counts after the window %+v", got)
	}
}
