package app_test

import (
	"bytes"
	"context"
	"errors"
	"image"
	"image/png"
	"slices"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/domain/software"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/problem"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/pgtest"
)

// TestSoftwareCatalog (plan M13a decisions 7 to 11, ticket PDK-409): the roles, one audit event per attempt with the
// params of the plan, request text bounded in the events of refused requests, the intent rules, the cascade of a
// delete and the source that an entry holds in use.
func TestSoftwareCatalog(t *testing.T) {
	h := newPrivilegesHarness(t)
	pool, err := db.NewOrgPool(context.Background(), pgtest.SharedPaddock(t).API, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	catalog := app.NewSoftwareCatalog(h.runner, pool)
	sources := app.NewSoftwareSources(h.runner, pool)
	steppedUp := h.account(t, principal.RoleOrgAdmin, true)
	operator := h.account(t, principal.RoleOrgOperator, false)
	auditor := h.account(t, principal.RoleOrgAuditor, false)
	ctx := func(p principal.Principal) context.Context { return principal.With(context.Background(), p) }
	nano := []software.PackageRef{{Distribution: "ubuntu", Release: "*", Architecture: "*", Package: "nano"}}
	groupID := uuid.Must(uuid.NewV7())
	if _, err := h.super.Exec(context.Background(), `INSERT INTO device_group (id, organization_id, name) VALUES ($1, $2, 'Laptops')`, groupID, h.org); err != nil {
		t.Fatal(err)
	}

	got := h.during(t, func() {
		if _, err := catalog.Create(ctx(auditor), app.EntryInput{Name: "Editor", Packages: nano}); !errors.Is(err, problem.Forbidden) {
			t.Errorf("auditor create = %v", err)
		}
		if _, err := catalog.Create(ctx(operator), app.EntryInput{Name: "Editor", Packages: nil}); !errors.Is(err, problem.InvalidRequest) {
			t.Errorf("no packages = %v", err)
		}
	})
	if !slices.Equal(got, []string{"software_catalog_entry.created:denied:forbidden", "software_catalog_entry.created:failure:invalid_request"}) {
		t.Fatalf("actions %v", got)
	}

	// A refused request records its text bounded and cleaned.
	huge := strings.Repeat("x", 200000) + "\u202e"
	if _, err := catalog.Create(ctx(auditor), app.EntryInput{Name: huge, Category: huge, Packages: nano}); !errors.Is(err, problem.Forbidden) {
		t.Fatal(err)
	}
	ev := h.lastEvent(t)
	if n, _ := ev.Params["name"].(string); len([]rune(n)) > software.MaxNameLength+1 || ev.Params["package_count"] != float64(1) {
		t.Fatalf("denied create recorded %+v", ev.Params)
	}
	if _, err := catalog.CreateAssignment(ctx(auditor), app.AssignmentInput{Intent: huge, UpdateRule: huge, Version: &huge, Reason: huge}); !errors.Is(err, problem.Forbidden) {
		t.Fatal(err)
	}
	ev = h.lastEvent(t)
	for _, k := range []string{"intent", "update_rule", "version", "reason"} {
		if s, _ := ev.Params[k].(string); len([]rune(s)) > software.MaxReasonLength+1 || strings.ContainsRune(s, '\u202e') {
			t.Fatalf("denied assignment recorded unbounded %s", k)
		}
	}

	key := sourceKey(t, "ed25519.asc")
	source, err := sources.Create(ctx(steppedUp), software.SourceInput{
		Slug: "vendor", Name: "Vendor", URIs: []string{"https://apt.vendor.example/"}, Suites: []string{"stable"},
		Components: []string{"main"}, SigningKey: key, Fingerprint: sourceEd25519FP,
	})
	if err != nil {
		t.Fatal(err)
	}
	entry, err := catalog.Create(ctx(operator), app.EntryInput{Name: " Editor ", Category: "Tools", SourceID: &source.ID, Packages: nano})
	if err != nil {
		t.Fatal(err)
	}
	if entry.Name != "Editor" || entry.SourceSlug != "vendor" || entry.HasIcon || entry.AssignmentCount != 0 {
		t.Fatalf("created %+v", entry)
	}
	ev = h.lastEvent(t)
	if ev.Params["name"] != "Editor" || ev.Params["category"] != "Tools" || ev.Params["source_id"] != source.ID.String() ||
		ev.Params["source_slug"] != "vendor" || ev.Params["package_count"] != float64(1) || ev.Target.Display != "Editor" {
		t.Fatalf("created event %+v", ev)
	}
	if _, err := catalog.Create(ctx(operator), app.EntryInput{Name: "Editor", Packages: nano}); !errors.Is(err, problem.AlreadyExists) {
		t.Fatalf("duplicate = %v", err)
	}
	if _, err := catalog.Create(ctx(operator), app.EntryInput{Name: "Other", SourceID: new(uuid.New()), Packages: nano}); !errors.Is(err, problem.NotFound) {
		t.Fatalf("unknown source = %v", err)
	}

	// The source is in use until the entry stops using it.
	if err := sources.Delete(ctx(steppedUp), source.ID); !errors.Is(err, problem.InUse) {
		t.Fatalf("delete used source = %v", err)
	}
	updated, err := catalog.Update(ctx(operator), entry.ID, app.EntryInput{Name: "Editor", Description: "d", Category: "Tools", Packages: nano})
	if err != nil || updated.SourceID.Valid || updated.SourceSlug != "" || updated.Description != "d" {
		t.Fatalf("update = %+v, %v", updated, err)
	}
	ev = h.lastEvent(t)
	if !slices.Equal(anyStrings(ev.Params["fields"]), []string{"description", "source_id"}) || ev.Params["name"] != "Editor" {
		t.Fatalf("updated event %+v", ev)
	}
	if err := sources.Delete(ctx(steppedUp), source.ID); err != nil {
		t.Fatalf("delete unused source = %v", err)
	}

	// Icons: a PNG within the limits is stored and named in the event.
	var buf bytes.Buffer
	if err := png.Encode(&buf, image.NewGray(image.Rect(0, 0, 16, 16))); err != nil {
		t.Fatal(err)
	}
	if err := catalog.SetIcon(ctx(auditor), entry.ID, buf.Bytes()); !errors.Is(err, problem.Forbidden) {
		t.Fatalf("auditor icon = %v", err)
	}
	if err := catalog.SetIcon(ctx(operator), entry.ID, []byte("GIF89a")); !errors.Is(err, problem.InvalidRequest) {
		t.Fatalf("non-PNG icon = %v", err)
	}
	if err := catalog.SetIcon(ctx(operator), entry.ID, buf.Bytes()); err != nil {
		t.Fatal(err)
	}
	if ev = h.lastEvent(t); !slices.Equal(anyStrings(ev.Params["fields"]), []string{"icon"}) {
		t.Fatalf("icon event %+v", ev)
	}
	if icon, err := catalog.Icon(ctx(auditor), entry.ID); err != nil || !bytes.Equal(icon, buf.Bytes()) {
		t.Fatalf("icon = %d bytes, %v", len(icon), err)
	}
	other, err := catalog.Create(ctx(operator), app.EntryInput{Name: "Other", Packages: nano})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := catalog.Icon(ctx(auditor), other.ID); !errors.Is(err, problem.NotFound) {
		t.Fatalf("icon without one = %v", err)
	}

	// Assignments: the intent rules, the defaults and the audit params.
	pinned := "1.0"
	created, err := catalog.CreateAssignment(ctx(operator), app.AssignmentInput{
		CatalogEntryID: &entry.ID, DeviceGroupID: &groupID, Intent: software.IntentRequired, Version: &pinned, Reason: "needed",
	})
	if err != nil || created.UpdateRule != software.UpdatePinned || created.AppName != "Editor" {
		t.Fatalf("assignment = %+v, %v", created, err)
	}
	ev = h.lastEvent(t)
	if ev.Params["app"] != "Editor" || ev.Params["catalog_entry_id"] != entry.ID.String() || ev.Params["device_group_id"] != groupID.String() ||
		ev.Params["intent"] != "required" || ev.Params["update_rule"] != "pinned" || ev.Params["version"] != "1.0" ||
		ev.Params["reason"] != "needed" || ev.Target.Display != "Editor → Laptops" {
		t.Fatalf("assignment event %+v", ev)
	}
	for name, in := range map[string]app.AssignmentInput{
		"latest with version":   {CatalogEntryID: &entry.ID, Intent: software.IntentRequired, UpdateRule: software.UpdateLatest, Version: &pinned},
		"forbid with version":   {CatalogEntryID: &entry.ID, Intent: software.IntentForbid, Version: &pinned},
		"unknown intent":        {CatalogEntryID: &entry.ID, Intent: "available"},
		"hold with bad version": {CatalogEntryID: &entry.ID, Intent: software.IntentHold, Version: new("1 0")},
	} {
		if _, err := catalog.CreateAssignment(ctx(operator), in); !errors.Is(err, problem.InvalidRequest) {
			t.Errorf("%s = %v", name, err)
		}
	}
	if _, err := catalog.CreateAssignment(ctx(operator), app.AssignmentInput{CatalogEntryID: &entry.ID, DeviceGroupID: &groupID, Intent: software.IntentHold}); !errors.Is(err, problem.AlreadyExists) {
		t.Fatalf("second in scope = %v", err)
	}
	if _, err := catalog.CreateAssignment(ctx(operator), app.AssignmentInput{CatalogEntryID: &entry.ID, DeviceGroupID: new(uuid.New()), Intent: software.IntentHold}); !errors.Is(err, problem.NotFound) {
		t.Fatalf("unknown group = %v", err)
	}
	if _, err := catalog.CreateAssignment(ctx(operator), app.AssignmentInput{CatalogEntryID: new(uuid.New()), Intent: software.IntentHold}); !errors.Is(err, problem.NotFound) {
		t.Fatalf("unknown entry = %v", err)
	}
	orgWide, err := catalog.CreateAssignment(ctx(operator), app.AssignmentInput{CatalogEntryID: &entry.ID, Intent: software.IntentHold})
	if err != nil || orgWide.DeviceGroupID.Valid || orgWide.UpdateRule != software.UpdateLatest {
		t.Fatalf("organization-wide = %+v, %v", orgWide, err)
	}
	if ev = h.lastEvent(t); ev.Params["device_group_id"] != nil || ev.Target.Display != "Editor → organization" {
		t.Fatalf("organization-wide event %+v", ev)
	}

	if _, err := catalog.UpdateAssignment(ctx(operator), created.ID, app.AssignmentInput{Intent: software.IntentForbid, Version: &pinned}); !errors.Is(err, problem.InvalidRequest) {
		t.Fatalf("forbid with version = %v", err)
	}
	if _, err := catalog.UpdateAssignment(ctx(operator), created.ID, app.AssignmentInput{CatalogEntryID: &other.ID, Intent: software.IntentForbid}); !errors.Is(err, problem.InvalidRequest) {
		t.Fatalf("entry change = %v", err)
	}
	patched, err := catalog.UpdateAssignment(ctx(operator), created.ID, app.AssignmentInput{Intent: software.IntentForbid})
	if err != nil || patched.Intent != "forbid" || patched.Version != nil {
		t.Fatalf("patch = %+v, %v", patched, err)
	}
	ev = h.lastEvent(t)
	if ev.Params["old_intent"] != "required" || ev.Params["old_version"] != "1.0" || ev.Params["intent"] != "forbid" || ev.Params["app"] != "Editor" ||
		ev.Params["device_group_id"] != groupID.String() {
		t.Fatalf("updated event %+v", ev)
	}

	page, err := catalog.ListAssignments(ctx(auditor), app.SoftwareAssignmentQuery{
		Page: app.ListPage{Sort: "-created_at", Limit: 25}, CatalogEntryID: &entry.ID, Intent: new("forbid"),
	})
	if err != nil || page.Count != 1 || page.Items[0].ID != created.ID {
		t.Fatalf("list assignments = %+v, %v", page, err)
	}
	entries, err := catalog.List(ctx(auditor), app.CatalogQuery{Page: app.ListPage{Sort: "name", Limit: 25}, Category: new("Tools")})
	if err != nil || entries.Count != 1 || entries.Items[0].AssignmentCount != 2 {
		t.Fatalf("list entries = %+v, %v", entries, err)
	}

	// Delete: the assignments go with the entry and the event counts them.
	if err := catalog.Delete(ctx(auditor), entry.ID); !errors.Is(err, problem.Forbidden) {
		t.Fatalf("auditor delete = %v", err)
	}
	if err := catalog.Delete(ctx(operator), entry.ID); err != nil {
		t.Fatal(err)
	}
	if ev = h.lastEvent(t); ev.Params["assignment_count"] != float64(2) || ev.Params["name"] != "Editor" {
		t.Fatalf("deleted event %+v", ev)
	}
	if _, err := catalog.GetAssignment(ctx(auditor), created.ID); !errors.Is(err, problem.NotFound) {
		t.Fatalf("assignment after delete = %v", err)
	}
	if err := catalog.Delete(ctx(operator), entry.ID); !errors.Is(err, problem.NotFound) {
		t.Fatalf("second delete = %v", err)
	}
	if err := catalog.DeleteAssignment(ctx(operator), orgWide.ID); !errors.Is(err, problem.NotFound) {
		t.Fatalf("delete assignment after the entry = %v", err)
	}
}

// TestSoftwareCatalogConstraints: the database refuses what the use cases already refuse, so a bug in a use case or a
// future writer cannot store an assignment that violates the intent rules or point into another organization.
func TestSoftwareCatalogConstraints(t *testing.T) {
	h := newPrivilegesHarness(t)
	ctx := context.Background()
	foreign := uuid.Must(uuid.NewV7())
	if _, err := h.super.Exec(ctx, "INSERT INTO organization (id, slug, name, status) VALUES ($1, $2, 'Foreign', 'active')", foreign, "foreign-"+foreign.String()[:8]); err != nil {
		t.Fatal(err)
	}
	insertSource := func(org uuid.UUID) uuid.UUID {
		id := uuid.Must(uuid.NewV7())
		if _, err := h.super.Exec(ctx, `INSERT INTO software_source (id, organization_id, slug, name, uris, suites, signing_key, fingerprint)
			VALUES ($1, $2, 'vendor', 'Vendor', '{https://a.example/}', '{stable}', 'key', $3)`, id, org, strings.Repeat("A", 40)); err != nil {
			t.Fatal(err)
		}
		return id
	}
	insertEntry := func(org uuid.UUID, name string, source any) (uuid.UUID, error) {
		id := uuid.Must(uuid.NewV7())
		_, err := h.super.Exec(ctx, `INSERT INTO software_catalog_entry (id, organization_id, name, source_id, packages) VALUES ($1, $2, $3, $4, '[]')`, id, org, name, source)
		return id, err
	}
	mine, theirs := insertSource(h.org), insertSource(foreign)
	if _, err := insertEntry(h.org, "Uses foreign source", theirs); err == nil {
		t.Fatal("an entry used a source of another organization")
	}
	entry, err := insertEntry(h.org, "Mine", mine)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.super.Exec(ctx, `DELETE FROM software_source WHERE id = $1`, mine); err == nil {
		t.Fatal("a source used by an entry was deleted")
	}
	insertAssignment := func(org, group any, intent, rule string, version any) error {
		_, err := h.super.Exec(ctx, `INSERT INTO software_assignment (id, organization_id, catalog_entry_id, device_group_id, intent, update_rule, version)
			VALUES ($1, $2, $3, $4, $5, $6, $7)`, uuid.Must(uuid.NewV7()), org, entry, group, intent, rule, version)
		return err
	}
	if err := insertAssignment(foreign, nil, "hold", "latest", nil); err == nil {
		t.Fatal("an assignment of another organization pointed at this entry")
	}
	for name, c := range map[string]struct {
		intent, rule string
		version      any
	}{
		"required pinned without version": {"required", "pinned", nil},
		"required latest with version":    {"required", "latest", "1.0"},
		"forbid with version":             {"forbid", "latest", "1.0"},
		"uninstall pinned":                {"uninstall", "pinned", nil},
		"hold pinned":                     {"hold", "pinned", "1.0"},
		"unknown intent":                  {"available", "latest", nil},
	} {
		if err := insertAssignment(h.org, nil, c.intent, c.rule, c.version); err == nil {
			t.Errorf("%s was stored", name)
		}
	}
	if err := insertAssignment(h.org, nil, "hold", "latest", "1.0"); err != nil {
		t.Fatal(err)
	}
	if err := insertAssignment(h.org, nil, "required", "latest", nil); err == nil {
		t.Fatal("a second organization-wide assignment of the entry was stored")
	}
}

// TestSoftwareCatalogProtectedPackages (architect decision 2026-11-02, plan M13a amendment M3): an entry that names a
// package of Paddock is refused at creation and, if one was stored earlier, at every assignment, each refusal with
// exactly one failure event.
func TestSoftwareCatalogProtectedPackages(t *testing.T) {
	h := newPrivilegesHarness(t)
	pool, err := db.NewOrgPool(context.Background(), pgtest.SharedPaddock(t).API, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	catalog := app.NewSoftwareCatalog(h.runner, pool)
	operator := h.account(t, principal.RoleOrgOperator, false)
	ctx := principal.With(context.Background(), operator)

	for _, name := range []string{"paddock-agent", "paddock-supervisor", "paddock-revoke", "fleet-osquery", "himmelblau", "pam-himmelblau", "nss-himmelblau"} {
		got := h.during(t, func() {
			_, err := catalog.Create(ctx, app.EntryInput{Name: "Protected " + name, Packages: []software.PackageRef{
				{Distribution: "ubuntu", Release: "*", Architecture: "*", Package: name}}})
			if !errors.Is(err, problem.InvalidRequest) {
				t.Errorf("%s = %v", name, err)
			}
		})
		if !slices.Equal(got, []string{"software_catalog_entry.created:failure:invalid_request"}) {
			t.Fatalf("%s: actions %v", name, got)
		}
	}

	entry := uuid.Must(uuid.NewV7())
	if _, err := h.super.Exec(context.Background(), `INSERT INTO software_catalog_entry (id, organization_id, name, packages)
		VALUES ($1, $2, 'Stored earlier', '[{"distribution":"ubuntu","release":"*","architecture":"*","package":"paddock-agent"}]')`, entry, h.org); err != nil {
		t.Fatal(err)
	}
	for _, intent := range []string{software.IntentForbid, software.IntentUninstall, software.IntentHold, software.IntentRequired} {
		got := h.during(t, func() {
			if _, err := catalog.CreateAssignment(ctx, app.AssignmentInput{CatalogEntryID: &entry, Intent: intent}); !errors.Is(err, problem.InvalidRequest) {
				t.Errorf("%s = %v", intent, err)
			}
		})
		if !slices.Equal(got, []string{"software_assignment.created:failure:invalid_request"}) {
			t.Fatalf("%s: actions %v", intent, got)
		}
	}

	// An update of an ordinary entry to a protected package is refused, audited once.
	ordinary, err := catalog.Create(ctx, app.EntryInput{Name: "Ordinary", Packages: []software.PackageRef{{Distribution: "ubuntu", Release: "*", Architecture: "*", Package: "nano"}}})
	if err != nil {
		t.Fatal(err)
	}
	got := h.during(t, func() {
		_, err := catalog.Update(ctx, ordinary.ID, app.EntryInput{Name: "Ordinary", Packages: []software.PackageRef{{Distribution: "ubuntu", Release: "*", Architecture: "*", Package: "himmelblau-apparmor"}}})
		if !errors.Is(err, problem.InvalidRequest) {
			t.Errorf("entry update = %v", err)
		}
	})
	if !slices.Equal(got, []string{"software_catalog_entry.updated:failure:invalid_request"}) {
		t.Fatalf("entry update actions %v", got)
	}

	// Removal-protected and conflicting packages: the intent decides.
	for _, c := range []struct {
		pkg, intent string
		refused     bool
	}{
		{"sudo", software.IntentForbid, true}, {"sudo", software.IntentUninstall, true}, {"sudo", software.IntentRequired, false},
		{"dracut", software.IntentUninstall, true}, {"initramfs-tools", software.IntentRequired, true},
		{"initramfs-tools", software.IntentHold, true}, {"initramfs-tools", software.IntentForbid, false},
	} {
		e, err := catalog.Create(ctx, app.EntryInput{Name: "Tier " + c.pkg + " " + c.intent, Packages: []software.PackageRef{{Distribution: "ubuntu", Release: "*", Architecture: "*", Package: c.pkg}}})
		if err != nil {
			t.Fatalf("entry naming %s: %v", c.pkg, err)
		}
		want := "software_assignment.created:success:"
		if c.refused {
			want = "software_assignment.created:failure:invalid_request"
		}
		got := h.during(t, func() {
			_, err := catalog.CreateAssignment(ctx, app.AssignmentInput{CatalogEntryID: &e.ID, Intent: c.intent})
			if errors.Is(err, problem.InvalidRequest) != c.refused || (!c.refused && err != nil) {
				t.Errorf("%s %s = %v, refused %v", c.intent, c.pkg, err, c.refused)
			}
		})
		if !slices.Equal(got, []string{want}) {
			t.Fatalf("%s %s: actions %v, want %s", c.intent, c.pkg, got, want)
		}
	}

	assignment := uuid.Must(uuid.NewV7())
	if _, err := h.super.Exec(context.Background(), `INSERT INTO software_assignment (id, organization_id, catalog_entry_id, intent) VALUES ($1, $2, $3, 'hold')`,
		assignment, h.org, entry); err != nil {
		t.Fatal(err)
	}
	got = h.during(t, func() {
		if _, err := catalog.UpdateAssignment(ctx, assignment, app.AssignmentInput{Intent: software.IntentForbid}); !errors.Is(err, problem.InvalidRequest) {
			t.Errorf("update = %v", err)
		}
	})
	if !slices.Equal(got, []string{"software_assignment.updated:failure:invalid_request"}) {
		t.Fatalf("update actions %v", got)
	}
}

// TestSoftwareCatalogUpdateKeepsAssignmentsValid (PDK-410 external re-check): changing an entry's packages is checked
// against the intents of its existing assignments, so an entry cannot be turned into a forbid of a package Paddock
// depends on, or a required package that conflicts with it, behind an assignment's back. A refusal is audited once.
func TestSoftwareCatalogUpdateKeepsAssignmentsValid(t *testing.T) {
	h := newPrivilegesHarness(t)
	pool, err := db.NewOrgPool(context.Background(), pgtest.SharedPaddock(t).API, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	catalog := app.NewSoftwareCatalog(h.runner, pool)
	ctx := principal.With(context.Background(), h.account(t, principal.RoleOrgOperator, false))
	refs := func(pkg string) []software.PackageRef {
		return []software.PackageRef{{Distribution: "ubuntu", Release: "*", Architecture: "*", Package: pkg}}
	}
	for _, c := range []struct {
		intent, pkg string
		refused     bool
	}{
		{software.IntentForbid, "sudo", true}, {software.IntentRequired, "initramfs-tools", true},
		{software.IntentRequired, "sudo", false},
	} {
		name := "Vim " + c.intent + " " + c.pkg
		e, err := catalog.Create(ctx, app.EntryInput{Name: name, Packages: refs("vim")})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := catalog.CreateAssignment(ctx, app.AssignmentInput{CatalogEntryID: &e.ID, Intent: c.intent}); err != nil {
			t.Fatal(err)
		}
		want := "software_catalog_entry.updated:success:"
		if c.refused {
			want = "software_catalog_entry.updated:failure:invalid_request"
		}
		got := h.during(t, func() {
			_, err := catalog.Update(ctx, e.ID, app.EntryInput{Name: name, Packages: refs(c.pkg)})
			if errors.Is(err, problem.InvalidRequest) != c.refused || (!c.refused && err != nil) {
				t.Errorf("%s, vim → %s = %v, refused %v", c.intent, c.pkg, err, c.refused)
			}
		})
		if !slices.Equal(got, []string{want}) {
			t.Fatalf("%s, vim → %s: actions %v, want %s", c.intent, c.pkg, got, want)
		}
		stored, err := catalog.Get(ctx, e.ID)
		if err != nil {
			t.Fatal(err)
		}
		packages, err := software.DecodePackages(stored.Packages)
		if err != nil {
			t.Fatal(err)
		}
		if wantPkg := map[bool]string{true: "vim", false: c.pkg}[c.refused]; packages[0].Package != wantPkg {
			t.Fatalf("%s: stored package %s, want %s", c.intent, packages[0].Package, wantPkg)
		}
	}
}
