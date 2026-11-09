package compiler_test

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/pkg/bundle"
	"github.com/phischl/paddock-mdm/server/internal/compiler"
	"github.com/phischl/paddock-mdm/server/internal/domain/device"
	"github.com/phischl/paddock-mdm/server/internal/domain/statechange"
)

// storedWarning is a compile_warning row as a test compares it.
type storedWarning struct {
	assignment uuid.NullUUID
	entry      uuid.NullUUID
	code       string
	params     map[string]any
}

// warnings returns the stored compile warnings of dev.
func (w *world) warnings(dev uuid.UUID) []storedWarning {
	w.t.Helper()
	rows, err := w.super.Query(context.Background(),
		"SELECT assignment_id, catalog_entry_id, code, params FROM compile_warning WHERE device_id = $1 ORDER BY code, assignment_id", dev)
	if err != nil {
		w.t.Fatal(err)
	}
	defer rows.Close()
	var out []storedWarning
	for rows.Next() {
		var s storedWarning
		var params []byte
		if err := rows.Scan(&s.assignment, &s.entry, &s.code, &params); err != nil {
			w.t.Fatal(err)
		}
		if err := json.Unmarshal(params, &s.params); err != nil {
			w.t.Fatal(err)
		}
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		w.t.Fatal(err)
	}
	return out
}

// assignmentOf returns the ID of the only assignment of entry.
func (w *world) assignmentOf(entry uuid.UUID) uuid.UUID {
	w.t.Helper()
	var id uuid.UUID
	if err := w.super.QueryRow(context.Background(), "SELECT id FROM software_assignment WHERE catalog_entry_id = $1", entry).Scan(&id); err != nil {
		w.t.Fatal(err)
	}
	return id
}

// TestCompileWarningAudienceTruncated (A10-10, plan M13b Q13): an audience of 201 users persists one
// audience_truncated warning for its assignment and device; a recompile with 200 users removes it.
func TestCompileWarningAudienceTruncated(t *testing.T) {
	w := newWorld(t)
	d := w.v2Device("{1,2}", w.g1)
	w.ubuntu(d, "amd64")
	users := make([]uuid.UUID, bundle.MaxSoftwareAudience+1)
	for i := range users {
		users[i] = w.user(fmt.Sprintf("u%03d", i), false)
	}
	w.own(d, users...)
	group := w.userGroup("all", users...)
	nano := w.entry("Nano", nil, [4]string{"ubuntu", "*", "*", "nano"})
	w.assignTo(nano, "user_group_id", group, "available")
	assignment := w.assignmentOf(nano)
	w.mustCompile(statechange.ScopeOrg, w.org)

	got := w.warnings(d)
	if len(got) != 1 || got[0].code != compiler.WarningAudienceTruncated || got[0].assignment.UUID != assignment ||
		got[0].entry.UUID != nano || got[0].params["users"] != float64(bundle.MaxSoftwareAudience+1) ||
		got[0].params["kept"] != float64(bundle.MaxSoftwareAudience) {
		t.Fatalf("warnings %+v", got)
	}
	// A compile that leaves the bundle unchanged keeps the warning, not a second one.
	w.mustCompile(statechange.ScopeDevice, d)
	if got := w.warnings(d); len(got) != 1 {
		t.Fatalf("after an unchanged compile: %+v", got)
	}

	w.exec("DELETE FROM user_group_member WHERE group_id = $1 AND user_id = $2", group, users[0])
	w.mustCompile(statechange.ScopeOrg, w.org)
	if p := pkgOf(w.fetch(d).Software, "nano"); p == nil || p.Audience == nil || len(p.Audience.Users) != bundle.MaxSoftwareAudience {
		t.Fatalf("package %+v", p)
	}
	if got := w.warnings(d); len(got) != 0 {
		t.Fatalf("after 200 users: %+v", got)
	}
}

// TestCompileWarningFlatpakForbidden (A10-9): an APT entry that forbids flatpak drops the device's Flatpak
// applications with their remote and the runtime and persists flatpak_forbidden for the required application's
// assignment; the APT part of the section stays as without the Flatpak application. Lifting the forbid brings the
// application back and removes the warning.
func TestCompileWarningFlatpakForbidden(t *testing.T) {
	for _, intent := range []string{"forbid", "uninstall"} {
		t.Run(intent, func(t *testing.T) {
			w := newWorld(t)
			flathub := w.flathub(loadSoftwareKey(t, "ed25519.asc"))
			gimp := w.flatpakEntry("GIMP", flathub, "org.gimp.GIMP")
			w.assign(gimp, nil, "required", "latest", nil)
			removal := w.flatpakEntry("Spotify", flathub, "com.spotify.Client")
			w.assign(removal, nil, "uninstall", "latest", nil)
			w.assign(w.entry("Nano", nil, [4]string{"ubuntu", "*", "*", "nano"}), nil, "required", "latest", nil)
			d := w.v2Device("{1,2}", w.g1)
			w.ubuntu(d, "amd64")
			other := w.v2Device("{1,2}", w.g2)
			w.ubuntu(other, "amd64")
			flatpak := w.entry("Flatpak", nil, [4]string{"ubuntu", "*", "*", "flatpak"})
			w.assign(flatpak, w.g1, intent, "latest", nil)
			w.mustCompile(statechange.ScopeOrg, w.org)

			s := w.fetch(d).Software
			if s == nil || len(s.Sources) != 0 || pkgOf(s, "org.gimp.GIMP") != nil || pkgOf(s, "com.spotify.Client") != nil {
				t.Fatalf("section %+v", s)
			}
			if p := pkgOf(s, "flatpak"); p == nil || p.Intent != intent || p.CatalogEntryID != flatpak.String() {
				t.Fatalf("flatpak %+v", p)
			}
			if p := pkgOf(s, "nano"); p == nil || p.Intent != bundle.SoftwareRequired || len(s.Packages) != 2 {
				t.Fatalf("APT part %+v", s.Packages)
			}
			got := w.warnings(d)
			if len(got) != 1 || got[0].code != compiler.WarningFlatpakForbidden || got[0].assignment.UUID != w.assignmentOf(gimp) ||
				got[0].entry.UUID != gimp || got[0].params["flatpak_ref"] != "org.gimp.GIMP" {
				t.Fatalf("warnings %+v", got)
			}
			// The device outside the forbid keeps its Flatpak applications and has no warning.
			if pkgOf(w.fetch(other).Software, "org.gimp.GIMP") == nil || len(w.warnings(other)) != 0 {
				t.Fatalf("other device %+v, warnings %+v", w.fetch(other).Software, w.warnings(other))
			}

			w.exec("DELETE FROM software_assignment WHERE catalog_entry_id = $1", flatpak)
			w.mustCompile(statechange.ScopeOrg, w.org)
			if s := w.fetch(d).Software; pkgOf(s, "org.gimp.GIMP") == nil || len(s.Sources) != 1 {
				t.Fatalf("after lifting the forbid %+v", s)
			}
			if got := w.warnings(d); len(got) != 0 {
				t.Fatalf("warnings after lifting the forbid %+v", got)
			}
		})
	}
}

// TestCompileWarningsKeptForBlockedDevice: a device whose bundle is blocked keeps its previous bundle and so its
// previous warnings.
func TestCompileWarningsKeptForBlockedDevice(t *testing.T) {
	w := newWorld(t)
	flathub := w.flathub(loadSoftwareKey(t, "ed25519.asc"))
	w.assign(w.flatpakEntry("GIMP", flathub, "org.gimp.GIMP"), nil, "required", "latest", nil)
	w.assign(w.entry("Flatpak", nil, [4]string{"ubuntu", "*", "*", "flatpak"}), nil, "forbid", "latest", nil)
	d := w.v2Device("{1,2}", w.g1)
	w.ubuntu(d, "amd64")
	w.mustCompile(statechange.ScopeOrg, w.org)
	if len(w.warnings(d)) != 1 {
		t.Fatalf("warnings %+v", w.warnings(d))
	}
	broken := w.entry("Broken", nil, [4]string{"ubuntu", "*", "*", "nano"})
	w.assign(broken, nil, "required", "latest", nil)
	w.exec(`UPDATE software_catalog_entry SET packages = '[{"distribution":"Debian!","release":"*","architecture":"*","package":"nano"}]' WHERE id = $1`, broken)
	w.mustCompile(statechange.ScopeOrg, w.org)
	if w.renderFailures(d, broken.String()) == 0 {
		t.Fatal("the bundle was not blocked")
	}
	if len(w.warnings(d)) != 1 {
		t.Fatalf("warnings of the blocked device %+v", w.warnings(d))
	}
}

// bundleSeq returns the bundle_seq of dev.
func (w *world) bundleSeq(dev uuid.UUID) int64 {
	w.t.Helper()
	var seq int64
	if err := w.super.QueryRow(context.Background(), "SELECT bundle_seq FROM device WHERE id = $1", dev).Scan(&seq); err != nil {
		w.t.Fatal(err)
	}
	return seq
}

// TestCompileWarningsOutdatedCompile (A10-10): two compiles of one organization run side by side. The outdated one,
// whose snapshot saw an older bundle, writes its warnings after the newer compile published; it neither brings back a
// warning whose cause is gone nor deletes a current one.
func TestCompileWarningsOutdatedCompile(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	flathub := w.flathub(loadSoftwareKey(t, "ed25519.asc"))
	w.assign(w.flatpakEntry("GIMP", flathub, "org.gimp.GIMP"), nil, "required", "latest", nil)
	flatpak := w.entry("Flatpak", nil, [4]string{"ubuntu", "*", "*", "flatpak"})
	w.assign(flatpak, nil, "forbid", "latest", nil)
	d := w.v2Device("{1,2}", w.g1)
	w.ubuntu(d, "amd64")
	w.mustCompile(statechange.ScopeOrg, w.org)
	forbidden := w.bundleSeq(d)
	if got := w.warnings(d); len(got) != 1 {
		t.Fatalf("warnings %+v", got)
	}

	w.exec("DELETE FROM software_assignment WHERE catalog_entry_id = $1", flatpak)
	w.mustCompile(statechange.ScopeOrg, w.org)
	lifted := w.bundleSeq(d)
	if lifted == forbidden || len(w.warnings(d)) != 0 {
		t.Fatalf("seq %d after %d, warnings %+v", lifted, forbidden, w.warnings(d))
	}
	if err := w.comp.RecordWarningsAt(ctx, w.org, d, forbidden, compiler.WarningFlatpakForbidden); err != nil {
		t.Fatal(err)
	}
	if got := w.warnings(d); len(got) != 0 {
		t.Fatalf("an outdated compile brought back %+v", got)
	}

	w.assign(flatpak, nil, "forbid", "latest", nil)
	w.mustCompile(statechange.ScopeOrg, w.org)
	if got := w.warnings(d); len(got) != 1 || w.bundleSeq(d) == lifted {
		t.Fatalf("warnings %+v", got)
	}
	if err := w.comp.RecordWarningsAt(ctx, w.org, d, lifted); err != nil {
		t.Fatal(err)
	}
	if got := w.warnings(d); len(got) != 1 || got[0].code != compiler.WarningFlatpakForbidden {
		t.Fatalf("an outdated compile deleted the current warnings, left %+v", got)
	}
	// The compile that saw the current bundle still replaces them.
	if err := w.comp.RecordWarningsAt(ctx, w.org, d, w.bundleSeq(d)); err != nil {
		t.Fatal(err)
	}
	if got := w.warnings(d); len(got) != 0 {
		t.Fatalf("warnings of the current compile were not replaced: %+v", got)
	}
}

// TestCompileWarningsClearedWhenDeviceLeavesActive: a device that leaves active is no longer compiled; its
// device-scoped recompile removes its warnings.
func TestCompileWarningsClearedWhenDeviceLeavesActive(t *testing.T) {
	w := newWorld(t)
	flathub := w.flathub(loadSoftwareKey(t, "ed25519.asc"))
	w.assign(w.flatpakEntry("GIMP", flathub, "org.gimp.GIMP"), nil, "required", "latest", nil)
	w.assign(w.entry("Flatpak", nil, [4]string{"ubuntu", "*", "*", "flatpak"}), nil, "forbid", "latest", nil)
	d := w.v2Device("{1,2}", w.g1)
	w.ubuntu(d, "amd64")
	w.mustCompile(statechange.ScopeOrg, w.org)
	if got := w.warnings(d); len(got) != 1 {
		t.Fatalf("warnings %+v", got)
	}
	w.exec("UPDATE device SET state = $1 WHERE id = $2", device.StateRetired, d)
	w.mustCompile(statechange.ScopeDevice, d)
	if got := w.warnings(d); len(got) != 0 {
		t.Fatalf("warnings of the retired device %+v", got)
	}
}
