package compiler_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/pkg/bundle"
	"github.com/phischl/paddock-mdm/pkg/compat"
	"github.com/phischl/paddock-mdm/pkg/openpgpkey"
	"github.com/phischl/paddock-mdm/server/internal/domain/statechange"
)

// softwareKey is an OpenPGP fixture key: its armored text, binary keyring and fingerprint.
type softwareKey struct {
	armored     string
	keyring     []byte
	fingerprint string
}

func loadSoftwareKey(t *testing.T, name string) softwareKey {
	t.Helper()
	armored, err := os.ReadFile("../../../pkg/openpgpkey/testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	fp, keyring, err := openpgpkey.Fingerprint(armored)
	if err != nil {
		t.Fatal(err)
	}
	return softwareKey{armored: string(armored), keyring: keyring, fingerprint: fp}
}

// source inserts a package source with key k whose stored fingerprint is fingerprint.
func (w *world) source(slug string, k softwareKey, fingerprint string) uuid.UUID {
	w.t.Helper()
	id := uuid.Must(uuid.NewV7())
	w.exec(`INSERT INTO software_source (id, organization_id, slug, name, uris, suites, components, architectures, signing_key, fingerprint)
		VALUES ($1, $2, $3, $3, '{https://repo.example.com/apt}', '{stable}', '{main}', '{amd64}', $4, $5)`,
		id, w.org, slug, k.armored, fingerprint)
	return id
}

// entry inserts a catalog entry with package references [distribution, release, architecture, package]...
func (w *world) entry(name string, source any, refs ...[4]string) uuid.UUID {
	w.t.Helper()
	var packages []map[string]string
	for _, r := range refs {
		packages = append(packages, map[string]string{"distribution": r[0], "release": r[1], "architecture": r[2], "package": r[3]})
	}
	raw, _ := json.Marshal(packages)
	id := uuid.Must(uuid.NewV7())
	w.exec("INSERT INTO software_catalog_entry (id, organization_id, name, source_id, packages) VALUES ($1, $2, $3, $4, $5)",
		id, w.org, name, source, raw)
	return id
}

func (w *world) assign(entry uuid.UUID, group any, intent, rule string, version any) uuid.UUID {
	w.t.Helper()
	id := uuid.Must(uuid.NewV7())
	w.exec(`INSERT INTO software_assignment (id, organization_id, catalog_entry_id, device_group_id, intent, update_rule, version)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`, id, w.org, entry, group, intent, rule, version)
	return id
}

// osRelease stores the os-release of dev in the shape enrollment stores it: the agent reports the keys lowercased
// (agent/internal/enroll.osRelease) and app.createDevice marshals the map as it is.
func (w *world) osRelease(dev uuid.UUID, id, versionID string) {
	w.t.Helper()
	raw, err := json.Marshal(map[string]string{"id": id, "version_id": versionID, "pretty_name": "X"})
	if err != nil {
		w.t.Fatal(err)
	}
	w.exec("UPDATE device SET os_release = $2 WHERE id = $1", dev, raw)
}

// ubuntu makes dev an Ubuntu 24.04 device with the reported architecture arch.
func (w *world) ubuntu(dev uuid.UUID, arch string) {
	w.t.Helper()
	w.osRelease(dev, "ubuntu", "24.04")
	w.exec("UPDATE device_status SET arch = $2 WHERE device_id = $1", dev, arch)
}

func holdsOf(b *bundle.Bundle) map[string]string {
	out := map[string]string{}
	for _, h := range b.Updates.Holds {
		v := "<nil>"
		if h.Version != nil {
			v = *h.Version
		}
		out[h.Package] = v
	}
	return out
}

func str(p *string) string {
	if p == nil {
		return "<nil>"
	}
	return *p
}

// TestSoftwareSection (plan M13a decision 14): a v2 device in a group with an assignment gets the software section
// with the resolved package and, for required packages, its source; holds and required pinned packages are merged
// with the package holds into the updates section, and the section follows the merged version.
func TestSoftwareSection(t *testing.T) {
	w := newWorld(t)
	key := loadSoftwareKey(t, "ed25519.asc")
	src := w.source("vendor", key, key.fingerprint)
	e := w.entry("Nano", src, [4]string{"ubuntu", "*", "*", "nano"})
	d := w.v2Device("{1,2}", w.g1)
	w.ubuntu(d, "amd64")
	w.exec("INSERT INTO package_hold (id, organization_id, package) VALUES ($1, $2, 'openssl')", uuid.Must(uuid.NewV7()), w.org)
	a := w.assign(e, w.g1, "required", "pinned", "1.0")
	w.mustCompile(statechange.ScopeOrg, w.org)

	b := w.fetch(d)
	s := b.Software
	if s == nil || len(s.Packages) != 1 {
		t.Fatalf("software section %+v", s)
	}
	if p := s.Packages[0]; p.Package != "nano" || p.Intent != bundle.SoftwareRequired || str(p.Version) != "1.0" || p.Source != "vendor" ||
		p.CatalogEntryID != e.String() {
		t.Fatalf("package %+v", p)
	}
	if len(s.Sources) != 1 {
		t.Fatalf("sources %+v", s.Sources)
	}
	if got := s.Sources[0]; got.Slug != "vendor" || got.Fingerprint != key.fingerprint || got.Keyring != base64.StdEncoding.EncodeToString(key.keyring) ||
		len(got.URIs) != 1 || got.URIs[0] != "https://repo.example.com/apt" || got.Suites[0] != "stable" || got.Components[0] != "main" ||
		got.Architectures[0] != "amd64" {
		t.Fatalf("source %+v", got)
	}
	if err := bundle.ValidateSoftware(*s); err != nil {
		t.Fatalf("compiled section fails ValidateSoftware: %v", err)
	}
	if h := holdsOf(b); len(h) != 2 || h["nano"] != "1.0" || h["openssl"] != "<nil>" {
		t.Fatalf("holds %v", h)
	}

	// A recompile without a change keeps the content hash; a changed assignment changes it.
	before := w.version(d)
	w.mustCompile(statechange.ScopeOrg, w.org)
	if w.version(d) != before {
		t.Fatal("an unchanged software state published a new bundle")
	}

	w.exec("UPDATE software_assignment SET intent = 'hold', update_rule = 'latest', version = NULL WHERE id = $1", a)
	w.mustCompile(statechange.ScopeOrg, w.org)
	if w.version(d) != before+1 {
		t.Fatal("a changed assignment did not publish a new bundle")
	}
	b = w.fetch(d)
	if s := b.Software; s == nil || len(s.Sources) != 0 || len(s.Packages) != 1 || s.Packages[0].Intent != bundle.SoftwareHold ||
		s.Packages[0].Source != "" || s.Packages[0].Version != nil {
		t.Fatalf("hold section %+v", b.Software)
	}
	if h := holdsOf(b); h["nano"] != "<nil>" {
		t.Fatalf("hold holds %v", h)
	}

	w.exec("UPDATE software_assignment SET intent = 'forbid' WHERE id = $1", a)
	w.mustCompile(statechange.ScopeOrg, w.org)
	b = w.fetch(d)
	if s := b.Software; s == nil || len(s.Sources) != 0 || len(s.Packages) != 1 || s.Packages[0].Intent != bundle.SoftwareForbid ||
		s.Packages[0].Source != "" {
		t.Fatalf("forbid section %+v", b.Software)
	}
	if h := holdsOf(b); len(h) != 1 || h["openssl"] != "<nil>" {
		t.Fatalf("forbid holds %v", h)
	}

	w.exec("UPDATE software_assignment SET intent = 'required' WHERE id = $1", a)
	w.exec("INSERT INTO package_hold (id, organization_id, package, version) VALUES ($1, $2, 'nano', '0.9')", uuid.Must(uuid.NewV7()), w.org)
	w.mustCompile(statechange.ScopeOrg, w.org)
	b = w.fetch(d)
	if s := b.Software; s == nil || len(s.Packages) != 1 || s.Packages[0].Intent != bundle.SoftwareRequired || str(s.Packages[0].Version) != "0.9" ||
		len(s.Sources) != 1 {
		t.Fatalf("required latest with a package hold %+v", b.Software)
	}
	if h := holdsOf(b); len(h) != 2 || h["nano"] != "0.9" {
		t.Fatalf("required latest with a package hold: holds %v", h)
	}
}

// TestSoftwareSectionOmitted: no section for an entry without a package for the device's distribution, for a device
// outside every assignment, and for a v1 device; a report-only device gets it like its other sections.
func TestSoftwareSectionOmitted(t *testing.T) {
	w := newWorld(t)
	debian := w.entry("Debian only", nil, [4]string{"debian", "*", "*", "nano"})
	ubuntuEntry := w.entry("Nano", nil, [4]string{"ubuntu", "*", "*", "nano"})
	w.assign(debian, nil, "required", "latest", nil)
	w.assign(ubuntuEntry, w.g1, "required", "latest", nil)
	other, outside, v1, reportOnly := w.v2Device("{1,2}"), w.v2Device("{1,2}", w.g2), w.v2Device("{1}", w.g1), w.v2Device("{1,2}", w.g1)
	for _, d := range []uuid.UUID{other, outside, v1, reportOnly} {
		w.ubuntu(d, "amd64")
	}
	w.exec("UPDATE device SET enrollment_method = 'adopted', config_mode = 'report_only' WHERE id = $1", reportOnly)
	w.mustCompile(statechange.ScopeOrg, w.org)
	for name, d := range map[string]uuid.UUID{"debian entry only": other, "outside the group": outside, "v1": v1} {
		if s := w.fetch(d).Software; s != nil {
			t.Errorf("%s: software section %+v", name, s)
		}
	}
	b := w.fetch(reportOnly)
	if b.Mode != bundle.ModeReportOnly || b.Software == nil || len(b.Software.Packages) != 1 || b.Software.Packages[0].Package != "nano" {
		t.Fatalf("report-only device: mode %q software %+v", b.Mode, b.Software)
	}
}

// TestSoftwareSectionArchitecture: an exact architecture wins over "*", and a device without a reported architecture
// resolves "*" only.
func TestSoftwareSectionArchitecture(t *testing.T) {
	w := newWorld(t)
	e := w.entry("Editor", nil, [4]string{"ubuntu", "*", "*", "editor"}, [4]string{"ubuntu", "*", "amd64", "editor-amd64"},
		[4]string{"ubuntu", "24.04", "arm64", "editor-arm64"})
	w.assign(e, nil, "required", "latest", nil)
	amd, unknown := w.v2Device("{1,2}"), w.v2Device("{1,2}")
	w.ubuntu(amd, "amd64")
	w.ubuntu(unknown, "")
	w.mustCompile(statechange.ScopeOrg, w.org)
	for d, want := range map[uuid.UUID]string{amd: "editor-amd64", unknown: "editor"} {
		if s := w.fetch(d).Software; s == nil || len(s.Packages) != 1 || s.Packages[0].Package != want {
			t.Errorf("software section %+v, want %s", s, want)
		}
	}
}

// TestSoftwareSectionRelease (PDK-698): the release-specific reference wins over "*" for a device whose os-release is
// stored as enrollment stores it (lowercase keys); a device of another release gets the wildcard one.
func TestSoftwareSectionRelease(t *testing.T) {
	w := newWorld(t)
	e := w.entry("Editor", nil, [4]string{"ubuntu", "*", "*", "editor"}, [4]string{"ubuntu", "24.04", "*", "editor-noble"})
	w.assign(e, nil, "required", "latest", nil)
	noble, plucky := w.v2Device("{1,2}"), w.v2Device("{1,2}")
	w.osRelease(noble, "ubuntu", "24.04")
	w.osRelease(plucky, "ubuntu", "26.04")
	w.mustCompile(statechange.ScopeOrg, w.org)
	for d, want := range map[uuid.UUID]string{noble: "editor-noble", plucky: "editor"} {
		if s := w.fetch(d).Software; s == nil || len(s.Packages) != 1 || s.Packages[0].Package != want {
			t.Errorf("software section %+v, want %s", s, want)
		}
	}
}

// TestSoftwareSectionDeterministic: sources and packages are sorted by slug and package, independent of the order the
// rows were created in.
func TestSoftwareSectionDeterministic(t *testing.T) {
	w := newWorld(t)
	ed, rsa := loadSoftwareKey(t, "ed25519.asc"), loadSoftwareKey(t, "rsa.asc")
	zeta, alpha := w.source("zeta", ed, ed.fingerprint), w.source("alpha", rsa, rsa.fingerprint)
	for _, x := range []struct {
		name string
		src  uuid.UUID
		pkg  string
	}{{"Z", zeta, "zsh"}, {"A", alpha, "ack"}, {"M", zeta, "mc"}} {
		w.assign(w.entry(x.name, x.src, [4]string{"ubuntu", "*", "*", x.pkg}), nil, "required", "latest", nil)
	}
	d := w.v2Device("{1,2}")
	w.ubuntu(d, "amd64")
	w.mustCompile(statechange.ScopeOrg, w.org)
	s := w.fetch(d).Software
	if s == nil || len(s.Sources) != 2 || s.Sources[0].Slug != "alpha" || s.Sources[1].Slug != "zeta" ||
		len(s.Packages) != 3 || s.Packages[0].Package != "ack" || s.Packages[1].Package != "mc" || s.Packages[2].Package != "zsh" {
		t.Fatalf("software section %+v", s)
	}
	if err := bundle.ValidateSoftware(*s); err != nil {
		t.Fatal(err)
	}
}

// TestSoftwareSectionRefusesFailedSource: a stored source whose key no longer matches its fingerprint never reaches a
// bundle, and neither does a required package from it; other packages are unaffected.
func TestSoftwareSectionRefusesFailedSource(t *testing.T) {
	w := newWorld(t)
	key := loadSoftwareKey(t, "ed25519.asc")
	bad := w.source("tampered", key, mismatchingFingerprint(key.fingerprint))
	w.assign(w.entry("Bad", bad, [4]string{"ubuntu", "*", "*", "bad"}), nil, "required", "latest", nil)
	w.assign(w.entry("Held", bad, [4]string{"ubuntu", "*", "*", "held"}), nil, "hold", "latest", nil)
	w.assign(w.entry("Good", nil, [4]string{"ubuntu", "*", "*", "good"}), nil, "required", "latest", nil)
	d := w.v2Device("{1,2}")
	w.ubuntu(d, "amd64")
	w.mustCompile(statechange.ScopeOrg, w.org)
	s := w.fetch(d).Software
	if s == nil || len(s.Sources) != 0 || len(s.Packages) != 2 || s.Packages[0].Package != "good" || s.Packages[1].Package != "held" ||
		s.Packages[1].Source != "" {
		t.Fatalf("software section %+v", s)
	}
}

// TestSoftwareHoldsOutsideTheRolloutOverlay (plan M11 R2.10): a device outside the wave renders the before-state of
// the staged package holds, but the holds of its software assignments, which are not rollout-able, stay.
func TestSoftwareHoldsOutsideTheRolloutOverlay(t *testing.T) {
	w := newStagedWorld(t)
	e := w.entry("Nano", nil, [4]string{"ubuntu", "*", "*", "nano"})
	w.assign(e, nil, "required", "pinned", "1.0")
	w.ubuntu(w.in, "amd64")
	w.ubuntu(w.out, "amd64")
	w.mustCompile(statechange.ScopeOrg, w.org)
	if h := holdsOf(w.fetch(w.in)); len(h) != 2 || h["nano"] != "1.0" || h["openssl"] != "<nil>" {
		t.Fatalf("holds inside the wave %v", h)
	}
	if h := holdsOf(w.fetch(w.out)); len(h) != 1 || h["nano"] != "1.0" {
		t.Fatalf("holds outside the wave %v", h)
	}
}

// TestSoftwareRemovalSupersedesPackageHold (architect decision 2026-11-02): a forbid or uninstall result drops a
// package_hold of the same package from the device's updates section and marks the package superseded_hold; a
// required package keeps the hold; recompiling the same state publishes nothing new.
func TestSoftwareRemovalSupersedesPackageHold(t *testing.T) {
	w := newWorld(t)
	e := w.entry("Nano", nil, [4]string{"ubuntu", "*", "*", "nano"})
	a := w.assign(e, nil, "forbid", "latest", nil)
	w.exec("INSERT INTO package_hold (id, organization_id, package) VALUES ($1, $2, 'nano'), ($3, $2, 'openssl')",
		uuid.Must(uuid.NewV7()), w.org, uuid.Must(uuid.NewV7()))
	d := w.v2Device("{1,2}")
	w.ubuntu(d, "amd64")
	for _, intent := range []string{"forbid", "uninstall"} {
		w.exec("UPDATE software_assignment SET intent = $2 WHERE id = $1", a, intent)
		w.mustCompile(statechange.ScopeOrg, w.org)
		b := w.fetch(d)
		if s := b.Software; s == nil || len(s.Packages) != 1 || s.Packages[0].Intent != intent || !s.Packages[0].SupersededHold {
			t.Fatalf("%s: software section %+v", intent, b.Software)
		}
		if h := holdsOf(b); len(h) != 1 || h["openssl"] != "<nil>" {
			t.Fatalf("%s: holds %v", intent, h)
		}
		before := w.version(d)
		w.mustCompile(statechange.ScopeOrg, w.org)
		if w.version(d) != before {
			t.Fatalf("%s: an unchanged state published a new bundle", intent)
		}
	}
	w.exec("UPDATE software_assignment SET intent = 'required' WHERE id = $1", a)
	w.mustCompile(statechange.ScopeOrg, w.org)
	b := w.fetch(d)
	if s := b.Software; s == nil || s.Packages[0].SupersededHold || s.Packages[0].Version != nil {
		t.Fatalf("required: software section %+v", b.Software)
	}
	if h := holdsOf(b); len(h) != 2 || h["nano"] != "<nil>" {
		t.Fatalf("required: holds %v", h)
	}
	enc, err := bundle.Encode(*b)
	if err != nil || strings.Contains(string(enc), "superseded_hold") {
		t.Fatalf("superseded_hold present without a superseded hold: %s (%v)", enc, err)
	}
}

// TestSoftwareVersionlessHolds documents how a hold without a version meets a required pinned assignment (Fix Round 1,
// review L1): a versionless package_hold wins in updates.Merge (nil first), so the package is required at the
// installed version and held; a versionless software hold does not unpin it (MergeIntents counts named versions only).
func TestSoftwareVersionlessHolds(t *testing.T) {
	w := newWorld(t)
	pinned := w.entry("Nano", nil, [4]string{"ubuntu", "*", "*", "nano"})
	w.assign(pinned, nil, "required", "pinned", "1.0")
	held := w.entry("Nano hold", nil, [4]string{"ubuntu", "*", "*", "nano"})
	softwareHold := w.assign(held, nil, "hold", "latest", nil)
	d := w.v2Device("{1,2}")
	w.ubuntu(d, "amd64")
	w.mustCompile(statechange.ScopeOrg, w.org)
	b := w.fetch(d)
	if s := b.Software; s == nil || len(s.Packages) != 1 || s.Packages[0].Intent != bundle.SoftwareRequired || str(s.Packages[0].Version) != "1.0" {
		t.Fatalf("software hold: section %+v", b.Software)
	}
	if h := holdsOf(b); len(h) != 1 || h["nano"] != "1.0" {
		t.Fatalf("software hold: holds %v", h)
	}
	w.exec("DELETE FROM software_assignment WHERE id = $1", softwareHold)
	w.exec("INSERT INTO package_hold (id, organization_id, package) VALUES ($1, $2, 'nano')", uuid.Must(uuid.NewV7()), w.org)
	w.mustCompile(statechange.ScopeOrg, w.org)
	b = w.fetch(d)
	if s := b.Software; s == nil || s.Packages[0].Intent != bundle.SoftwareRequired || s.Packages[0].Version != nil {
		t.Fatalf("package hold: section %+v", b.Software)
	}
	if h := holdsOf(b); len(h) != 1 || h["nano"] != "<nil>" {
		t.Fatalf("package hold: holds %v", h)
	}
}

// TestSoftwareStoredSourceRechecked (Fix Round 1, review M1): a stored source that fails the current URI rule (U+FFFD,
// accepted by the upload before the rules were aligned) is left out together with the required package from it; the
// device still gets the valid rest.
func TestSoftwareStoredSourceRechecked(t *testing.T) {
	w := newWorld(t)
	key := loadSoftwareKey(t, "ed25519.asc")
	src := w.source("vendor", key, key.fingerprint)
	w.exec("UPDATE software_source SET uris = '{https://repo.example.com/\uFFFDapt}' WHERE id = $1", src)
	w.assign(w.entry("Vendor", src, [4]string{"ubuntu", "*", "*", "vendor-tool"}), nil, "required", "latest", nil)
	w.assign(w.entry("Good", nil, [4]string{"ubuntu", "*", "*", "good"}), nil, "required", "latest", nil)
	d := w.v2Device("{1,2}")
	w.ubuntu(d, "amd64")
	w.mustCompile(statechange.ScopeOrg, w.org)
	if s := w.fetch(d).Software; s == nil || len(s.Sources) != 0 || len(s.Packages) != 1 || s.Packages[0].Package != "good" {
		t.Fatalf("software section %+v", s)
	}
}

// renderFailures counts the device.bundle_render_failed events of dev whose reason contains what.
func (w *world) renderFailures(dev uuid.UUID, what string) int {
	w.t.Helper()
	var n int
	if err := w.super.QueryRow(context.Background(), `SELECT count(*) FROM action WHERE organization_id = $1
		AND code = 'device.bundle_render_failed' AND outcome = 'failure' AND target->>'id' = $2
		AND strpos(params->>'reason', $3) > 0`, w.org, dev.String(), what).Scan(&n); err != nil {
		w.t.Fatal(err)
	}
	return n
}

// TestSoftwareInvalidEntryFailsClosed (architect decision 2026-11-02, PDK-697): a forbid entry whose package
// references were corrupted outside the API is not skipped — a competing required assignment would lift the forbid.
// Every device the entry applies to keeps its previous bundle and the render failure names the entry; a device the
// entry does not apply to (another distribution) and the rest of the organization are compiled normally.
func TestSoftwareInvalidEntryFailsClosed(t *testing.T) {
	w := newWorld(t)
	forbidden := w.entry("Nano forbidden", nil, [4]string{"ubuntu", "*", "*", "nano"})
	w.assign(forbidden, w.g1, "forbid", "latest", nil)
	d, fedora := w.v2Device("{1,2}", w.g1), w.v2Device("{1,2}")
	w.ubuntu(d, "amd64")
	w.mustCompile(statechange.ScopeOrg, w.org)
	if s := w.fetch(d).Software; s == nil || s.Packages[0].Intent != bundle.SoftwareForbid {
		t.Fatalf("before: %+v", s)
	}
	before := w.version(d)

	w.exec(`UPDATE software_catalog_entry SET packages = '[{"distribution":"ubuntu","release":"*","architecture":"*","package":"nano"},
		{"distribution":"Debian!","release":"*","architecture":"*","package":"nano"}]' WHERE id = $1`, forbidden)
	w.assign(w.entry("Nano", nil, [4]string{"ubuntu", "*", "*", "nano"}), nil, "required", "latest", nil)
	w.osRelease(fedora, "fedora", "40")
	w.assign(w.entry("Fedora tool", nil, [4]string{"fedora", "*", "*", "tool"}), nil, "required", "latest", nil)
	fedoraBefore := w.version(fedora)
	w.mustCompile(statechange.ScopeOrg, w.org)
	if w.version(d) != before {
		t.Fatal("a bundle was published although an entry that applies to the device fails the catalog rules")
	}
	if s := w.fetch(d).Software; s == nil || len(s.Packages) != 1 || s.Packages[0].Intent != bundle.SoftwareForbid {
		t.Fatalf("the forbid was lifted: %+v", s)
	}
	if n := w.renderFailures(d, forbidden.String()); n != 1 {
		t.Fatalf("%d render failures naming the entry, want 1", n)
	}
	if w.version(fedora) != fedoraBefore+1 || w.fetch(fedora).Software == nil || w.renderFailures(fedora, forbidden.String()) != 0 {
		t.Fatal("a device the entry does not apply to was blocked")
	}

	w.exec(`UPDATE software_catalog_entry SET packages = '"not a list"' WHERE id = $1`, forbidden)
	w.exec("INSERT INTO device_group_member (organization_id, device_group_id, device_id) VALUES ($1, $2, $3)", w.org, w.g1, fedora)
	w.mustCompile(statechange.ScopeOrg, w.org)
	if w.version(d) != before || w.renderFailures(fedora, forbidden.String()) != 1 {
		t.Fatal("an invalid entry must block every device in the assignment's scope, whatever its distribution")
	}
}

// TestSoftwareEmptyEntryFailsClosed (PDK-410 external re-check): an entry whose references were emptied outside the
// API resolves nowhere, but skipping it would drop its organization-wide forbid; every device fails its render and
// the package another entry requires is not installed.
func TestSoftwareEmptyEntryFailsClosed(t *testing.T) {
	w := newWorld(t)
	empty := w.entry("Vim forbidden", nil, [4]string{"ubuntu", "*", "*", "vim"})
	w.assign(empty, nil, "forbid", "latest", nil)
	d := w.v2Device("{1,2}")
	w.ubuntu(d, "amd64")
	w.mustCompile(statechange.ScopeOrg, w.org)
	before := w.version(d)
	for i, packages := range []string{"[]", "null"} {
		w.exec("UPDATE software_catalog_entry SET packages = $2::jsonb WHERE id = $1", empty, packages)
		if i == 0 {
			w.assign(w.entry("Vim", nil, [4]string{"ubuntu", "*", "*", "vim"}), nil, "required", "latest", nil)
		}
		w.mustCompile(statechange.ScopeOrg, w.org)
		if w.version(d) != before || w.renderFailures(d, empty.String()) != i+1 {
			t.Fatalf("packages %s: version %d (before %d), the device must keep its previous bundle", packages, w.version(d), before)
		}
		if s := w.fetch(d).Software; s == nil || len(s.Packages) != 1 || s.Packages[0].Intent != bundle.SoftwareForbid {
			t.Fatalf("packages %s: vim must stay forbidden: %+v", packages, s)
		}
	}
}

// TestSoftwareProtectedResultFailsClosed: an assignment stored before the protected-package rules (forbid sudo, which
// paddock-agent depends on) yields a result the bundle contract refuses; the device keeps its previous bundle.
func TestSoftwareProtectedResultFailsClosed(t *testing.T) {
	w := newWorld(t)
	d := w.v2Device("{1,2}")
	w.ubuntu(d, "amd64")
	w.mustCompile(statechange.ScopeOrg, w.org)
	before := w.version(d)
	w.assign(w.entry("Sudo", nil, [4]string{"ubuntu", "*", "*", "sudo"}), nil, "forbid", "latest", nil)
	w.mustCompile(statechange.ScopeOrg, w.org)
	if w.version(d) != before || w.renderFailures(d, "protected") != 1 {
		t.Fatal("a forbid of a removal-protected package was published")
	}
}

// mismatchingFingerprint returns a well-formed fingerprint that differs from fp in its last hex digit.
func mismatchingFingerprint(fp string) string {
	last := byte('0')
	if fp[len(fp)-1] == '0' {
		last = '1'
	}
	return fp[:len(fp)-1] + string(last)
}

// userGroup inserts a user group with the given members.
func (w *world) userGroup(slug string, members ...uuid.UUID) uuid.UUID {
	w.t.Helper()
	id := uuid.Must(uuid.NewV7())
	w.exec("INSERT INTO user_group (id, organization_id, slug, name, source) VALUES ($1, $2, $3, $3, 'local')", id, w.org, slug)
	for _, m := range members {
		w.exec("INSERT INTO user_group_member (organization_id, group_id, user_id) VALUES ($1, $2, $3)", w.org, id, m)
	}
	return id
}

// own makes users owners of dev.
func (w *world) own(dev uuid.UUID, users ...uuid.UUID) {
	w.t.Helper()
	for _, u := range users {
		w.exec("INSERT INTO device_owner (organization_id, device_id, user_id) VALUES ($1, $2, $3)", w.org, dev, u)
	}
}

// assignTo inserts an assignment of entry to a user (column user_id) or a user group (column user_group_id).
func (w *world) assignTo(entry uuid.UUID, column string, target uuid.UUID, intent string) {
	w.t.Helper()
	w.exec(`INSERT INTO software_assignment (id, organization_id, catalog_entry_id, `+column+`, intent) VALUES ($1, $2, $3, $4, $5)`,
		uuid.Must(uuid.NewV7()), w.org, entry, target, intent)
}

// flathub inserts a Flatpak source with key k.
func (w *world) flathub(k softwareKey) uuid.UUID {
	w.t.Helper()
	id := uuid.Must(uuid.NewV7())
	w.exec(`INSERT INTO software_source (id, organization_id, kind, slug, name, uris, suites, components, signing_key, fingerprint)
		VALUES ($1, $2, 'flatpak', 'flathub', 'Flathub', '{https://dl.flathub.org/repo/}', '{}', '{}', $3, $4)`,
		id, w.org, k.armored, k.fingerprint)
	return id
}

// pkgOf returns the package or Flatpak application name of dev's software section, nil when absent.
func pkgOf(s *bundle.SoftwareSpec, name string) *bundle.SoftwarePackage {
	if s == nil {
		return nil
	}
	for i, p := range s.Packages {
		if p.Package == name || p.FlatpakRef == name {
			return &s.Packages[i]
		}
	}
	return nil
}

// audienceString renders an audience for comparison: "all", the sorted user names joined by ",", or "-" for none.
func audienceString(a *bundle.SoftwareAudience) string {
	switch {
	case a == nil:
		return "-"
	case a.All:
		return "all"
	}
	return strings.Join(a.Users, ",")
}

// TestSoftwareTargets (plan M13b decision 8, PDK-799): an organization or device-group target applies to the device
// with the audience everyone; a user target applies when the user owns the device, a user-group target when an owner
// is a member, with the audience of those owners only; a device without owners gets no user-targeted package; two
// assignments of one entry merge into the union or everyone; a required package through a user target applies to the
// device; an available package that loses against another intent carries no audience.
func TestSoftwareTargets(t *testing.T) {
	type assignment struct {
		target string // organization, g1, g2, alice, bob, carol, devs
		intent string
	}
	cases := []struct {
		name    string
		assign  []assignment
		owned   string // the owned device's intent and audience, "" when the package is absent
		unowned string // the same for the device without owners
	}{
		{"organization available", []assignment{{"organization", "available"}}, "available all", "available all"},
		{"device group available", []assignment{{"g1", "available"}}, "available all", "available all"},
		{"other device group available", []assignment{{"g2", "available"}}, "", ""},
		{"owner available", []assignment{{"alice", "available"}}, "available alice", ""},
		{"non-owner available", []assignment{{"bob", "available"}}, "", ""},
		{"user group available", []assignment{{"devs", "available"}}, "available alice", ""},
		{"user and group union", []assignment{{"carol", "available"}, {"devs", "available"}}, "available alice,carol", ""},
		{"organization wins the union", []assignment{{"alice", "available"}, {"organization", "available"}}, "available all", "available all"},
		{"owner required", []assignment{{"alice", "required"}}, "required -", ""},
		{"user group forbid", []assignment{{"devs", "forbid"}}, "forbid -", ""},
		{"forbid beats available", []assignment{{"alice", "available"}, {"g1", "forbid"}}, "forbid -", "forbid -"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := newWorld(t)
			alice, bob, carol := w.user("alice", false), w.user("bob", false), w.user("carol", false)
			devs := w.userGroup("devs", alice, bob)
			names := map[string]string{w.username(alice): "alice", w.username(carol): "carol", w.username(bob): "bob"}
			e := w.entry("Nano", nil, [4]string{"ubuntu", "*", "*", "nano"})
			for _, a := range c.assign {
				switch a.target {
				case "organization":
					w.assign(e, nil, a.intent, "latest", nil)
				case "g1":
					w.assign(e, w.g1, a.intent, "latest", nil)
				case "g2":
					w.assign(e, w.g2, a.intent, "latest", nil)
				case "devs":
					w.assignTo(e, "user_group_id", devs, a.intent)
				default:
					w.assignTo(e, "user_id", map[string]uuid.UUID{"alice": alice, "bob": bob, "carol": carol}[a.target], a.intent)
				}
			}
			owned, unowned := w.v2Device("{1,2}", w.g1), w.v2Device("{1,2}", w.g1)
			w.ubuntu(owned, "amd64")
			w.ubuntu(unowned, "amd64")
			w.own(owned, alice, carol)
			w.mustCompile(statechange.ScopeOrg, w.org)
			for _, d := range []struct {
				id   uuid.UUID
				want string
			}{{owned, c.owned}, {unowned, c.unowned}} {
				got := ""
				if p := pkgOf(w.fetch(d.id).Software, "nano"); p != nil {
					var users []string
					if p.Audience != nil {
						for _, u := range p.Audience.Users {
							users = append(users, names[u])
						}
					}
					aud := audienceString(p.Audience)
					if len(users) > 0 {
						aud = strings.Join(users, ",")
					}
					got = p.Intent + " " + aud
				}
				if got != d.want {
					t.Errorf("device %s: %q, want %q", d.id, got, d.want)
				}
			}
		})
	}
}

// TestSoftwareAudienceChangePublishes (plan M13b decision 7): a new owner changes the audience of an available
// package, so the recompiled bundle is a new version; a recompile without a change is not.
func TestSoftwareAudienceChangePublishes(t *testing.T) {
	w := newWorld(t)
	alice, bob := w.user("alice", false), w.user("bob", false)
	devs := w.userGroup("devs", alice, bob)
	w.assignTo(w.entry("Nano", nil, [4]string{"ubuntu", "*", "*", "nano"}), "user_group_id", devs, "available")
	d := w.v2Device("{1,2}", w.g1)
	w.ubuntu(d, "amd64")
	w.own(d, alice)
	w.mustCompile(statechange.ScopeOrg, w.org)
	before := w.version(d)
	w.mustCompile(statechange.ScopeDevice, d)
	if w.version(d) != before {
		t.Fatal("a recompile without a change published a new bundle")
	}
	w.own(d, bob)
	w.mustCompile(statechange.ScopeDevice, d)
	if w.version(d) == before {
		t.Fatal("a changed audience did not publish a new bundle")
	}
	if p := pkgOf(w.fetch(d).Software, "nano"); p == nil || audienceString(p.Audience) != w.username(alice)+","+w.username(bob) {
		t.Fatalf("package %+v", p)
	}
}

// TestSoftwareAudienceTruncated (plan M13b R2, decision Q13): an audience over bundle.MaxSoftwareAudience users keeps
// the first ones by user name, and the bundle is still published.
func TestSoftwareAudienceTruncated(t *testing.T) {
	w := newWorld(t)
	d := w.v2Device("{1,2}", w.g1)
	w.ubuntu(d, "amd64")
	users := make([]uuid.UUID, bundle.MaxSoftwareAudience+1)
	for i := range users {
		users[i] = w.user(fmt.Sprintf("u%03d", i), false)
	}
	w.own(d, users...)
	w.assignTo(w.entry("Nano", nil, [4]string{"ubuntu", "*", "*", "nano"}), "user_group_id", w.userGroup("all", users...), "available")
	w.mustCompile(statechange.ScopeOrg, w.org)
	p := pkgOf(w.fetch(d).Software, "nano")
	if p == nil || p.Audience == nil || len(p.Audience.Users) != bundle.MaxSoftwareAudience ||
		p.Audience.Users[0] != w.username(users[0]) || slices.Contains(p.Audience.Users, w.username(users[bundle.MaxSoftwareAudience])) {
		t.Fatalf("package %+v", p)
	}
}

// TestSoftwareFlatpak (plan M13b decisions 8 and 9, decision Q12): a Flatpak application renders flatpak_ref, scope
// and its remote; the section then requires the flatpak package once from the distribution's repositories with the
// nil entry ID, unless an entry names the package itself.
func TestSoftwareFlatpak(t *testing.T) {
	w := newWorld(t)
	key := loadSoftwareKey(t, "ed25519.asc")
	flathub := w.flathub(key)
	gimp := uuid.Must(uuid.NewV7())
	w.exec(`INSERT INTO software_catalog_entry (id, organization_id, name, source_id, packages) VALUES ($1, $2, 'GIMP', $3,
		'[{"distribution":"ubuntu","release":"*","architecture":"*","flatpak_ref":"org.gimp.GIMP","scope":"user"}]')`,
		gimp, w.org, flathub)
	inkscape := uuid.Must(uuid.NewV7())
	w.exec(`INSERT INTO software_catalog_entry (id, organization_id, name, source_id, packages) VALUES ($1, $2, 'Inkscape', $3,
		'[{"distribution":"ubuntu","release":"*","architecture":"*","flatpak_ref":"org.inkscape.Inkscape"}]')`,
		inkscape, w.org, flathub)
	w.assign(gimp, nil, "available", "latest", nil)
	w.assign(inkscape, w.g1, "required", "latest", nil)
	d := w.v2Device("{1,2}", w.g1)
	w.ubuntu(d, "amd64")
	w.mustCompile(statechange.ScopeOrg, w.org)

	s := w.fetch(d).Software
	if s == nil || len(s.Sources) != 1 || s.Sources[0].Slug != "flathub" || s.Sources[0].Kind != bundle.SoftwareSourceFlatpak ||
		len(s.Sources[0].URIs) != 1 || len(s.Sources[0].Suites) != 0 || s.Sources[0].Fingerprint != key.fingerprint {
		t.Fatalf("sources %+v", s)
	}
	if p := pkgOf(s, "org.gimp.GIMP"); p == nil || p.Package != "" || p.Scope != "user" || p.Source != "flathub" ||
		p.Intent != bundle.SoftwareAvailable || audienceString(p.Audience) != "all" || p.CatalogEntryID != gimp.String() {
		t.Fatalf("gimp %+v", p)
	}
	if p := pkgOf(s, "org.inkscape.Inkscape"); p == nil || p.Scope != "system" || p.Source != "flathub" || p.Intent != bundle.SoftwareRequired {
		t.Fatalf("inkscape %+v", p)
	}
	runtimes := 0
	for _, p := range s.Packages {
		if p.Package == "flatpak" {
			runtimes++
			if p.Intent != bundle.SoftwareRequired || p.Source != "" || p.CatalogEntryID != bundle.SoftwareRuntimeEntryID || p.Version != nil {
				t.Fatalf("runtime %+v", p)
			}
		}
	}
	if runtimes != 1 || len(s.Packages) != 3 {
		t.Fatalf("%d flatpak runtime packages in %+v, want 1 of 3 packages", runtimes, s.Packages)
	}
	if hb := holdsOf(w.fetch(d)); len(hb) != 0 {
		t.Fatalf("holds %v", hb)
	}

	own := w.entry("Flatpak", nil, [4]string{"ubuntu", "*", "*", "flatpak"})
	w.assign(own, nil, "required", "latest", nil)
	w.mustCompile(statechange.ScopeOrg, w.org)
	if p := pkgOf(w.fetch(d).Software, "flatpak"); p == nil || p.CatalogEntryID != own.String() || len(w.fetch(d).Software.Packages) != 3 {
		t.Fatalf("an entry naming flatpak: %+v", p)
	}
}

// TestSoftwareNoFlatpakRuntimeWithoutFlatpak: a section without a Flatpak source does not get the flatpak package,
// even when the organization has a Flatpak source that no package of the device needs.
func TestSoftwareNoFlatpakRuntimeWithoutFlatpak(t *testing.T) {
	w := newWorld(t)
	w.flathub(loadSoftwareKey(t, "ed25519.asc"))
	w.assign(w.entry("Nano", nil, [4]string{"ubuntu", "*", "*", "nano"}), nil, "required", "latest", nil)
	d := w.v2Device("{1,2}", w.g1)
	w.ubuntu(d, "amd64")
	w.mustCompile(statechange.ScopeOrg, w.org)
	if s := w.fetch(d).Software; s == nil || len(s.Packages) != 1 || len(s.Sources) != 0 {
		t.Fatalf("software section %+v", s)
	}
}

// TestSoftwareStrayFlatpakRefFailsClosed (PDK-798 review 1, PDK-697): only a valid entry of a Flatpak source stays out
// of the bundle until PDK-799. A flatpak_ref stored outside the API on an entry of an APT source or of the
// distribution's repositories, or a Flatpak entry whose references fail the catalog rules, is invalid: the forbid it
// carries is not lifted by skipping it, the device keeps its previous bundle and the render failure names the entry.
func TestSoftwareStrayFlatpakRefFailsClosed(t *testing.T) {
	cases := []struct {
		name     string
		source   func(w *world, key softwareKey) any
		packages string
	}{
		{"distribution repositories", func(*world, softwareKey) any { return nil },
			`[{"distribution":"ubuntu","release":"*","architecture":"*","package":"nano","flatpak_ref":"a.b.C"}]`},
		{"apt source", func(w *world, key softwareKey) any { return w.source("vendor", key, key.fingerprint) },
			`[{"distribution":"ubuntu","release":"*","architecture":"*","package":"nano","flatpak_ref":"a.b.C"}]`},
		{"flatpak source without flatpak_ref", func(w *world, key softwareKey) any {
			id := uuid.Must(uuid.NewV7())
			w.exec(`INSERT INTO software_source (id, organization_id, kind, slug, name, uris, suites, components, signing_key, fingerprint)
				VALUES ($1, $2, 'flatpak', 'flathub', 'Flathub', '{https://dl.flathub.org/repo/}', '{}', '{}', $3, $4)`,
				id, w.org, key.armored, key.fingerprint)
			return id
		}, `[{"distribution":"ubuntu","release":"*","architecture":"*","package":"nano"}]`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := newWorld(t)
			key := loadSoftwareKey(t, "ed25519.asc")
			forbidden := w.entry("Nano forbidden", nil, [4]string{"ubuntu", "*", "*", "nano"})
			w.assign(forbidden, w.g1, "forbid", "latest", nil)
			w.assign(w.entry("Nano", nil, [4]string{"ubuntu", "*", "*", "nano"}), nil, "required", "latest", nil)
			d := w.v2Device("{1,2}", w.g1)
			w.ubuntu(d, "amd64")
			w.mustCompile(statechange.ScopeOrg, w.org)
			if s := w.fetch(d).Software; s == nil || len(s.Packages) != 1 || s.Packages[0].Intent != bundle.SoftwareForbid {
				t.Fatalf("before: %+v", s)
			}
			before := w.version(d)

			w.exec("UPDATE software_catalog_entry SET source_id = $2, packages = $3::jsonb WHERE id = $1",
				forbidden, c.source(w, key), c.packages)
			w.mustCompile(statechange.ScopeOrg, w.org)
			if w.version(d) != before {
				t.Fatal("a bundle was published although the entry with a stray flatpak_ref applies to the device")
			}
			if s := w.fetch(d).Software; s == nil || len(s.Packages) != 1 || s.Packages[0].Intent != bundle.SoftwareForbid {
				t.Fatalf("the forbid was lifted: %+v", s)
			}
			if n := w.renderFailures(d, forbidden.String()); n != 1 {
				t.Fatalf("%d render failures naming the entry, want 1", n)
			}
		})
	}
}

// flatpakEntry inserts a catalog entry of the Flatpak source src with application ref in the system scope.
func (w *world) flatpakEntry(name string, src uuid.UUID, ref string) uuid.UUID {
	w.t.Helper()
	id := uuid.Must(uuid.NewV7())
	w.exec(`INSERT INTO software_catalog_entry (id, organization_id, name, source_id, packages) VALUES ($1, $2, $3, $4,
		jsonb_build_array(jsonb_build_object('distribution', 'ubuntu', 'release', '*', 'architecture', '*', 'flatpak_ref', $5::text)))`,
		id, w.org, name, src, ref)
	return id
}

// agentAt makes dev report agent version v.
func (w *world) agentAt(dev uuid.UUID, v string) {
	w.t.Helper()
	w.exec("UPDATE device_status SET agent_version = $2 WHERE device_id = $1", dev, v)
}

// alpha9Software is the software section as the alpha.9 agent decodes it (pkg/bundle at v0.1.0-alpha.9), frozen
// here: a field outside it is one the alpha.9 agent does not know.
type alpha9Software struct {
	Sources []struct {
		Slug          string   `json:"slug"`
		URIs          []string `json:"uris"`
		Suites        []string `json:"suites"`
		Components    []string `json:"components"`
		Architectures []string `json:"architectures"`
		Keyring       string   `json:"keyring"`
		Fingerprint   string   `json:"fingerprint"`
	} `json:"sources"`
	Packages []struct {
		Package        string  `json:"package"`
		Intent         string  `json:"intent"`
		Version        *string `json:"version"`
		Source         string  `json:"source"`
		CatalogEntryID string  `json:"catalog_entry_id"`
		SupersededHold bool    `json:"superseded_hold,omitempty"`
	} `json:"packages"`
}

// alpha9Accepts reports why the alpha.9 agent would refuse a software section, nil when it accepts it. The section
// must carry only the fields of alpha9Software, and those must pass a9ValidateSoftware, the alpha.9
// bundle.ValidateSoftware frozen in alpha9_software_test.go.
func alpha9Accepts(raw []byte) error {
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	var old alpha9Software
	if err := dec.Decode(&old); err != nil {
		return fmt.Errorf("decode as alpha.9: %w", err)
	}
	return a9ValidateSoftware(old)
}

// alpha9FixtureSoftware is the software section of the alpha.9 compat fixture's schema-2 bundle (pkg/compat), what
// the alpha.9 server put on the wire.
func alpha9FixtureSoftware(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile("../../../pkg/compat/testdata/0.1.0-alpha.9/" + compat.BundleFile(bundle.SchemaVersion2))
	if err != nil {
		t.Fatal(err)
	}
	var env struct {
		Payload []byte `json:"payload"`
	}
	var b struct {
		Software json.RawMessage `json:"software"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(env.Payload, &b); err != nil || len(b.Software) == 0 {
		t.Fatalf("fixture software section: %v", err)
	}
	return b.Software
}

// TestSoftwareOlderAgentGated (architect decision A10-6, plan M13b C5): an agent release before the first one that
// reads available packages and Flatpak gets neither, nor a Flatpak remote or the flatpak runtime, and keeps its
// required, forbid and uninstall APT packages, in a section the frozen alpha.9 bundle.ValidateSoftware accepts (checked
// against the alpha.9 compat fixture); the newer agent gets everything, which alpha.9 would refuse.
func TestSoftwareOlderAgentGated(t *testing.T) {
	fixture := alpha9FixtureSoftware(t)
	if err := alpha9Accepts(fixture); err != nil {
		t.Fatalf("the alpha.9 check refuses the alpha.9 fixture: %v", err)
	}

	w := newWorld(t)
	key := loadSoftwareKey(t, "ed25519.asc")
	vendor := w.source("vendor", key, key.fingerprint)
	flathub := w.flathub(key)
	w.assign(w.entry("Nano", vendor, [4]string{"ubuntu", "*", "*", "nano"}), nil, "required", "latest", nil)
	w.assign(w.entry("Telnet", nil, [4]string{"ubuntu", "*", "*", "telnet"}), nil, "forbid", "latest", nil)
	w.assign(w.entry("Ftp", nil, [4]string{"ubuntu", "*", "*", "ftp"}), nil, "uninstall", "latest", nil)
	w.assign(w.entry("Htop", vendor, [4]string{"ubuntu", "*", "*", "htop"}), nil, "available", "latest", nil)
	w.assign(w.flatpakEntry("GIMP", flathub, "org.gimp.GIMP"), nil, "required", "latest", nil)
	w.assign(w.flatpakEntry("Inkscape", flathub, "org.inkscape.Inkscape"), nil, "available", "latest", nil)
	w.assign(w.flatpakEntry("Steam", flathub, "com.valvesoftware.Steam"), nil, "forbid", "latest", nil)
	devices := map[string]uuid.UUID{}
	for _, v := range []string{"0.1.0-alpha.8", "0.1.0-alpha.9", "0.1.0-alpha.9+build.1", "0.1.0-alpha.10", "0.1.0-alpha.11"} {
		d := w.v2Device("{1,2}", w.g1)
		w.ubuntu(d, "amd64")
		w.agentAt(d, v)
		devices[v] = d
	}
	w.mustCompile(statechange.ScopeOrg, w.org)

	names := func(s *bundle.SoftwareSpec) (string, string) {
		var pkgs, srcs []string
		for _, p := range s.Packages {
			pkgs = append(pkgs, p.Package+p.FlatpakRef+"="+p.Intent)
		}
		for _, src := range s.Sources {
			srcs = append(srcs, src.Slug)
		}
		return strings.Join(pkgs, " "), strings.Join(srcs, " ")
	}
	const (
		oldPackages = "ftp=uninstall nano=required telnet=forbid"
		newPackages = "flatpak=required com.valvesoftware.Steam=forbid org.gimp.GIMP=required org.inkscape.Inkscape=available " +
			"ftp=uninstall htop=available nano=required telnet=forbid"
	)
	for v, d := range devices {
		s := w.fetch(d).Software
		if s == nil {
			t.Fatalf("%s: no software section", v)
		}
		raw, err := json.Marshal(s)
		if err != nil {
			t.Fatal(err)
		}
		pkgs, srcs := names(s)
		if v == "0.1.0-alpha.10" || v == "0.1.0-alpha.11" {
			if pkgs != newPackages || srcs != "flathub vendor" {
				t.Errorf("%s: packages %q sources %q, want everything", v, pkgs, srcs)
			}
			if alpha9Accepts(raw) == nil {
				t.Errorf("%s: the alpha.9 check accepts the full section; it no longer proves the gate", v)
			}
			continue
		}
		if pkgs != oldPackages || srcs != "vendor" {
			t.Errorf("%s: packages %q sources %q, want %q from vendor", v, pkgs, srcs, oldPackages)
		}
		if err := alpha9Accepts(raw); err != nil {
			t.Errorf("%s: the alpha.9 agent refuses the section: %v", v, err)
		}
	}
}

// TestSoftwareReconcileFollowsAgentGate (A10-6, review 2 of PDK-799): the reconcile loop recompiles a device whose
// agent version changed since its latest compile, so an upgrade past the gate gains the available and Flatpak content
// and a rollback below it drops them again, in a section the frozen alpha.9 rules accept. An unchanged version
// recompiles nothing.
func TestSoftwareReconcileFollowsAgentGate(t *testing.T) {
	w := newWorld(t)
	key := loadSoftwareKey(t, "ed25519.asc")
	vendor := w.source("vendor", key, key.fingerprint)
	flathub := w.flathub(key)
	w.assign(w.entry("Nano", vendor, [4]string{"ubuntu", "*", "*", "nano"}), nil, "required", "latest", nil)
	w.assign(w.entry("Htop", vendor, [4]string{"ubuntu", "*", "*", "htop"}), nil, "available", "latest", nil)
	w.assign(w.flatpakEntry("GIMP", flathub, "org.gimp.GIMP"), nil, "required", "latest", nil)
	d := w.v2Device("{1,2}", w.g1)
	w.ubuntu(d, "amd64")
	w.agentAt(d, "0.1.0-alpha.9")
	w.mustCompile(statechange.ScopeOrg, w.org)

	reconcile := func() {
		t.Helper()
		if err := w.comp.Reconcile(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	check := func(when string, full bool) {
		t.Helper()
		s := w.fetch(d).Software
		if s == nil {
			t.Fatalf("%s: no software section", when)
		}
		raw, err := json.Marshal(s)
		if err != nil {
			t.Fatal(err)
		}
		gained := pkgOf(s, "htop") != nil && pkgOf(s, "org.gimp.GIMP") != nil && pkgOf(s, "flatpak") != nil
		if full != gained || pkgOf(s, "nano") == nil {
			t.Fatalf("%s: packages %+v, want self-service content %v", when, s.Packages, full)
		}
		if accepted := alpha9Accepts(raw) == nil; accepted == full {
			t.Fatalf("%s: the alpha.9 agent accepts the section: %v, want %v", when, accepted, !full)
		}
	}
	check("compiled at alpha.9", false)
	version := w.version(d)
	reconcile()
	if w.version(d) != version {
		t.Fatal("a reconcile without an agent change published a bundle")
	}

	w.agentAt(d, "0.1.0-alpha.10")
	reconcile()
	check("upgraded to alpha.10", true)
	if w.version(d) != version+1 {
		t.Fatalf("upgrade: version %d, want %d", w.version(d), version+1)
	}
	reconcile()
	if w.version(d) != version+1 {
		t.Fatal("the upgrade is recompiled again")
	}

	w.agentAt(d, "0.1.0-alpha.9")
	reconcile()
	check("rolled back to alpha.9", false)
	if w.version(d) != version+2 {
		t.Fatalf("rollback: version %d, want %d", w.version(d), version+2)
	}
}

// TestSoftwareFlatpakRemovalBringsNoRemote (architect decision A10-7): a Flatpak forbid or uninstall acts only where
// Flatpak is present: it names no source, and the section has neither the remote nor the flatpak runtime. A Flatpak
// source that fails the source rules does not lift the forbid.
func TestSoftwareFlatpakRemovalBringsNoRemote(t *testing.T) {
	w := newWorld(t)
	key := loadSoftwareKey(t, "ed25519.asc")
	flathub := w.flathub(key)
	steam := w.flatpakEntry("Steam", flathub, "com.valvesoftware.Steam")
	w.assign(steam, nil, "forbid", "latest", nil)
	w.assign(w.flatpakEntry("GIMP", flathub, "org.gimp.GIMP"), w.g1, "uninstall", "latest", nil)
	d := w.v2Device("{1,2}", w.g1)
	w.ubuntu(d, "amd64")
	w.mustCompile(statechange.ScopeOrg, w.org)
	check := func(when string) {
		t.Helper()
		s := w.fetch(d).Software
		if s == nil || len(s.Sources) != 0 || len(s.Packages) != 2 || pkgOf(s, "flatpak") != nil {
			t.Fatalf("%s: software section %+v", when, s)
		}
		for ref, intent := range map[string]string{"com.valvesoftware.Steam": bundle.SoftwareForbid, "org.gimp.GIMP": bundle.SoftwareUninstall} {
			if p := pkgOf(s, ref); p == nil || p.Intent != intent || p.Source != "" {
				t.Fatalf("%s: %s %+v", when, ref, p)
			}
		}
	}
	check("valid source")

	before := w.version(d)
	w.exec("UPDATE software_source SET fingerprint = $2 WHERE id = $1", flathub, mismatchingFingerprint(key.fingerprint))
	w.assign(w.entry("Nano", nil, [4]string{"ubuntu", "*", "*", "nano"}), nil, "required", "latest", nil)
	w.mustCompile(statechange.ScopeOrg, w.org)
	if w.version(d) == before {
		t.Fatal("a failed Flatpak source blocked the bundle of a device with a Flatpak forbid")
	}
	if p := pkgOf(w.fetch(d).Software, "nano"); p == nil {
		t.Fatal("the recompiled bundle lacks nano")
	}
	if p := pkgOf(w.fetch(d).Software, "com.valvesoftware.Steam"); p == nil || p.Intent != bundle.SoftwareForbid {
		t.Fatalf("the failed source lifted the forbid: %+v", p)
	}
}

// namedUser inserts a user with user name username.
func (w *world) namedUser(username string) uuid.UUID {
	w.t.Helper()
	id := uuid.Must(uuid.NewV7())
	w.exec("INSERT INTO app_user (id, organization_id, authentik_pk, username, source) VALUES ($1, $2, $3, $4, 'local')",
		id, w.org, "pk-"+id.String(), username)
	return id
}

// TestSoftwareAudienceUserNames (PDK-799 review 1): an owner with a 256-character UPN, the longest app_user allows,
// is in the audience; an owner whose stored name an audience cannot carry is left out instead of failing the bundle,
// and an available package whose audience is left with nobody is not offered. The device's bundle is published.
func TestSoftwareAudienceUserNames(t *testing.T) {
	w := newWorld(t)
	long := strings.Repeat("a", 256-len("@c.test")) + "@c.test"
	alice, spaced, bob := w.namedUser(long), w.namedUser("bad user@c.test"), w.namedUser("bob@c.test")
	nano := w.entry("Nano", nil, [4]string{"ubuntu", "*", "*", "nano"})
	w.assignTo(nano, "user_group_id", w.userGroup("devs", alice, spaced), "available")
	w.assignTo(w.entry("Htop", nil, [4]string{"ubuntu", "*", "*", "htop"}), "user_id", spaced, "available")
	w.assignTo(w.entry("Vim", nil, [4]string{"ubuntu", "*", "*", "vim"}), "user_id", spaced, "required")
	w.assign(w.entry("Tree", nil, [4]string{"ubuntu", "*", "*", "tree"}), nil, "required", "latest", nil)
	d := w.v2Device("{1,2}", w.g1)
	w.ubuntu(d, "amd64")
	w.own(d, alice, spaced, bob)
	w.mustCompile(statechange.ScopeOrg, w.org)
	if w.version(d) == 0 {
		t.Fatal("no bundle was published")
	}
	s := w.fetch(d).Software
	if p := pkgOf(s, "nano"); p == nil || audienceString(p.Audience) != long {
		t.Fatalf("nano %+v", p)
	}
	if p := pkgOf(s, "htop"); p != nil {
		t.Fatalf("htop is offered to nobody but rendered: %+v", p)
	}
	if p := pkgOf(s, "vim"); p == nil || p.Intent != bundle.SoftwareRequired {
		t.Fatalf("a required package of the owner with the uncarried name: %+v", p)
	}
}
