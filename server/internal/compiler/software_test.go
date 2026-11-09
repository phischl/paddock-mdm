package compiler_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/pkg/bundle"
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

// TestSoftwareSelfServiceRowsLeftOut (plan M13b §3.2, PDK-798): until the compiler renders them (PDK-799), a user or
// user-group target, the available intent and a Flatpak source with its entry leave the bundle as it is: a forbid
// targeted at one user never applies to every device of the organization, and none of these rows fails a bundle.
func TestSoftwareSelfServiceRowsLeftOut(t *testing.T) {
	w := newWorld(t)
	key := loadSoftwareKey(t, "ed25519.asc")
	user, group := uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())
	w.exec("INSERT INTO app_user (id, organization_id, username, source) VALUES ($1, $2, 'alice@example.org', 'local')", user, w.org)
	w.exec("INSERT INTO user_group (id, organization_id, slug, name, source) VALUES ($1, $2, 'devs', 'Devs', 'local')", group, w.org)
	nano := w.entry("Nano", nil, [4]string{"ubuntu", "*", "*", "nano"})
	vim := w.entry("Vim", nil, [4]string{"ubuntu", "*", "*", "vim"})
	flathub := uuid.Must(uuid.NewV7())
	w.exec(`INSERT INTO software_source (id, organization_id, kind, slug, name, uris, suites, components, signing_key, fingerprint)
		VALUES ($1, $2, 'flatpak', 'flathub', 'Flathub', '{https://dl.flathub.org/repo/}', '{}', '{}', $3, $4)`,
		flathub, w.org, key.armored, key.fingerprint)
	gimp := uuid.Must(uuid.NewV7())
	w.exec(`INSERT INTO software_catalog_entry (id, organization_id, name, source_id, packages) VALUES ($1, $2, 'GIMP', $3,
		'[{"distribution":"ubuntu","release":"*","architecture":"*","flatpak_ref":"org.gimp.GIMP","scope":"system"}]')`,
		gimp, w.org, flathub)
	w.exec(`INSERT INTO software_assignment (id, organization_id, catalog_entry_id, user_id, intent) VALUES ($1, $2, $3, $4, 'forbid')`,
		uuid.Must(uuid.NewV7()), w.org, nano, user)
	w.exec(`INSERT INTO software_assignment (id, organization_id, catalog_entry_id, user_group_id, intent) VALUES ($1, $2, $3, $4, 'required')`,
		uuid.Must(uuid.NewV7()), w.org, vim, group)
	w.assign(vim, nil, "available", "latest", nil)
	w.assign(gimp, nil, "required", "latest", nil)
	w.assign(nano, nil, "required", "latest", nil)
	d := w.v2Device("{1,2}", w.g1)
	w.ubuntu(d, "amd64")
	w.mustCompile(statechange.ScopeOrg, w.org)

	s := w.fetch(d).Software
	if s == nil || len(s.Packages) != 1 || s.Packages[0].Package != "nano" || s.Packages[0].Intent != bundle.SoftwareRequired ||
		len(s.Sources) != 0 {
		t.Fatalf("software section %+v, want only the organization's required nano", s)
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
