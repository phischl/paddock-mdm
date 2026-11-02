package compiler_test

import (
	"encoding/base64"
	"encoding/json"
	"os"
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

// ubuntu makes dev an Ubuntu 24.04 device with the reported architecture arch.
func (w *world) ubuntu(dev uuid.UUID, arch string) {
	w.t.Helper()
	w.exec(`UPDATE device SET os_release = '{"ID":"ubuntu","VERSION_ID":"24.04"}' WHERE id = $1`, dev)
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
	bad := w.source("tampered", key, "0123456789ABCDEF0123456789ABCDEF01234567")
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
