package acceptance

import (
	"encoding/json"
	"net/http"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/pkg/bundle"
	"github.com/phischl/paddock-mdm/pkg/openpgpkey"
	"github.com/phischl/paddock-mdm/test/acceptance/devicesim"
	"github.com/phischl/paddock-mdm/test/acceptance/internal/env"
)

// gatePackage is the package name the software gates assign; no devicesim installs anything.
const gatePackage = "paddock-gate-app"

// rotatedSourceKey is a second public key for a key change: the server's RSA 3072 domain fixture, with its
// fingerprint computed here, so that no fingerprint is written down twice.
func rotatedSourceKey(t *testing.T) (key, fingerprint string) {
	t.Helper()
	armored, err := os.ReadFile("../../server/internal/domain/software/testdata/rsa3072.asc")
	if err != nil {
		t.Fatal(err)
	}
	fp, _, err := openpgpkey.Fingerprint(armored)
	if err != nil {
		t.Fatal(err)
	}
	if fp == gateSourceFP {
		t.Fatalf("the rotated key has the fingerprint of the first key %s", fp)
	}
	return string(armored), fp
}

// gateSource creates a source as a stepped-up administrator and deletes it when the test ends; it returns the
// source's ID and slug.
func gateSource(t *testing.T, s stepper, prefix string) (id, slug string) {
	t.Helper()
	s.stepUp(t)
	body := sourceBody(prefix)
	res := call(t, s.Portal, http.MethodPost, softwareSources, body)
	expectStatus(t, res, http.StatusCreated, "")
	id = responseID(t, res).String()
	deleteSourceOnCleanup(t, s.Portal, s.stepUp, softwareSources+"/"+id)
	return id, body["slug"].(string)
}

// gateEntry creates a catalog entry of packages (from source, "" for the distribution's) and deletes it when the
// test ends.
func gateEntry(t *testing.T, p *env.Portal, source string, packages ...map[string]any) string {
	t.Helper()
	body := map[string]any{"name": "sw-gate-" + uniqueSuffix(), "packages": packages}
	if source != "" {
		body["source_id"] = source
	}
	res := call(t, p, http.MethodPost, softwareCatalog, body)
	expectStatus(t, res, http.StatusCreated, "")
	return createdID(t, p, softwareCatalog, res)
}

// packageRef is one package name of a catalog entry.
func packageRef(distribution, release, pkg string) map[string]any {
	return map[string]any{"distribution": distribution, "release": release, "architecture": "*", "package": pkg}
}

// TestSoftwareSources (plan M13a §9, AC-1 to AC-3, AC-11): adding a source needs org_admin with a fresh step-up and
// records its fingerprint; a session without step-up and an API token are refused with a denied event; http URIs
// and a mismatching fingerprint are refused; a key change records both fingerprints; a source a catalog entry uses
// cannot be deleted. The audit-once cases of the three source codes are in audit_once_software_test.go, the list
// contract in list_contract_test.go and the isolation gate in isolation_fixtures_test.go.
func TestSoftwareSources(t *testing.T) {
	alice := login(t, env.Alice)
	admin := adminUser(t, "sw-source")
	s := adminStepper(admin)

	s.stepUp(t)
	body := sourceBody("sw-src")
	res := call(t, admin.Portal, http.MethodPost, softwareSources, body)
	expectStatus(t, res, http.StatusCreated, "")
	id := responseID(t, res).String()
	path := softwareSources + "/" + id
	deleteSourceOnCleanup(t, admin.Portal, s.stepUp, path)
	if ev := expectOneEvent(t, alice, res.RequestID, "software_source.created", "success"); ev.Params["fingerprint"] != gateSourceFP {
		t.Fatalf("software_source.created params %v, want fingerprint %s", ev.Params, gateSourceFP)
	}

	t.Run("list without the key", func(t *testing.T) {
		res := call(t, alice, http.MethodGet, softwareSources+"?page_size=100&q="+body["slug"].(string), nil)
		expectStatus(t, res, http.StatusOK, "")
		var page struct {
			Items []map[string]any `json:"items"`
		}
		if err := res.JSON(&page); err != nil {
			t.Fatal(err)
		}
		i := slices.IndexFunc(page.Items, func(it map[string]any) bool { return it["id"] == id })
		if i < 0 {
			t.Fatalf("source %s not listed: %s", id, res.Body)
		}
		if _, ok := page.Items[i]["signing_key"]; ok || page.Items[i]["fingerprint"] != gateSourceFP {
			t.Fatalf("listed source %v: want the fingerprint and no signing_key", page.Items[i])
		}
		var one map[string]any
		res = call(t, alice, http.MethodGet, path, nil)
		expectStatus(t, res, http.StatusOK, "")
		if err := res.JSON(&one); err != nil || !strings.Contains(one["signing_key"].(string), "BEGIN PGP PUBLIC KEY BLOCK") {
			t.Fatalf("GET %s: %v %s", path, err, res.Body)
		}
	})

	t.Run("refused without step-up", func(t *testing.T) {
		expectRefusal(t, alice, call(t, withoutStepUp(t, admin), http.MethodPost, softwareSources, sourceBody("sw-src")),
			http.StatusForbidden, "step_up_required", "software_source.created")
	})

	t.Run("refused for an API token", func(t *testing.T) {
		token := tokenPortal(t, createAPIToken(t, login(t, env.Alice), env.Alice, "org_admin").Secret)
		expectRefusal(t, alice, call(t, token, http.MethodPost, softwareSources, sourceBody("sw-src")),
			http.StatusForbidden, "step_up_required", "software_source.created")
	})

	t.Run("https only", func(t *testing.T) {
		s.stepUp(t)
		b := sourceBody("sw-src")
		b["uris"] = []string{"http://apt.gates.example/"}
		res := call(t, admin.Portal, http.MethodPost, softwareSources, b)
		expectStatus(t, res, http.StatusBadRequest, "invalid_request")
		if d := problemDetail(t, res); !strings.Contains(d, "https") {
			t.Fatalf("detail %q does not name https", d)
		}
	})

	t.Run("fingerprint mismatch", func(t *testing.T) {
		s.stepUp(t)
		b := sourceBody("sw-src")
		b["fingerprint"] = strings.Repeat("0", 40)
		res := call(t, admin.Portal, http.MethodPost, softwareSources, b)
		expectStatus(t, res, http.StatusUnprocessableEntity, "fingerprint_mismatch")
		expectOneEvent(t, alice, res.RequestID, "software_source.created", "failure")
	})

	t.Run("key change", func(t *testing.T) {
		key, fp := rotatedSourceKey(t)
		change := map[string]any{"signing_key": key, "fingerprint": fp}
		expectRefusal(t, alice, call(t, withoutStepUp(t, admin), http.MethodPatch, path, change),
			http.StatusForbidden, "step_up_required", "software_source.updated")
		s.stepUp(t)
		res := call(t, admin.Portal, http.MethodPatch, path, change)
		expectStatus(t, res, http.StatusOK, "")
		ev := expectOneEvent(t, alice, res.RequestID, "software_source.updated", "success")
		if ev.Params["fingerprint"] != fp || ev.Params["old_fingerprint"] != gateSourceFP {
			t.Fatalf("software_source.updated params %v, want fingerprint %s and old_fingerprint %s", ev.Params, fp, gateSourceFP)
		}
	})

	t.Run("in use", func(t *testing.T) {
		gateEntry(t, alice, id, packageRef("ubuntu", "*", gatePackage))
		s.stepUp(t)
		res := call(t, admin.Portal, http.MethodDelete, path, nil)
		expectStatus(t, res, http.StatusConflict, "in_use")
		expectOneEvent(t, alice, res.RequestID, "software_source.deleted", "failure")
	})
}

// TestSoftwareCatalog (plan M13a §9, AC-4, AC-7): an operator's catalog entry assigned `required pinned 1.0` to a
// device group reaches the group's devicesim bundle as the software section with the source and as a hold in the
// updates section; a device that then reports another distribution gets no section; `forbid` drops the source and
// the hold. The audit-once cases of the six catalog and assignment codes are in audit_once_software_test.go.
func TestSoftwareCatalog(t *testing.T) {
	alice := login(t, env.Alice)
	source, slug := gateSource(t, adminStepper(adminUser(t, "sw-catalog")), "sw-cat")
	op := operatorUser(t)
	group := namedGroup(t, alice, "software-catalog")
	d := activeDevice(t, alice, group, "sw-cat-"+uniqueSuffix())
	other := activeDevice(t, alice, group, "sw-cat-other-"+uniqueSuffix())
	// The software section is schema 2 only (plan M13a decision 13); a devicesim reports schema 1 unless told otherwise.
	for _, sim := range []*devicesim.Device{d, other} {
		sim.SchemaVersions = []int{bundle.SchemaVersion, bundle.SchemaVersion2}
	}

	entry := gateEntry(t, op.Portal, source, packageRef("ubuntu", "*", gatePackage))
	res := call(t, op.Portal, http.MethodPost, softwareAssignments, map[string]any{
		"catalog_entry_id": entry, "device_group_id": group, "intent": "required", "version": "1.0",
	})
	expectStatus(t, res, http.StatusCreated, "")
	expectOneEvent(t, alice, res.RequestID, "software_assignment.created", "success")
	assignment := softwareAssignments + "/" + responseID(t, res).String()

	hasSection := func(b *bundle.Bundle) bool { return b.Software != nil && len(b.Software.Packages) == 1 }
	held := func(b *bundle.Bundle, version string) bool {
		return b.Updates != nil && slices.ContainsFunc(b.Updates.Holds, func(h bundle.Hold) bool {
			return h.Package == gatePackage && h.Version != nil && *h.Version == version
		})
	}

	b := latestBundle(t, d, 2*time.Minute, hasSection)
	p := b.Software.Packages[0]
	if p.Package != gatePackage || p.Intent != bundle.SoftwareRequired || p.Version == nil || *p.Version != "1.0" ||
		p.Source != slug || p.CatalogEntryID != entry {
		t.Fatalf("software package %s", asJSON(t, p))
	}
	if len(b.Software.Sources) != 1 || b.Software.Sources[0].Slug != slug || b.Software.Sources[0].Fingerprint != gateSourceFP {
		t.Fatalf("software sources %s", asJSON(t, b.Software.Sources))
	}
	if !held(b, "1.0") {
		t.Fatalf("updates section without the hold %s 1.0: %s", gatePackage, asJSON(t, b.Updates))
	}

	t.Run("another distribution", func(t *testing.T) {
		latestBundle(t, other, 2*time.Minute, hasSection)
		other.OSRelease = map[string]string{"id": "debian", "version_id": "12"}
		b := latestBundle(t, other, 3*time.Minute, func(b *bundle.Bundle) bool {
			return b.SchemaVersion == bundle.SchemaVersion2 && b.Software == nil
		})
		if held(b, "1.0") {
			t.Fatalf("a device without the package keeps its hold: %s", asJSON(t, b.Updates))
		}
	})

	t.Run("forbid", func(t *testing.T) {
		res := call(t, op.Portal, http.MethodPatch, assignment, map[string]any{"intent": "forbid"})
		expectStatus(t, res, http.StatusOK, "")
		b := latestBundle(t, d, 2*time.Minute, func(b *bundle.Bundle) bool {
			return hasSection(b) && b.Software.Packages[0].Intent == bundle.SoftwareForbid
		})
		if p := b.Software.Packages[0]; p.Version != nil || p.Source != "" || len(b.Software.Sources) != 0 {
			t.Fatalf("forbid section %s", asJSON(t, b.Software))
		}
		if b.Updates != nil && slices.ContainsFunc(b.Updates.Holds, func(h bundle.Hold) bool { return h.Package == gatePackage }) {
			t.Fatalf("forbid keeps the hold: %s", asJSON(t, b.Updates))
		}
	})
}

// TestSoftwareStatus (plan M13a §9): an assigned entry without a package for the device's distribution is
// not_applicable on the device's managed software and on the entry's device list. The status of reported items and
// the digest-only check-in are TestSoftwareStatusFromCheckin (software_status_test.go).
func TestSoftwareStatus(t *testing.T) {
	alice := login(t, env.Alice)
	group := namedGroup(t, alice, "software-na")
	d := activeDevice(t, alice, group, "sw-na-"+uniqueSuffix())
	entry := gateEntry(t, alice, "", packageRef("debian", "12", gatePackage))
	expectStatus(t, call(t, alice, http.MethodPost, softwareAssignments, map[string]any{
		"catalog_entry_id": entry, "device_group_id": group, "intent": "required",
	}), http.StatusCreated, "")

	state := func(path, key, want string) {
		t.Helper()
		res := call(t, alice, http.MethodGet, path, nil)
		expectStatus(t, res, http.StatusOK, "")
		var page struct {
			Items []map[string]any `json:"items"`
		}
		if err := json.Unmarshal(res.Body, &page); err != nil {
			t.Fatal(err)
		}
		for _, it := range page.Items {
			if it[key] == want {
				if it["state"] != "not_applicable" {
					t.Fatalf("%s: %v, want state not_applicable", path, it)
				}
				return
			}
		}
		t.Fatalf("%s lists no item with %s %s: %s", path, key, want, res.Body)
	}
	state("/api/v1/devices/"+d.DeviceID+"/managed-software", "catalog_entry_id", entry)
	state(softwareCatalog+"/"+entry+"/devices", "device_id", d.DeviceID)
}
