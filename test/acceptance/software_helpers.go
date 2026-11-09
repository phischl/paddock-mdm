package acceptance

import (
	"bytes"
	"image"
	"image/png"
	"net/http"
	"testing"

	"github.com/phischl/paddock-mdm/test/acceptance/internal/env"
)

const (
	softwareSources     = "/api/v1/software-sources"
	softwareCatalog     = "/api/v1/software-catalog"
	softwareAssignments = "/api/v1/software-assignments"
)

// gateSourceKey is a public Ed25519 test key (with a Curve25519 subkey) of the server's domain fixtures
// (server/internal/domain/software/testdata/ed25519.asc); gateSourceFP is its fingerprint as gpg prints it.
const (
	gateSourceFP  = "8A367815ED9674ED9013609A8F03DFF0EB10E2E4"
	gateSourceKey = `-----BEGIN PGP PUBLIC KEY BLOCK-----

mDMEauZTvxYJKwYBBAHaRw8BAQdA8gZS4XMIj+mH6B+32KGXexz3r0XUKaDHuLsS
kYIR6+S0LlBhZGRvY2sgVGVzdCBFZDI1NTE5IDxlZDI1NTE5QGV4YW1wbGUuaW52
YWxpZD6IkwQTFgoAOxYhBIo2eBXtlnTtkBNgmo8D3/DrEOLkBQJq5lO/AhsDBQsJ
CAcCAiICBhUKCQgLAgQWAgMBAh4HAheAAAoJEI8D3/DrEOLkHw0A/iSPs1Mg5Py+
jDGd2BJQqCDnKEiRxTmuR1CLiwvVUcIYAQCfK1gGmWT7VKYSd7iBLTlNME2A4Ah3
uvazPRhP79yuCLQjU2Vjb25kIFVJRCA8c2Vjb25kQGV4YW1wbGUuaW52YWxpZD6I
kwQTFgoAOxYhBIo2eBXtlnTtkBNgmo8D3/DrEOLkBQJq5lO/AhsDBQsJCAcCAiIC
BhUKCQgLAgQWAgMBAh4HAheAAAoJEI8D3/DrEOLkd2YBAI7YC6TCEYlDYXe+1oLp
UejfTc67VQpzh+PyRgIdahV5AQCe45395A0hZczX24FGoecIdz7Q8qlSE9ro+3fd
LfPBAbg4BGrmU78SCisGAQQBl1UBBQEBB0CA2TMUB69tDfU9x1w4tcQB+PUdshFt
LLehChFTbg18aQMBCAeIeAQYFgoAIBYhBIo2eBXtlnTtkBNgmo8D3/DrEOLkBQJq
5lO/AhsMAAoJEI8D3/DrEOLkR0YBALg9FQwjK7sI3vQzKF1ZMCQuxn4Nx3mPZJHr
b1JZI/bLAP93zqDeQdEr+6W895yBkW3YX8m0hAlEhhGYiQKke/xVBw==
=8qw8
-----END PGP PUBLIC KEY BLOCK-----
`
)

// sourceBody is a valid software source with a unique slug and name that start with prefix ([a-z0-9-]).
func sourceBody(prefix string) map[string]any {
	slug := prefix + "-" + uniqueSuffix()
	return map[string]any{
		"slug": slug, "name": slug, "uris": []string{"https://apt.gates.example/"}, "suites": []string{"stable"},
		"components": []string{"main"}, "signing_key": gateSourceKey, "fingerprint": gateSourceFP,
	}
}

// flatpakSourceBody is a valid Flatpak source (plan M13b decision 5): one https remote and no suites or components.
func flatpakSourceBody(prefix string) map[string]any {
	body := sourceBody(prefix)
	body["kind"], body["uris"], body["suites"], body["components"] = "flatpak", []string{"https://flatpak.gates.example/repo/"}, []string{}, []string{}
	return body
}

// flatpakRef is one Flatpak application of a catalog entry, in scope system or user.
func flatpakRef(ref, scope string) map[string]any {
	return map[string]any{"distribution": "ubuntu", "release": "*", "architecture": "*", "flatpak_ref": ref, "scope": scope}
}

// deleteSourceOnCleanup deletes a software source when the test ends; renew steps p up again when its step-up window
// has run out meanwhile.
func deleteSourceOnCleanup(t *testing.T, p *env.Portal, renew func(t *testing.T), path string) {
	t.Helper()
	t.Cleanup(func() {
		res := call(t, p, http.MethodDelete, path, nil)
		if res.Status == http.StatusForbidden && res.ProblemCode() == "step_up_required" {
			renew(t)
			res = call(t, p, http.MethodDelete, path, nil)
		}
		if res.Status != http.StatusNoContent && res.Status != http.StatusNotFound {
			t.Errorf("cleanup: DELETE %s: HTTP %d %s", path, res.Status, res.Body)
		}
	})
}

// entryBody is a valid catalog entry with a unique name that starts with prefix.
func entryBody(prefix string) map[string]any {
	return map[string]any{
		"name": prefix + "-" + uniqueSuffix(),
		"packages": []map[string]any{
			{"distribution": "ubuntu", "release": "*", "architecture": "*", "package": "nano"},
		},
	}
}

// gatePNG is a valid 16 by 16 PNG for the icon operations.
func gatePNG(t *testing.T) []byte {
	t.Helper()
	var b bytes.Buffer
	if err := png.Encode(&b, image.NewGray(image.Rect(0, 0, 16, 16))); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// listSoftwareEntry creates a catalog entry assigned to a device group and removes it with the test: the entry the
// list gate reads on the device's and on the entry's page (PDK-411). Only the group's devices manage it.
func listSoftwareEntry(t *testing.T, p *env.Portal, group string) string {
	t.Helper()
	res := call(t, p, http.MethodPost, softwareCatalog, entryBody("list-contract"))
	expectStatus(t, res, http.StatusCreated, "")
	entry := createdID(t, p, softwareCatalog, res)
	expectStatus(t, call(t, p, http.MethodPost, softwareAssignments, map[string]any{
		"catalog_entry_id": entry, "device_group_id": group, "intent": "hold",
	}), http.StatusCreated, "")
	return entry
}
