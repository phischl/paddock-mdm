package acceptance

import (
	"io"
	"net/http"
	"testing"
	"time"

	"aead.dev/minisign"

	"github.com/phischl/paddock-mdm/pkg/releasesig"
	"github.com/phischl/paddock-mdm/test/acceptance/internal/env"
	"github.com/phischl/paddock-mdm/test/acceptance/internal/stack"
)

// TestAgentPackagesPublic checks plan M4b decision 1: the Debian packages of a release are served without
// credentials at bundles.<domain>/packages/<version>/<name>_<version>_<arch>.deb, byte for byte as uploaded, while
// agent binaries and bucket listings still need a presigned URL.
func TestAgentPackagesPublic(t *testing.T) {
	root := login(t, env.PlatformAdmin)
	v := gateRelease(t, root, false, false)
	deb := []byte("!<arch>\ngate package " + v)
	expectStatus(t, uploadPackage(t, root, v, "paddock-supervisor", deb, signPackage(t, deb, v)), http.StatusOK, "")

	client, err := env.NewHTTPClient()
	if err != nil {
		t.Fatal(err)
	}
	get := func(path string) (int, []byte) {
		t.Helper()
		req, err := http.NewRequestWithContext(testContext(t, time.Minute), http.MethodGet, stack.BundlesURL()+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		res, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = res.Body.Close() }()
		body, _ := io.ReadAll(res.Body)
		return res.StatusCode, body
	}
	if status, body := get("/packages/" + v + "/paddock-supervisor_" + v + "_amd64.deb"); status != http.StatusOK || string(body) != string(deb) {
		t.Fatalf("public package: HTTP %d, %d bytes", status, len(body))
	}
	if status, _ := get("/packages/" + v + "/paddock-agent_" + v + "_amd64.deb"); status != http.StatusNotFound && status != http.StatusForbidden {
		t.Errorf("missing package: HTTP %d", status)
	}
	// paddock-revoke is signed with the revocation release key: the agent release key does not do (plan M4c
	// decision 4), not even with the release comment. Its comment binds it to the release like every other package
	// (ADR 0043 amendment 2026-11-11 c, PDK-1004).
	revoke := []byte("!<arch>\ngate revoke " + v)
	expectStatus(t, uploadPackage(t, root, v, "paddock-revoke", revoke, signPackage(t, revoke, v)), http.StatusBadRequest, "invalid_request")
	revokeKey, err := stack.RevokeReleaseKey("")
	if err != nil {
		t.Fatal(err)
	}
	for label, comment := range map[string]string{"no comment": "", "older release": releasesig.Comment("0.0.1", "amd64"),
		"other arch": releasesig.Comment(v, "arm64"), "former comment": "paddock-revoke " + v + " amd64"} {
		sig := minisign.Sign(revokeKey, revoke)
		if comment != "" {
			sig = minisign.SignWithComments(revokeKey, revoke, comment, "")
		}
		res := uploadPackage(t, root, v, "paddock-revoke", revoke, sig)
		if res.Status != http.StatusUnprocessableEntity || res.ProblemCode() != "release_signature_mismatch" {
			t.Errorf("paddock-revoke with %s: HTTP %d %s, want 422 release_signature_mismatch", label, res.Status, res.ProblemCode())
		}
	}
	expectStatus(t, uploadPackage(t, root, v, "paddock-revoke", revoke, signRevokePackage(t, revokeKey, revoke, v)), http.StatusOK, "")
	expectStatus(t, uploadPackage(t, root, v, "paddock-supervisor", deb, signRevokePackage(t, revokeKey, deb, v)), http.StatusBadRequest, "invalid_request")
	bin := []byte("gate binary " + v)
	expectStatus(t, uploadArtifact(t, root, v, bin, signBinary(t, bin, v)), http.StatusOK, "")
	for _, path := range []string{"/paddock-agent-artifacts/releases/" + v + "/amd64/paddockd", "/paddock-agent-artifacts/?list-type=2",
		"/paddock-agent-artifacts/?list-type=2&prefix=packages/", "/packages/"} {
		if status, _ := get(path); status != http.StatusForbidden {
			t.Errorf("%s without credentials: HTTP %d, want 403", path, status)
		}
	}
}

// signRevokePackage signs a package as the holders of the revocation release key do offline: with the trusted comment
// of its release and arch amd64 (ADR 0043 amendment 2026-11-11 c, PDK-1004).
func signRevokePackage(t *testing.T, key minisign.PrivateKey, deb []byte, v string) []byte {
	t.Helper()
	return minisign.SignWithComments(key, deb, releasesig.Comment(v, "amd64"), "")
}
