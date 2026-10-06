package acceptance

import (
	"io"
	"net/http"
	"testing"
	"time"

	"aead.dev/minisign"

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
	expectStatus(t, uploadPackage(t, root, v, "paddock-supervisor", deb, minisign.Sign(releaseKey(t), deb)), http.StatusOK, "")

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
	bin := []byte("gate binary " + v)
	expectStatus(t, uploadArtifact(t, root, v, bin, minisign.Sign(releaseKey(t), bin)), http.StatusOK, "")
	for _, path := range []string{"/paddock-agent-artifacts/releases/" + v + "/amd64/paddockd", "/paddock-agent-artifacts/?list-type=2",
		"/paddock-agent-artifacts/?list-type=2&prefix=packages/", "/packages/"} {
		if status, _ := get(path); status != http.StatusForbidden {
			t.Errorf("%s without credentials: HTTP %d, want 403", path, status)
		}
	}
}
