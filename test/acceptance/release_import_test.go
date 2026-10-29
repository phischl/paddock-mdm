package acceptance

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"aead.dev/minisign"

	"github.com/phischl/paddock-mdm/pkg/releasesig"
	"github.com/phischl/paddock-mdm/test/acceptance/internal/env"
	"github.com/phischl/paddock-mdm/test/acceptance/internal/stack"
)

// githubFixtureAlias is the host name of the GitHub fixture on the network cp; compose.dev.yaml points
// PADDOCK_AGENT_RELEASE_SOURCE_URL of paddock-api at it (ADR 0043 decision 9).
const githubFixtureAlias = "github-fixture"

// startGitHubFixture serves dir as GitHub's REST API under http://github-fixture:8080 on the network cp: dir holds
// repos/phischl/paddock-mdm/releases (the release list) and download/v<v>/<asset>. The file server reads the disk on
// every request, so a gate may rewrite dir while it runs. Older fixture servers are removed first.
func startGitHubFixture(t *testing.T, dir string) {
	t.Helper()
	ctx := testContext(t, 2*time.Minute)
	image, err := stack.Image("CADDY_IMAGE")
	if err != nil {
		t.Fatal(err)
	}
	// Per Compose project: the fixtures of a second development stack on the host are not this run's to remove.
	label := "paddock.github-fixture=" + stack.Project()
	if old, err := stack.Docker(ctx, nil, "ps", "-aq", "--filter", "label="+label); err == nil && strings.TrimSpace(old) != "" {
		_, _ = stack.Docker(ctx, nil, append([]string{"rm", "-f"}, strings.Fields(old)...)...)
	}
	if err := os.Chmod(dir, 0o755); err != nil { // Caddy reads it as another user
		t.Fatal(err)
	}
	name := "paddock-github-fixture-" + uniqueSuffix()
	if out, err := stack.Docker(ctx, nil, "run", "-d", "--rm", "--name", name, "--label", label, "--network", stack.Network("cp"),
		"--network-alias", githubFixtureAlias, "-v", dir+":/srv:ro", image, "caddy", "file-server", "--root", "/srv",
		"--listen", ":8080"); err != nil {
		t.Fatalf("start the GitHub fixture server: %v: %s", err, out)
	}
	t.Cleanup(func() { _, _ = stack.Docker(context.Background(), nil, "rm", "-f", name) })
	// The api asks the fixture right away, unlike the worker's OSV cycle: wait until Caddy listens.
	for deadline := time.Now().Add(30 * time.Second); ; {
		out, err := stack.Docker(ctx, nil, "exec", name, "wget", "-q", "-O", "/dev/null", "http://127.0.0.1:8080/repos/phischl/paddock-mdm/releases")
		if err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the GitHub fixture server did not start: %v: %s", err, out)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// fixtureRelease is one release of the GitHub fixture; files maps an asset name to its content.
type fixtureRelease struct {
	tag   string
	draft bool
	files map[string][]byte
}

// writeGitHubFixture (re)writes the release list and the assets of rels below dir.
func writeGitHubFixture(t *testing.T, dir string, rels ...fixtureRelease) {
	t.Helper()
	list := make([]map[string]any, 0, len(rels))
	for _, r := range rels {
		assets := []map[string]any{}
		for name, body := range r.files {
			path := filepath.Join(dir, "download", r.tag, name)
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, body, 0o644); err != nil { //nolint:gosec // Caddy reads it as another user
				t.Fatal(err)
			}
			assets = append(assets, map[string]any{"name": name, "size": len(body),
				"browser_download_url": "http://" + githubFixtureAlias + ":8080/download/" + r.tag + "/" + name})
		}
		list = append(list, map[string]any{"tag_name": r.tag, "draft": r.draft, "prerelease": strings.Contains(r.tag, "-"),
			"published_at": "2026-10-25T10:00:00Z", "assets": assets})
	}
	body, err := json.Marshal(list)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "repos", "phischl", "paddock-mdm", "releases")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, body, 0o644); err != nil { //nolint:gosec // Caddy reads it as another user
		t.Fatal(err)
	}
}

// signedSourceRelease is release v as the release workflow ships it (the set of v0.1.0-alpha.5): paddockd amd64 and
// arm64, paddock-agent and paddock-supervisor amd64, each with its signature by the development release key, plus
// the unsigned paddock-revoke package, which the import ignores.
func signedSourceRelease(t *testing.T, v string) fixtureRelease {
	t.Helper()
	key := releaseKey(t)
	files := map[string][]byte{}
	for _, arch := range []string{"amd64", "arm64"} {
		name := "paddockd_" + v + "_linux_" + arch
		files[name] = []byte("gate paddockd " + arch + " " + v)
		files[name+".minisig"] = minisign.SignWithComments(key, files[name], releasesig.Comment(v, arch), "")
	}
	for _, pkg := range []string{"paddock-agent", "paddock-supervisor"} {
		addSignedPackage(t, files, pkg, v, "amd64")
	}
	files["paddock-revoke_"+v+"_amd64-unsigned.deb"] = []byte("unsigned revoke")
	return fixtureRelease{tag: "v" + v, files: files}
}

func addSignedPackage(t *testing.T, files map[string][]byte, pkg, v, arch string) {
	t.Helper()
	name := pkg + "_" + v + "_" + arch + ".deb"
	files[name] = []byte("!<arch>\ngate " + name)
	files[name+".minisig"] = minisign.SignWithComments(releaseKey(t), files[name], pkg+" "+v+" "+arch, "")
}

// importBase is the version core of the gate's releases: the patch after the newest published release of the stack,
// so every version derived from it is newer than whatever other gates and tests published before
// (gateVersion is 0.0.1-gate…, other test suites publish their own) and stays on the release channel.
type importBase struct{ major, minor, patch uint64 }

func newImportBase(t *testing.T, root *env.Portal) importBase {
	t.Helper()
	res := call(t, root, http.MethodGet, "/api/platform/v1/agent-releases?status=published&sort=-version&page_size=10", nil)
	expectStatus(t, res, http.StatusOK, "")
	var page struct {
		Items []struct {
			Version string `json:"version"`
		} `json:"items"`
	}
	if err := res.JSON(&page); err != nil {
		t.Fatal(err)
	}
	if len(page.Items) == 0 {
		return importBase{}
	}
	core, _, _ := strings.Cut(page.Items[0].Version, "+")
	core, _, _ = strings.Cut(core, "-")
	var b importBase
	if _, err := fmt.Sscanf(core, "%d.%d.%d", &b.major, &b.minor, &b.patch); err != nil {
		t.Fatalf("newest release %q: %v", page.Items[0].Version, err)
	}
	b.patch++
	return b
}

// version is a fresh release version on the release channel; a larger offset is a newer version.
func (b importBase) version(offset int64) string {
	return fmt.Sprintf("%d.%d.%d-alpha.%d", b.major, b.minor, b.patch, time.Now().UnixMilli()+offset)
}

// above is a version newer than every version of b.
func (b importBase) above() string { return fmt.Sprintf("%d.0.0", b.major+1) }

func importRelease(t *testing.T, p *env.Portal, version string) env.Response {
	t.Helper()
	return call(t, p, http.MethodPost, "/api/platform/v1/agent-releases/import", map[string]string{"version": version})
}

// importEvent is the agent_release.imported event of a request (the created, uploaded and published events share
// its correlation ID).
func importEvent(t *testing.T, idx *env.AuditIndex, res env.Response, outcome string) env.IndexEvent {
	t.Helper()
	return expectOneIndexEvent(t, idx, platformOrg, "correlation_id = $1 AND code = 'agent_release.imported'", res.RequestID,
		"agent_release.imported", outcome, auditPollTimeout)
}

// expectNoRelease requires that version was not stored.
func expectNoRelease(t *testing.T, root *env.Portal, version string) {
	t.Helper()
	expectStatus(t, call(t, root, http.MethodGet, "/api/platform/v1/agent-releases/"+version, nil), http.StatusNotFound, "not_found")
}

// TestAgentReleaseImport is the gate of ADR 0043: a platform administrator checks the configured release source (the
// GitHub fixture of the development stack) and imports the latest release with a step-up; every file is verified
// with the release public key before anything is stored, the release is published without a rollout, and every
// refusal stores nothing and is one audit event. Drafts and tags outside the release channel are never chosen.
func TestAgentReleaseImport(t *testing.T) {
	root, idx := login(t, env.PlatformAdmin), auditIndex(t)
	dir := t.TempDir()
	base := newImportBase(t, root)
	v := base.version(0)
	older := signedSourceRelease(t, "0.0.1-alpha.1")
	current := signedSourceRelease(t, v)
	others := []fixtureRelease{older, {tag: "v" + base.above(), draft: true, files: map[string][]byte{}},
		{tag: "v" + base.above() + "-e2e", files: map[string][]byte{}}}
	writeGitHubFixture(t, dir, append([]fixtureRelease{current}, others...)...)
	startGitHubFixture(t, dir)

	// 1. The source.
	var src struct {
		Enabled    bool    `json:"enabled"`
		Repository *string `json:"repository"`
		URL        *string `json:"url"`
	}
	res := call(t, root, http.MethodGet, "/api/platform/v1/agent-release-source", nil)
	expectStatus(t, res, http.StatusOK, "")
	if err := res.JSON(&src); err != nil || !src.Enabled || src.Repository == nil || *src.Repository != "phischl/paddock-mdm" ||
		src.URL == nil || *src.URL != "http://github-fixture:8080" {
		t.Fatalf("source: %s", res.Body)
	}

	// 2. The check finds v: the draft and the tag outside the channel pattern are not candidates.
	type checkResult struct {
		Latest       *string `json:"latest"`
		NewestStored *string `json:"newest_stored"`
		Importable   bool    `json:"importable"`
		Reason       *string `json:"reason"`
	}
	check := func() checkResult {
		t.Helper()
		res := call(t, root, http.MethodPost, "/api/platform/v1/agent-release-source/check", nil)
		expectStatus(t, res, http.StatusOK, "")
		var c checkResult
		if err := res.JSON(&c); err != nil {
			t.Fatal(err)
		}
		return c
	}
	if c := check(); c.Latest == nil || *c.Latest != v || !c.Importable || c.Reason != nil {
		t.Fatalf("check: %+v", c)
	}

	// 3. Without a step-up the import is denied.
	res = importRelease(t, root, v)
	expectStatus(t, res, http.StatusForbidden, "step_up_required")
	expectOneIndexEvent(t, idx, platformOrg, "correlation_id = $1", res.RequestID, "agent_release.imported", "denied", auditPollTimeout)

	// 4. With a step-up v is imported and published, byte for byte as the source serves it.
	stepUp(t, root, env.PlatformAdmin, true)
	res = importRelease(t, root, v)
	expectStatus(t, res, http.StatusCreated, "")
	if loc := res.Header.Get("Location"); loc != "/api/platform/v1/agent-releases/"+v {
		t.Fatalf("Location %q", loc)
	}
	var detail struct {
		Release struct {
			Status string `json:"status"`
		} `json:"release"`
		Artifacts []struct {
			Arch   string `json:"arch"`
			Sha256 string `json:"sha256"`
		} `json:"artifacts"`
		Packages []struct {
			Arch string `json:"arch"`
		} `json:"packages"`
		Rollout any `json:"rollout"`
	}
	if err := res.JSON(&detail); err != nil {
		t.Fatal(err)
	}
	if detail.Release.Status != "published" || len(detail.Artifacts) != 2 || len(detail.Packages) != 2 ||
		detail.Packages[0].Arch != "amd64" || detail.Packages[1].Arch != "amd64" || detail.Rollout != nil {
		t.Fatalf("imported release: %s", res.Body)
	}
	sum := sha256.Sum256(current.files["paddockd_"+v+"_linux_amd64"])
	for _, a := range detail.Artifacts {
		if a.Arch == "amd64" && a.Sha256 != hex.EncodeToString(sum[:]) {
			t.Fatalf("amd64 artifact sha256 %s, want %x", a.Sha256, sum)
		}
	}
	ev := importEvent(t, idx, res, "success")
	if ev.Params["version"] != v || ev.Params["source"] != "phischl/paddock-mdm" || fmt.Sprint(ev.Params["files"]) != "4" {
		t.Fatalf("import event params %v", ev.Params)
	}
	get := call(t, root, http.MethodGet, "/api/platform/v1/agent-releases/"+v, nil)
	expectStatus(t, get, http.StatusOK, "")
	var created, read map[string]any
	if err := res.JSON(&created); err != nil {
		t.Fatal(err)
	}
	if err := get.JSON(&read); err != nil || !reflect.DeepEqual(created, read) {
		t.Fatalf("GET %s differs from the import's answer:\n%s\n%s", v, get.Body, res.Body)
	}

	// 5. v is now the newest stored release.
	if c := check(); c.Importable || c.Reason == nil || *c.Reason != "not_newer" || c.NewestStored == nil || *c.NewestStored != v {
		t.Fatalf("check after the import: %+v", c)
	}

	// 6. An older release is refused.
	freshStepUp(t, root, env.PlatformAdmin)
	res = importRelease(t, root, "0.0.1-alpha.1")
	expectStatus(t, res, http.StatusConflict, "release_not_newer")
	importEvent(t, idx, res, "failure")

	// 7.–10. Refusals that store nothing, and an optional arm64 package.
	v2, v3, v4, v5, v6 := base.version(1), base.version(2), base.version(3), base.version(4), base.version(5)
	tampered := signedSourceRelease(t, v2)
	tampered.files["paddockd_"+v2+"_linux_amd64"] = []byte("not what was signed")
	wrongComment := signedSourceRelease(t, v3)
	bin := wrongComment.files["paddockd_"+v3+"_linux_amd64"]
	wrongComment.files["paddockd_"+v3+"_linux_amd64.minisig"] = minisign.SignWithComments(releaseKey(t), bin, releasesig.Comment(v, "amd64"), "")
	incomplete := signedSourceRelease(t, v4)
	delete(incomplete.files, "paddock-supervisor_"+v4+"_amd64.deb.minisig")
	withArm64 := signedSourceRelease(t, v5)
	addSignedPackage(t, withArm64.files, "paddock-agent", v5, "arm64")
	unsignedArm64 := signedSourceRelease(t, v6)
	addSignedPackage(t, unsignedArm64.files, "paddock-agent", v6, "arm64")
	delete(unsignedArm64.files, "paddock-agent_"+v6+"_arm64.deb.minisig")
	writeGitHubFixture(t, dir, append([]fixtureRelease{current, tampered, wrongComment, incomplete, withArm64, unsignedArm64}, others...)...)

	freshStepUp(t, root, env.PlatformAdmin)
	res = importRelease(t, root, v2)
	expectStatus(t, res, http.StatusBadRequest, "invalid_request")
	importEvent(t, idx, res, "failure")
	expectNoRelease(t, root, v2)

	freshStepUp(t, root, env.PlatformAdmin)
	res = importRelease(t, root, v3)
	expectStatus(t, res, http.StatusUnprocessableEntity, "release_signature_mismatch")
	importEvent(t, idx, res, "failure")
	expectNoRelease(t, root, v3)

	freshStepUp(t, root, env.PlatformAdmin)
	res = importRelease(t, root, v4)
	expectStatus(t, res, http.StatusUnprocessableEntity, "release_incomplete")
	if !strings.Contains(string(res.Body), "paddock-supervisor_"+v4+"_amd64.deb.minisig") {
		t.Fatalf("the refusal does not name the missing signature: %s", res.Body)
	}
	importEvent(t, idx, res, "failure")
	expectNoRelease(t, root, v4)

	freshStepUp(t, root, env.PlatformAdmin)
	res = importRelease(t, root, v5)
	expectStatus(t, res, http.StatusCreated, "")
	if err := res.JSON(&detail); err != nil || len(detail.Packages) != 3 {
		t.Fatalf("import with an arm64 package: %s", res.Body)
	}

	freshStepUp(t, root, env.PlatformAdmin)
	res = importRelease(t, root, v6)
	expectStatus(t, res, http.StatusUnprocessableEntity, "release_incomplete")
	expectNoRelease(t, root, v6)
}

// importAuditCases are the A3 cases of POST /api/platform/v1/agent-releases/import (ADR 0043 decision 7); they live in
// releaseAuditCases, whose cases run one after another, because each starts the one GitHub fixture.
func importAuditCases() []auditCase {
	return []auditCase{
		{"no step-up", func(t *testing.T, w *auditWorld) {
			res := importRelease(t, login(t, env.PlatformAdmin), "0.0.2")
			expectStatus(t, res, http.StatusForbidden, "step_up_required")
			expectOneIndexEvent(t, w.idx, platformOrg, "correlation_id = $1", res.RequestID, "agent_release.imported", "denied", auditPollTimeout)
		}},
		{"wrong role", func(t *testing.T, w *auditWorld) {
			res := importRelease(t, w.alice, "0.0.2")
			expectStatus(t, res, http.StatusForbidden, "forbidden")
			expectOneEvent(t, w.alice, res.RequestID, "agent_release.imported", "denied")
		}},
		{"conflict", func(t *testing.T, w *auditWorld) {
			gateRelease(t, w.root, true, true) // 0.0.1-gate… is newer than 0.0.1-alpha.1
			dir := t.TempDir()
			writeGitHubFixture(t, dir, signedSourceRelease(t, "0.0.1-alpha.1"))
			startGitHubFixture(t, dir)
			freshStepUp(t, w.root, env.PlatformAdmin)
			res := importRelease(t, w.root, "0.0.1-alpha.1")
			expectStatus(t, res, http.StatusConflict, "release_not_newer")
			expectOneIndexEvent(t, w.idx, platformOrg, "correlation_id = $1", res.RequestID, "agent_release.imported", "failure", auditPollTimeout)
		}},
		{"success", func(t *testing.T, w *auditWorld) {
			v := newImportBase(t, w.root).version(0)
			dir := t.TempDir()
			writeGitHubFixture(t, dir, signedSourceRelease(t, v))
			startGitHubFixture(t, dir)
			freshStepUp(t, w.root, env.PlatformAdmin)
			res := importRelease(t, w.root, v)
			expectStatus(t, res, http.StatusCreated, "")
			importEvent(t, w.idx, res, "success")
		}},
	}
}
