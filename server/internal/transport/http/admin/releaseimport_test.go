package admin_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"aead.dev/minisign"

	"github.com/phischl/paddock-mdm/pkg/releasesig"
	"github.com/phischl/paddock-mdm/server/internal/adapters/githubreleases"
	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/config"
	"github.com/phischl/paddock-mdm/server/internal/domain/agentrelease"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/pgtest"
	"github.com/phischl/paddock-mdm/server/internal/transport/http/admin"
)

// githubFixture serves one release of version v in the shape of GitHub's REST API, signed with key.
func githubFixture(t *testing.T, key minisign.PrivateKey, v string) *httptest.Server {
	t.Helper()
	files := map[string][]byte{}
	for _, a := range agentrelease.SourceAssets(v) {
		if !a.Required {
			continue
		}
		body := []byte("content of " + a.Name)
		comment := a.Package + " " + v + " " + a.Arch
		if a.Package == "" {
			comment = releasesig.Comment(v, a.Arch)
		}
		files[a.Name] = body
		files[a.Name+".minisig"] = minisign.SignWithComments(key, body, comment, "")
	}
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/repos/phischl/paddock-mdm/releases" {
			assets := []map[string]any{}
			for name, body := range files {
				assets = append(assets, map[string]any{"name": name, "size": len(body), "browser_download_url": srv.URL + "/download/" + name})
			}
			_ = json.NewEncoder(w).Encode([]map[string]any{{"tag_name": "v" + v, "draft": false, "published_at": "2026-10-25T10:00:00Z", "assets": assets}})
			return
		}
		body, ok := files[strings.TrimPrefix(r.URL.Path, "/download/")]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// TestReleaseImportAPISourceOff: with the source switched off the source reads as disabled, the check and the import
// answer 403 release_source_disabled, and only the import is audited (ADR 0043 decisions 6 and 7).
func TestReleaseImportAPISourceOff(t *testing.T) {
	e := newEnv(t)
	root := e.platformSession()

	src := e.do(call{method: "GET", path: "/api/platform/v1/agent-release-source", cookie: root})
	if src.status != http.StatusOK || strings.ReplaceAll(string(src.body), "\n", "") != `{"enabled":false,"repository":null,"url":null}` {
		t.Fatalf("source: %d %s", src.status, src.body)
	}
	chk := e.do(call{method: "POST", path: "/api/platform/v1/agent-release-source/check", cookie: root})
	if chk.status != http.StatusForbidden || chk.problemCode(t) != "release_source_disabled" {
		t.Fatalf("check: %d %s", chk.status, chk.body)
	}
	if ev := e.events(chk.header.Get("X-Request-Id")); len(ev) != 0 {
		t.Fatalf("the check was audited: %v", ev)
	}
	imp := e.do(call{method: "POST", path: "/api/platform/v1/agent-releases/import", body: map[string]string{"version": "1.2.3"},
		cookie: e.steppedUp(root, time.Now())})
	if imp.status != http.StatusForbidden || imp.problemCode(t) != "release_source_disabled" {
		t.Fatalf("import: %d %s", imp.status, imp.body)
	}
	e.expectEvent(imp, "agent_release.imported:denied:release_source_disabled")

	// The literal path wins over /agent-releases/{version} for POST; GET reads the (missing) release "import".
	get := e.do(call{method: "GET", path: "/api/platform/v1/agent-releases/import", cookie: root, skipReqCheck: true})
	if get.status != http.StatusNotFound || get.problemCode(t) != "not_found" {
		t.Fatalf("GET import: %d %s", get.status, get.body)
	}
}

// TestReleaseImportAPI: check and import against a GitHub-compatible source.
func TestReleaseImportAPI(t *testing.T) {
	v := fmt.Sprintf("%d.0.0", time.Now().UnixNano())
	var key minisign.PrivateKey
	var srv *httptest.Server
	e := newEnvWith(t, func(d *admin.Deps) {
		pool, err := db.NewPlatformPool(t.Context(), pgtest.SharedPaddock(t).Platform, db.Options{})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(pool.Close)
		cfg := config.ReleaseSource{Repository: "phischl/paddock-mdm", URL: "http://fixture.invalid"}
		d.ReleaseImports = app.NewReleaseImports(d.Runner, pool, d.Releases, &lazySource{srv: &srv}, cfg)
	})
	key = e.release
	srv = githubFixture(t, key, v)
	root := e.platformSession()

	src := e.do(call{method: "GET", path: "/api/platform/v1/agent-release-source", cookie: root})
	var info struct {
		Enabled    bool   `json:"enabled"`
		Repository string `json:"repository"`
	}
	src.decode(t, &info)
	if !info.Enabled || info.Repository != "phischl/paddock-mdm" {
		t.Fatalf("source: %s", src.body)
	}
	chk := e.do(call{method: "POST", path: "/api/platform/v1/agent-release-source/check", cookie: root})
	var c struct {
		Latest     string  `json:"latest"`
		Importable bool    `json:"importable"`
		Reason     *string `json:"reason"`
	}
	chk.decode(t, &c)
	if chk.status != http.StatusOK || c.Latest != v || !c.Importable || c.Reason != nil {
		t.Fatalf("check: %d %s", chk.status, chk.body)
	}

	body := map[string]string{"version": v}
	denied := e.do(call{method: "POST", path: "/api/platform/v1/agent-releases/import", body: body, cookie: root})
	if denied.status != http.StatusForbidden || denied.problemCode(t) != "step_up_required" {
		t.Fatalf("import without step-up: %d %s", denied.status, denied.body)
	}
	e.expectEvent(denied, "agent_release.imported:denied:step_up_required")

	imp := e.do(call{method: "POST", path: "/api/platform/v1/agent-releases/import", body: body, cookie: e.steppedUp(root, time.Now())})
	var d struct {
		Release struct {
			Status string `json:"status"`
		} `json:"release"`
		Artifacts []any `json:"artifacts"`
		Packages  []any `json:"packages"`
	}
	imp.decode(t, &d)
	if imp.status != http.StatusCreated || imp.header.Get("Location") != "/api/platform/v1/agent-releases/"+v ||
		d.Release.Status != "published" || len(d.Artifacts) != 2 || len(d.Packages) != 2 {
		t.Fatalf("import: %d %s %s", imp.status, imp.header.Get("Location"), imp.body)
	}

	again := e.do(call{method: "POST", path: "/api/platform/v1/agent-releases/import", body: body, cookie: e.steppedUp(root, time.Now())})
	if again.status != http.StatusConflict || again.problemCode(t) != "release_not_newer" {
		t.Fatalf("import again: %d %s", again.status, again.body)
	}
	e.expectEvent(again, "agent_release.imported:failure:release_not_newer")
}

// lazySource is a githubreleases client on a fixture started after the handler was built.
type lazySource struct{ srv **httptest.Server }

func (l *lazySource) client() *githubreleases.Client {
	return githubreleases.New((*l.srv).URL, "phischl/paddock-mdm", "", true)
}

func (l *lazySource) ListReleases(ctx context.Context) ([]githubreleases.Release, error) {
	return l.client().ListReleases(ctx)
}

func (l *lazySource) Download(ctx context.Context, a githubreleases.Asset, maxBytes int64) ([]byte, error) {
	return l.client().Download(ctx, a, maxBytes)
}
