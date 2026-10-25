package app_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"testing"
	"time"

	"aead.dev/minisign"
	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/pkg/releasesig"
	"github.com/phischl/paddock-mdm/server/internal/adapters/githubreleases"
	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/config"
	"github.com/phischl/paddock-mdm/server/internal/domain/agentrelease"
	"github.com/phischl/paddock-mdm/server/internal/platform/httpx"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/problem"
)

// fakeSource is a release source in memory; an asset's URL is its name. block makes ListReleases wait for the
// context.
type fakeSource struct {
	releases []githubreleases.Release
	files    map[string][]byte
	block    bool
}

func (f *fakeSource) ListReleases(ctx context.Context) ([]githubreleases.Release, error) {
	if f.block {
		<-ctx.Done()
		return nil, fmt.Errorf("list releases: %w", ctx.Err())
	}
	return f.releases, nil
}

func (f *fakeSource) Download(_ context.Context, a githubreleases.Asset, _ int64) ([]byte, error) {
	b, ok := f.files[a.URL]
	if !ok {
		return nil, errors.New("HTTP 404")
	}
	return b, nil
}

// add lists one more file of release v on the source.
func (f *fakeSource) add(v, name string, body []byte) {
	f.files[name] = body
	for i := range f.releases {
		if f.releases[i].Version == v {
			f.releases[i].Assets = append(f.releases[i].Assets, githubreleases.Asset{Name: name, Size: int64(len(body)), URL: name})
			return
		}
	}
	f.releases = append(f.releases, githubreleases.Release{Version: v, PublishedAt: time.Now(),
		Assets: []githubreleases.Asset{{Name: name, Size: int64(len(body)), URL: name}}})
}

// addSigned lists a file and its signature; comment is the trusted comment.
func (h releaseHarness) addSigned(f *fakeSource, v, name string, body []byte, comment string) {
	f.add(v, name, body)
	f.add(v, name+".minisig", minisign.SignWithComments(h.priv, body, comment, ""))
}

// addRelease lists the required assets of v as the release workflow ships them (ADR 0043 decision 4), plus the
// unsigned paddock-revoke package and SHA256SUMS, which the import must ignore.
func (h releaseHarness) addRelease(f *fakeSource, v string) {
	for _, a := range agentrelease.SourceAssets(v) {
		if !a.Required {
			continue
		}
		comment := a.Package + " " + v + " " + a.Arch
		if a.Package == "" {
			comment = releasesig.Comment(v, a.Arch)
		}
		h.addSigned(f, v, a.Name, []byte("content of "+a.Name), comment)
	}
	f.add(v, "paddock-revoke_"+v+"_amd64-unsigned.deb", []byte("revoke"))
	f.add(v, "SHA256SUMS", []byte("sums"))
}

// sourceVersion is a release version newer than every release other tests publish.
func sourceVersion() string { return fmt.Sprintf("%d.0.0", time.Now().UnixNano()) }

func steppedUpAdmin() (context.Context, uuid.UUID, string) {
	id, corr := uuid.New(), uuid.NewString()
	ctx := principal.With(context.Background(), principal.Principal{Kind: principal.KindPlatformAdmin,
		Role: principal.RolePlatform, ID: id, Display: "pa@test", StepUpAt: time.Now()})
	return httpx.WithRequestID(ctx, corr), id, corr
}

var testSourceConfig = config.ReleaseSource{Repository: "phischl/paddock-mdm", URL: "http://github-fixture:8080"}

func (h releaseHarness) imports(src app.ReleaseSource) *app.ReleaseImports {
	return app.NewReleaseImports(h.runner, h.platform, h.releases, src, testSourceConfig)
}

// TestReleaseImport: a complete signed release is imported with the administrator as the actor of every event, as
// the host command would have stored it (ADR 0043 decisions 1, 2 and 4); paddock-revoke and unsigned files are not.
func TestReleaseImport(t *testing.T) {
	h := newReleaseHarness(t, false)
	src := &fakeSource{files: map[string][]byte{}}
	imp := h.imports(src)
	v := sourceVersion()
	h.addRelease(src, v)

	chk, err := imp.Check(platformAdmin())
	if err != nil || chk.Latest != v || !chk.Importable || chk.Reason != "" {
		t.Fatalf("check = %+v, %v", chk, err)
	}

	ctx, admin, corr := steppedUpAdmin()
	d, err := imp.Import(ctx, v)
	if err != nil {
		t.Fatal(err)
	}
	if d.Release.Status != agentrelease.StatusPublished || len(d.Artifacts) != 2 || len(d.Packages) != 2 || d.Rollout != nil {
		t.Fatalf("release %+v, %d artifacts, %d packages, rollout %v", d.Release, len(d.Artifacts), len(d.Packages), d.Rollout)
	}
	for _, art := range d.Artifacts {
		name := "paddockd_" + v + "_linux_" + art.Arch
		sum := sha256.Sum256(src.files[name])
		if art.Sha256 != hex.EncodeToString(sum[:]) || art.Size != int64(len(src.files[name])) ||
			art.ObjectKey != agentrelease.ObjectKey(v, art.Arch) || art.Minisig != base64.StdEncoding.EncodeToString(src.files[name+".minisig"]) {
			t.Errorf("artifact %+v does not match %s", art, name)
		}
		if string(h.store.puts[art.ObjectKey]) != string(src.files[name]) {
			t.Errorf("%s: stored object differs", name)
		}
	}
	for _, pkg := range d.Packages {
		name := pkg.Name + "_" + v + "_" + pkg.Arch + ".deb"
		sum := sha256.Sum256(src.files[name])
		if pkg.Arch != "amd64" || pkg.Sha256 != hex.EncodeToString(sum[:]) || pkg.PackageVersion != nil ||
			pkg.ObjectKey != agentrelease.PackageObjectKey(v, pkg.Name, "", pkg.Arch) {
			t.Errorf("package %+v does not match %s", pkg, name)
		}
	}
	if n := countRows(t, h.super, `SELECT count(*) FROM agent_package WHERE version = $1 AND name = 'paddock-revoke'`, v); n != 0 {
		t.Error("paddock-revoke was imported")
	}
	for code, want := range map[string]int{
		"agent_release.imported": 1, "agent_release.created": 1, "agent_release.artifact_uploaded": 4, "agent_release.published": 1,
	} {
		if n := countRows(t, h.super, `SELECT count(*) FROM action WHERE correlation_id = $1 AND code = $2
			AND outcome = 'success' AND actor->>'type' = 'platform_admin' AND actor->>'id' = $3`, corr, code, admin.String()); n != want {
			t.Errorf("%d %s events of the administrator, want %d", n, code, want)
		}
	}
	if n := countRows(t, h.super, `SELECT count(*) FROM action WHERE correlation_id = $1 AND code = 'agent_release.imported'
		AND params->>'source' = 'phischl/paddock-mdm' AND params->>'source_url' = 'http://github-fixture:8080'
		AND params->>'version' = $2 AND params ? 'newest_stored' AND params->>'files' = '4'
		AND (actor->>'step_up')::boolean`, corr, v); n != 1 {
		t.Error("the import event lacks its params or the step-up")
	}

	chk, err = imp.Check(platformAdmin())
	if err != nil || chk.Importable || chk.Reason != app.CheckReasonNotNewer || chk.NewestStored != v {
		t.Fatalf("check after the import = %+v, %v", chk, err)
	}

	// The next import names the release just imported as the newest stored; optional packages are imported.
	v2 := sourceVersion()
	h.addRelease(src, v2)
	deb := []byte("arm64 deb")
	h.addSigned(src, v2, "paddock-agent_"+v2+"_arm64.deb", deb, "paddock-agent "+v2+" arm64")
	ctx, _, corr = steppedUpAdmin()
	if d, err = imp.Import(ctx, v2); err != nil || len(d.Packages) != 3 {
		t.Fatalf("import with an arm64 package: %d packages, %v", len(d.Packages), err)
	}
	if n := countRows(t, h.super, `SELECT count(*) FROM action WHERE correlation_id = $1 AND code = 'agent_release.imported'
		AND outcome = 'success' AND params->>'files' = '5' AND params->>'newest_stored' = $2`, corr, v); n != 1 {
		t.Error("the import of the arm64 package does not record 5 files and the previous newest release")
	}

	v3 := sourceVersion()
	h.addRelease(src, v3)
	src.add(v3, "paddock-agent_"+v3+"_arm64.deb", deb)
	ctx, _, _ = steppedUpAdmin()
	_, err = imp.Import(ctx, v3)
	expectProblem(t, err, problem.ReleaseIncomplete)

	v4 := sourceVersion()
	h.addRelease(src, v4)
	fleetd := []byte("fleetd deb")
	h.addSigned(src, v4, "fleet-osquery_1.48.0_amd64.deb", fleetd, "fleet-osquery 1.48.0 amd64")
	ctx, _, _ = steppedUpAdmin()
	if d, err = imp.Import(ctx, v4); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, pkg := range d.Packages {
		if pkg.Name == agentrelease.PackageFleetd && pkg.PackageVersion != nil && *pkg.PackageVersion == "1.48.0" &&
			pkg.ObjectKey == agentrelease.PackageObjectKey(v4, agentrelease.PackageFleetd, "1.48.0", "amd64") {
			found = true
		}
	}
	if !found {
		t.Fatalf("fleet-osquery 1.48.0 not imported: %+v", d.Packages)
	}
}

// TestReleaseImportContinuesADraft: a stored draft of the version is continued, as the host command does.
func TestReleaseImportContinuesADraft(t *testing.T) {
	h := newReleaseHarness(t, false)
	src := &fakeSource{files: map[string][]byte{}}
	v := sourceVersion()
	h.addRelease(src, v)
	if _, err := h.releases.Create(platformAdmin(), v); err != nil {
		t.Fatal(err)
	}
	ctx, _, _ := steppedUpAdmin()
	if d, err := h.imports(src).Import(ctx, v); err != nil || d.Release.Status != agentrelease.StatusPublished {
		t.Fatalf("import of a draft: %+v, %v", d.Release, err)
	}
}

// TestReleaseImportRefusals: every refusal leaves the control plane unchanged and is one audit event.
func TestReleaseImportRefusals(t *testing.T) {
	h := newReleaseHarness(t, false)
	src := &fakeSource{files: map[string][]byte{}}
	imp := h.imports(src)
	published := sourceVersion()
	h.addRelease(src, published)
	ctx, _, _ := steppedUpAdmin()
	if _, err := imp.Import(ctx, published); err != nil {
		t.Fatal(err)
	}

	for name, c := range map[string]struct {
		setup   func() string
		want    *problem.Error
		outcome string
	}{
		"equal version":       {func() string { return published }, problem.ReleaseNotNewer, "failure"},
		"older version":       {func() string { return "1.0.0" }, problem.ReleaseNotNewer, "failure"},
		"outside the pattern": {func() string { return "1.0.0-e2e" }, problem.InvalidRequest, "failure"},
		"not on the source":   {sourceVersion, problem.NotFound, "failure"},
		"missing signature": {func() string {
			v := sourceVersion()
			h.addRelease(src, v)
			src.releases[len(src.releases)-1].Assets = withoutAsset(src.releases[len(src.releases)-1].Assets,
				"paddock-supervisor_"+v+"_amd64.deb.minisig")
			return v
		}, problem.ReleaseIncomplete, "failure"},
		"missing binary": {func() string {
			v := sourceVersion()
			h.addRelease(src, v)
			src.releases[len(src.releases)-1].Assets = withoutAsset(src.releases[len(src.releases)-1].Assets,
				"paddockd_"+v+"_linux_arm64")
			return v
		}, problem.ReleaseIncomplete, "failure"},
		"tampered body": {func() string {
			v := sourceVersion()
			h.addRelease(src, v)
			src.files["paddockd_"+v+"_linux_amd64"] = []byte("tampered")
			return v
		}, problem.InvalidRequest, "failure"},
		"signed for another version": {func() string {
			v := sourceVersion()
			h.addRelease(src, v)
			name := "paddockd_" + v + "_linux_amd64"
			src.files[name+".minisig"] = minisign.SignWithComments(h.priv, src.files[name], releasesig.Comment(published, "amd64"), "")
			return v
		}, problem.ReleaseSignatureMismatch, "failure"},
	} {
		v := c.setup()
		ctx, _, corr := steppedUpAdmin()
		before := len(h.store.puts)
		_, err := imp.Import(ctx, v)
		if problem.From(err).Code != c.want.Code {
			t.Errorf("%s: %v, want %s", name, err, c.want.Code)
			continue
		}
		if v != published {
			if n := countRows(t, h.super, "SELECT count(*) FROM agent_release WHERE version = $1", v); n != 0 {
				t.Errorf("%s: the release was created", name)
			}
		}
		if len(h.store.puts) != before {
			t.Errorf("%s: a file was stored", name)
		}
		if n := countRows(t, h.super, `SELECT count(*) FROM action WHERE correlation_id = $1`, corr); n != 1 {
			t.Errorf("%s: %d audit events, want exactly the import", name, n)
		}
		if n := countRows(t, h.super, `SELECT count(*) FROM action WHERE correlation_id = $1
			AND code = 'agent_release.imported' AND outcome = $2 AND error_code = $3`, corr, c.outcome, c.want.Code); n != 1 {
			t.Errorf("%s: no %s agent_release.imported event with %s", name, c.outcome, c.want.Code)
		}
	}

	// Without a step-up the import is denied before the source is asked.
	v := sourceVersion()
	h.addRelease(src, v)
	corr := uuid.NewString()
	_, err := imp.Import(httpx.WithRequestID(platformAdmin(), corr), v)
	expectProblem(t, err, problem.StepUpRequired)
	if n := countRows(t, h.super, `SELECT count(*) FROM action WHERE correlation_id = $1 AND code = 'agent_release.imported'
		AND outcome = 'denied' AND error_code = 'step_up_required'`, corr); n != 1 {
		t.Error("the import without a step-up is not one denied event")
	}
}

func withoutAsset(assets []githubreleases.Asset, name string) []githubreleases.Asset {
	out := assets[:0:0]
	for _, a := range assets {
		if a.Name != name {
			out = append(out, a)
		}
	}
	return out
}

// TestReleaseImportSourceOffOrUnavailable: a source switched off denies the import and the check; a source that does
// not answer within the bound fails with release_source_unavailable (ADR 0043 decisions 5 and 6).
func TestReleaseImportSourceOffOrUnavailable(t *testing.T) {
	h := newReleaseHarness(t, false)
	off := app.NewReleaseImports(h.runner, h.platform, h.releases, nil, config.ReleaseSource{})
	if info, err := off.Source(platformAdmin()); err != nil || info.Enabled || info.Repository != "" || info.URL != "" {
		t.Fatalf("source = %+v, %v", info, err)
	}
	if _, err := off.Check(platformAdmin()); !errors.Is(err, problem.ReleaseSourceDisabled) {
		t.Fatalf("check while off: %v", err)
	}
	ctx, _, corr := steppedUpAdmin()
	_, err := off.Import(ctx, sourceVersion())
	expectProblem(t, err, problem.ReleaseSourceDisabled)
	if n := countRows(t, h.super, `SELECT count(*) FROM action WHERE correlation_id = $1 AND code = 'agent_release.imported'
		AND outcome = 'denied' AND error_code = 'release_source_disabled'`, corr); n != 1 {
		t.Error("the import while off is not one denied event")
	}

	if _, err := h.imports(&fakeSource{}).Source(systemCtx(uuid.New())); err == nil {
		t.Error("a non-platform principal read the source")
	}

	blocking := h.imports(&fakeSource{block: true})
	blocking.SetTimeout(100 * time.Millisecond)
	ctx, _, corr = steppedUpAdmin()
	start := time.Now()
	_, err = blocking.Import(ctx, sourceVersion())
	expectProblem(t, err, problem.ReleaseSourceUnavailable)
	if time.Since(start) > 10*time.Second {
		t.Errorf("the import took %s", time.Since(start))
	}
	if n := countRows(t, h.super, `SELECT count(*) FROM action WHERE correlation_id = $1 AND code = 'agent_release.imported'
		AND outcome = 'failure' AND error_code = 'release_source_unavailable'`, corr); n != 1 {
		t.Error("the unavailable source is not one failed event")
	}
}
