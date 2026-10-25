package app

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/phischl/paddock-mdm/pkg/semver"
	"github.com/phischl/paddock-mdm/server/internal/adapters/githubreleases"
	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/config"
	"github.com/phischl/paddock-mdm/server/internal/domain/agentrelease"
	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/problem"
)

// ReleaseSource lists the releases of the configured source and downloads their assets (githubreleases.Client).
type ReleaseSource interface {
	ListReleases(ctx context.Context) ([]githubreleases.Release, error)
	Download(ctx context.Context, a githubreleases.Asset, maxBytes int64) ([]byte, error)
}

// ReleaseImports are the platform use cases of the agent release import (ADR 0043 decision 1).
type ReleaseImports struct {
	runner   *ActionRunner
	platform *db.PlatformPool
	releases *AgentReleases
	source   ReleaseSource
	cfg      config.ReleaseSource
	timeout  time.Duration
}

// NewReleaseImports creates the use cases; source is nil while the feature is off.
func NewReleaseImports(runner *ActionRunner, platform *db.PlatformPool, releases *AgentReleases, source ReleaseSource,
	cfg config.ReleaseSource) *ReleaseImports {
	return &ReleaseImports{runner: runner, platform: platform, releases: releases, source: source, cfg: cfg,
		timeout: ImportTimeout}
}

// SpecAgentReleaseImport is the audited import (step-up required).
var SpecAgentReleaseImport = ActionSpec{Code: audit.CodeAgentReleaseImported, AllowedRoles: RolesPlatform, RequiresStepUp: true}

// ImportTimeout bounds one import including every download (ADR 0043 decision 5); it stays below the server's write
// timeout of 120 s, so the administrator always gets an answer.
const ImportTimeout = 90 * time.Second

// Reasons of a check result that is not importable.
const (
	CheckReasonNoneFound = "none_found"
	CheckReasonNotNewer  = "not_newer"
)

// SourceInfo is the configured release source.
type SourceInfo struct {
	Enabled         bool
	Repository, URL string
}

// enabled reports whether the import may reach the source.
func (r *ReleaseImports) enabled() bool { return r.cfg.Enabled() && r.source != nil }

// Source reports the configured source; platform administrators only (ErrForbidden otherwise); no outbound call.
func (r *ReleaseImports) Source(ctx context.Context) (SourceInfo, error) {
	if _, err := RequirePlatform(ctx); err != nil {
		return SourceInfo{}, err
	}
	if !r.enabled() {
		return SourceInfo{}, nil
	}
	return SourceInfo{Enabled: true, Repository: r.cfg.Repository, URL: r.cfg.URL}, nil
}

// CheckResult is the latest candidate of the source against the newest published release; Reason is "" when
// Importable, otherwise CheckReasonNoneFound or CheckReasonNotNewer.
type CheckResult struct {
	Latest       string
	PublishedAt  time.Time
	NewestStored string
	Importable   bool
	Reason       string
}

// Check lists the source and compares the latest candidate with the newest published release (ADR 0043 decision 3);
// problem.ReleaseSourceDisabled when off, problem.ReleaseSourceUnavailable on any source error; no audit event.
func (r *ReleaseImports) Check(ctx context.Context) (CheckResult, error) {
	var out CheckResult
	if _, err := RequirePlatform(ctx); err != nil {
		return out, err
	}
	if !r.enabled() {
		return out, problem.ReleaseSourceDisabled
	}
	rels, err := r.source.ListReleases(ctx)
	if err != nil {
		return out, sourceProblem(err)
	}
	if out.NewestStored, err = r.newestPublished(ctx); err != nil {
		return out, err
	}
	for _, rel := range rels {
		if out.Latest == "" || semver.Compare(rel.Version, out.Latest) > 0 {
			out.Latest, out.PublishedAt = rel.Version, rel.PublishedAt
		}
	}
	switch {
	case out.Latest == "":
		out.Reason = CheckReasonNoneFound
	case out.NewestStored != "" && semver.Compare(out.Latest, out.NewestStored) <= 0:
		out.Reason = CheckReasonNotNewer
	default:
		out.Importable = true
	}
	return out, nil
}

// newestPublished is the version of the newest published release, or "" without one.
func (r *ReleaseImports) newestPublished(ctx context.Context) (string, error) {
	var v string
	err := r.platform.InPlatform(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		var err error
		v, err = newestPublishedIn(ctx, q)
		return err
	})
	return v, err
}

func newestPublishedIn(ctx context.Context, q *pgstore.Queries) (string, error) {
	rel, err := q.NewestPublishedAgentRelease(ctx)
	if db.IsNoRows(err) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("newest published agent release: %w", err)
	}
	return rel.Version, nil
}

// Import imports version (ADR 0043 decisions 3, 4, 7 and 8) as one action SpecAgentReleaseImport around the download,
// the verification and the shared publish function of AgentReleases. It never starts a rollout.
func (r *ReleaseImports) Import(ctx context.Context, version string) (ReleaseDetail, error) {
	spec := SpecAgentReleaseImport
	t := releaseTarget(version)
	spec.Target = &t
	spec.Params = map[string]any{"source": r.cfg.Repository, "source_url": r.cfg.URL, "version": version}
	files := 0
	err := r.runner.RunExternal(ctx, ScopePlatform, spec,
		func(ctx context.Context, q *pgstore.Queries, rec Recorder) error {
			if err := agentrelease.ValidateSourceVersion(version); err != nil {
				return problem.InvalidRequest.WithDetail(err.Error())
			}
			if !r.enabled() {
				return problem.ReleaseSourceDisabled
			}
			newest, err := newestPublishedIn(ctx, q)
			if err != nil {
				return err
			}
			rec.SetParam("newest_stored", newest)
			existing, err := q.GetAgentRelease(ctx, version)
			switch {
			case err == nil && existing.Status != agentrelease.StatusDraft:
				return problem.ReleaseNotNewer.WithDetail("release " + version + " is already published")
			case err != nil && !db.IsNoRows(err):
				return fmt.Errorf("get agent release: %w", err)
			case newest != "" && semver.Compare(version, newest) <= 0:
				return problem.ReleaseNotNewer.WithDetail(fmt.Sprintf("%s is not newer than the newest published release %s", version, newest))
			}
			return nil
		},
		func(ctx context.Context) error {
			ctx, cancel := context.WithTimeout(ctx, r.timeout)
			defer cancel()
			arts, pkgs, err := r.fetch(ctx, version)
			if err != nil {
				return err
			}
			if _, err := r.releases.publishVerified(ctx, version, arts, pkgs); err != nil {
				return err
			}
			files = len(arts) + len(pkgs)
			return nil
		},
		func(_ context.Context, _ *pgstore.Queries, rec Recorder, externalErr error) error {
			if externalErr == nil {
				rec.SetParam("files", files)
			}
			return nil
		})
	if err != nil {
		return ReleaseDetail{}, err
	}
	return r.releases.get(ctx, version)
}

// fetch downloads the Paddock assets of version and verifies every file before anything is created or stored (ADR
// 0043 decisions 2 and 4). paddock-revoke, unsigned files and every other asset are never fetched.
func (r *ReleaseImports) fetch(ctx context.Context, version string) ([]HostArtifact, []HostPackage, error) {
	rels, err := r.source.ListReleases(ctx)
	if err != nil {
		return nil, nil, sourceProblem(err)
	}
	var rel *githubreleases.Release
	for i := range rels {
		if rels[i].Version == version {
			rel = &rels[i]
		}
	}
	if rel == nil {
		return nil, nil, problem.NotFound.WithDetail("release " + version + " is not on the release source")
	}
	assets := make(map[string]githubreleases.Asset, len(rel.Assets))
	for _, a := range rel.Assets {
		assets[a.Name] = a
	}

	// Every asset and signature is looked up before the first download, so an incomplete release costs no transfer.
	var wanted []agentrelease.SourceAsset
	for _, want := range agentrelease.SourceAssets(version) {
		if _, ok := assets[want.Name]; ok {
			wanted = append(wanted, want)
		} else if want.Required {
			return nil, nil, problem.ReleaseIncomplete.WithDetail(want.Name + " is missing")
		}
	}
	fleetdVersion := map[string]string{}
	for _, a := range rel.Assets {
		if pv, arch, ok := agentrelease.ParseFleetdAsset(a.Name); ok {
			fleetdVersion[a.Name] = pv
			wanted = append(wanted, agentrelease.SourceAsset{Name: a.Name, Arch: arch, Package: agentrelease.PackageFleetd})
		}
	}
	for _, want := range wanted {
		if _, ok := assets[want.Name+".minisig"]; !ok {
			return nil, nil, problem.ReleaseIncomplete.WithDetail(want.Name + ".minisig is missing")
		}
	}

	var arts []HostArtifact
	var pkgs []HostPackage
	for _, want := range wanted {
		body, err := r.download(ctx, assets[want.Name], agentrelease.MaxArtifactBytes)
		if err != nil {
			return nil, nil, err
		}
		sig, err := r.download(ctx, assets[want.Name+".minisig"], githubreleases.MaxMinisigBytes)
		if err != nil {
			return nil, nil, err
		}
		if want.Package == "" {
			if _, err := r.verify(r.releases.verify, want, body, sig, version); err != nil {
				return nil, nil, err
			}
			arts = append(arts, HostArtifact{Arch: want.Arch, Binary: body, Minisig: sig})
			continue
		}
		pv := fleetdVersion[want.Name]
		if err := agentrelease.ValidatePackage(want.Package, pv); err != nil {
			return nil, nil, problem.InvalidRequest.WithDetail(want.Name + ": " + err.Error())
		}
		if _, err := r.verify(r.releases.packageVerifier(want.Package), want, body, sig, ""); err != nil {
			return nil, nil, err
		}
		pkgs = append(pkgs, HostPackage{Name: want.Package, PackageVersion: pv, Arch: want.Arch, Deb: body, Minisig: sig})
	}
	return arts, pkgs, nil
}

// download fetches one asset within maxBytes.
func (r *ReleaseImports) download(ctx context.Context, a githubreleases.Asset, maxBytes int64) ([]byte, error) {
	body, err := r.source.Download(ctx, a, maxBytes)
	if err != nil {
		return nil, sourceProblem(err)
	}
	return body, nil
}

// verify checks one downloaded file with checkFile and names the asset in the refusal; for an agent binary
// (binaryVersion set) the trusted comment must name the release and arch (checkBinaryComment).
func (r *ReleaseImports) verify(verify VerifyRelease, a agentrelease.SourceAsset, body, sig []byte, binaryVersion string) (string, error) {
	if len(body) == 0 {
		return "", problem.InvalidRequest.WithDetail(a.Name + " is empty")
	}
	comment, err := checkFile(verify, a.Arch, body, base64.StdEncoding.EncodeToString(sig))
	if err != nil {
		return "", problem.InvalidRequest.WithDetail(a.Name + ": the signature does not verify with the release public key")
	}
	if binaryVersion != "" {
		if err := checkBinaryComment(comment, binaryVersion, a.Arch); err != nil {
			return "", fmt.Errorf("%s: %w", a.Name, err)
		}
	}
	return comment, nil
}

// sourceProblem maps an error of the release source to release_source_unavailable; nothing is retried (ADR 0043
// decision 5).
func sourceProblem(err error) error {
	var rl *githubreleases.RateLimitError
	if errors.As(err, &rl) {
		return problem.ReleaseSourceUnavailable.WithDetail("rate limit exceeded; resets at " + rl.ResetAt.UTC().Format(time.RFC3339))
	}
	return problem.ReleaseSourceUnavailable.WithDetail(err.Error())
}
