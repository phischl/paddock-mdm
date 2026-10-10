package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"aead.dev/minisign"
	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/config"
	"github.com/phischl/paddock-mdm/server/internal/domain/agentrelease"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/platform/objectstore"
	"github.com/phischl/paddock-mdm/server/internal/transport/http/admin/adminapi"
)

// runAgentRelease uploads and publishes the signed agent files of dir with the api role's configuration (plan M7b
// decision 31, §6.4): in the Compose stack as docker compose … run --rm --no-deps -v <dir>:/release:ro paddock-api
// admin agent-release --version <v> --dir /release. It prints the release detail as JSON.
func runAgentRelease(ctx context.Context, l *config.Loader, cmd adminCommand, stdout io.Writer) error {
	// stdout carries the JSON only; the logs of the use cases go to stderr.
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, nil)))
	orgDSN := l.SecretFile("PADDOCK_DB_URL_FILE")
	platformDSN := l.SecretFile("PADDOCK_DB_PLATFORM_URL_FILE")
	releaseKey := l.SecretFile("PADDOCK_RELEASE_PUBLIC_KEY_FILE")
	revokeReleaseKey := l.SecretFile("PADDOCK_REVOKE_RELEASE_PUBLIC_KEY_FILE")
	artifacts := objectstore.New(l.Required("PADDOCK_ARTIFACTS_S3_ENDPOINT"), l.SecretFile("PADDOCK_ARTIFACTS_S3_ACCESS_KEY_FILE"),
		l.SecretFile("PADDOCK_ARTIFACTS_S3_SECRET_KEY_FILE"), l.String("PADDOCK_ARTIFACTS_S3_BUCKET", "paddock-agent-artifacts"))
	development := config.LoadCommon(l).Development()
	if err := l.Err(); err != nil {
		return err
	}
	var releasePub, revokeReleasePub minisign.PublicKey
	if err := releasePub.UnmarshalText([]byte(releaseKey)); err != nil {
		return fmt.Errorf("PADDOCK_RELEASE_PUBLIC_KEY_FILE: %w", err)
	}
	if err := revokeReleasePub.UnmarshalText([]byte(revokeReleaseKey)); err != nil {
		return fmt.Errorf("PADDOCK_REVOKE_RELEASE_PUBLIC_KEY_FILE: %w", err)
	}
	binaries, packages, err := readReleaseDir(cmd.dir, cmd.version)
	if err != nil {
		return err
	}

	orgPool, err := db.NewOrgPool(ctx, orgDSN, db.Options{ApplicationName: "paddock-admin", MaxConns: 2})
	if err != nil {
		return err
	}
	defer orgPool.Close()
	platformPool, err := db.NewPlatformPool(ctx, platformDSN, db.Options{ApplicationName: "paddock-admin-platform", MaxConns: 2})
	if err != nil {
		return err
	}
	defer platformPool.Close()
	correlation := "admin-" + uuid.NewString()
	runner := app.NewActionRunner(orgPool, platformPool, func(context.Context) string { return correlation })
	releases := app.NewAgentReleases(runner, platformPool, artifacts, app.NewReleaseVerifier(releasePub),
		app.NewReleaseVerifier(revokeReleasePub), development)
	d, err := releases.PublishFromHost(ctx, cmd.version, binaries, packages)
	if err != nil {
		fmt.Fprintf(os.Stderr, "agent-release %s: %v\n", cmd.version, err)
		return err
	}
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(releaseDetailJSON(d))
}

// readReleaseDir reads the layout of the offline signing step (§6.4): <arch>/paddockd with paddockd.minisig per
// architecture, <name>_<version>_<arch>.deb with its .minisig for the Paddock packages (version: the release version
// or its Debian form x.y.z~alpha.N), and fleet-osquery_<fleetd version>_<arch>.deb. Every file needs its signature.
func readReleaseDir(dir, version string) ([]app.HostArtifact, []app.HostPackage, error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = root.Close() }()
	read := func(name string) ([]byte, []byte, error) {
		body, err := root.ReadFile(name)
		if err != nil {
			return nil, nil, err
		}
		sig, err := root.ReadFile(name + ".minisig")
		if err != nil {
			return nil, nil, fmt.Errorf("%s has no signature: %w", name, err)
		}
		return body, sig, nil
	}
	var binaries []app.HostArtifact
	for _, arch := range agentrelease.Arches {
		name := filepath.Join(arch, "paddockd")
		if _, err := root.Stat(name); errors.Is(err, os.ErrNotExist) {
			continue
		}
		body, sig, err := read(name)
		if err != nil {
			return nil, nil, err
		}
		binaries = append(binaries, app.HostArtifact{Arch: arch, Binary: body, Minisig: sig})
	}
	if len(binaries) == 0 {
		return nil, nil, fmt.Errorf("%s: no <arch>/paddockd (arch: %s)", dir, strings.Join(agentrelease.Arches, ", "))
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, nil, err
	}
	var packages []app.HostPackage
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".deb") {
			continue
		}
		pkg, err := parseDebName(e.Name(), version)
		if err != nil {
			return nil, nil, err
		}
		if pkg.Deb, pkg.Minisig, err = read(e.Name()); err != nil {
			return nil, nil, err
		}
		packages = append(packages, pkg)
	}
	return binaries, packages, nil
}

// parseDebName maps <name>_<version>_<arch>.deb to its package: the Paddock packages must carry the release version
// (or its Debian form), fleet-osquery carries the fleetd version.
func parseDebName(file, version string) (app.HostPackage, error) {
	parts := strings.Split(strings.TrimSuffix(file, ".deb"), "_")
	if len(parts) != 3 || !strings.HasSuffix(file, ".deb") {
		return app.HostPackage{}, fmt.Errorf("%s: not <name>_<version>_<arch>.deb", file)
	}
	pkg := app.HostPackage{Name: parts[0], Arch: parts[2]}
	if err := agentrelease.ValidateArch(pkg.Arch); err != nil {
		return app.HostPackage{}, fmt.Errorf("%s: %w", file, err)
	}
	switch pkg.Name {
	case agentrelease.PackageFleetd:
		pkg.PackageVersion = parts[1]
	case agentrelease.PackageAgent, agentrelease.PackageSupervisor, agentrelease.PackageRevoke:
		if parts[1] != version && parts[1] != strings.Replace(version, "-", "~", 1) {
			return app.HostPackage{}, fmt.Errorf("%s: not a package of release %s", file, version)
		}
	default:
		return app.HostPackage{}, fmt.Errorf("%s: unknown package %s", file, pkg.Name)
	}
	return pkg, nil
}

// releaseDetailJSON is the admin API's representation of a release (GET /api/platform/v1/agent-releases/{version}).
func releaseDetailJSON(d app.ReleaseDetail) adminapi.AgentReleaseDetail {
	r := d.Release
	out := adminapi.AgentReleaseDetail{
		Release: adminapi.AgentRelease{
			Version: r.Version, Status: adminapi.AgentReleaseStatus(r.Status), CreatedBy: r.CreatedBy,
			CreatedAt: r.CreatedAt.UTC(), PublishedAt: r.PublishedAt, ArtifactCount: len(d.Artifacts),
		},
		Artifacts: make([]adminapi.AgentArtifact, len(d.Artifacts)),
		Packages:  make([]adminapi.AgentPackage, len(d.Packages)),
	}
	if out.Release.PublishedAt != nil {
		t := out.Release.PublishedAt.UTC()
		out.Release.PublishedAt = &t
	}
	for i, a := range d.Artifacts {
		out.Artifacts[i] = adminapi.AgentArtifact{Arch: adminapi.AgentArtifactArch(a.Arch), Sha256: a.Sha256, Size: a.Size,
			CreatedAt: a.CreatedAt.UTC()}
	}
	for i, p := range d.Packages {
		out.Packages[i] = adminapi.AgentPackage{
			Name: adminapi.AgentPackageName(p.Name), Arch: adminapi.AgentPackageArch(p.Arch), Sha256: p.Sha256, Size: p.Size,
			UrlPath: "/" + p.ObjectKey, CreatedAt: p.CreatedAt.UTC(), PackageVersion: p.PackageVersion,
		}
	}
	return out
}
