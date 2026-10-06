package app

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/phischl/paddock-mdm/pkg/protocol"
	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/autoinstall"
	"github.com/phischl/paddock-mdm/server/internal/domain/agentrelease"
	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
	"github.com/phischl/paddock-mdm/server/internal/domain/enrollment"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/problem"
)

// SpecAutoinstallGenerate is the generation of a Paddock autoinstall (plan M4b decision 2).
var SpecAutoinstallGenerate = ActionSpec{Code: audit.CodeAutoinstallGenerated, AllowedRoles: RolesWrite}

// installArch is the architecture of devices installed with the Paddock autoinstall (arm64 is a non-goal of M4b).
const installArch = "amd64"

// Autoinstall generates Paddock autoinstalls. It stores nothing: the user-data with its passphrase and token exists
// only in the response.
type Autoinstall struct {
	runner     *ActionRunner
	org        *db.OrgPool
	bundlesURL string // public bundles host, e.g. https://bundles.example.org
	now        func() time.Time
}

// NewAutoinstall creates the use case; bundlesURL is the public host the packages are downloaded from.
func NewAutoinstall(runner *ActionRunner, org *db.OrgPool, bundlesURL string) *Autoinstall {
	return &Autoinstall{runner: runner, org: org, bundlesURL: strings.TrimRight(bundlesURL, "/"), now: time.Now}
}

// AutoinstallRequest is what an administrator chooses for one device.
type AutoinstallRequest struct {
	EnrollmentConfig protocol.EnrollmentConfig
	Release          string
	Hostname         string
	Locale           string
	KeyboardLayout   string
	Timezone         string
}

// Generate renders the user-data for one device (audited: autoinstall.generated with the release and the agent
// version, never the passphrase or the token). The enrollment configuration must belong to the caller's
// organization and its token must still be usable; the packages are those of the newest published release that has
// both of them.
func (a *Autoinstall) Generate(ctx context.Context, req AutoinstallRequest) ([]byte, error) {
	spec := SpecAutoinstallGenerate
	spec.Params = map[string]any{"release": req.Release}
	var out []byte
	err := a.runner.RunTx(ctx, ScopeOrg, spec, func(ctx context.Context, q *pgstore.Queries, rec Recorder) error {
		if err := autoinstall.Validate(req.Release, req.Hostname, req.Locale, req.KeyboardLayout, req.Timezone); err != nil {
			return problem.InvalidRequest.WithDetail(err.Error())
		}
		cfg, err := a.enrollmentConfig(ctx, q, req.EnrollmentConfig)
		if err != nil {
			return err
		}
		rows, err := q.InstallPackages(ctx, installArch)
		if err != nil {
			return fmt.Errorf("install packages: %w", err)
		}
		names := make([]string, len(rows))
		for i, r := range rows {
			names[i] = r.Name
		}
		if !slices.Contains(names, agentrelease.PackageAgent) || !slices.Contains(names, agentrelease.PackageSupervisor) {
			return problem.InvalidState.WithDetail("no published agent release has both Debian packages for " + installArch)
		}
		packages := make([]autoinstall.Package, len(rows))
		for i, r := range rows {
			packages[i] = autoinstall.Package{Name: r.Name, URL: a.bundlesURL + "/" + r.ObjectKey, SHA256: r.Sha256}
		}
		rec.SetParam("agent_version", rows[0].Version)
		settings, err := q.GetLoginSettings(ctx)
		if err != nil {
			return err
		}
		out, err = autoinstall.Render(autoinstall.Input{
			Release: req.Release, Hostname: req.Hostname, Locale: req.Locale, KeyboardLayout: req.KeyboardLayout,
			Timezone: req.Timezone, EnrollmentConfig: cfg, AgentVersion: rows[0].Version, Packages: packages,
			BootPINMinLength: int(settings.BootPinMinLength),
		}, a.now())
		return err
	})
	return out, err
}

// enrollmentConfig checks that cfg is an enrollment configuration of the caller's organization whose token can still
// enroll a device, and returns it as the device will read it. A token of another organization is not found, exactly
// like a token that does not exist.
func (a *Autoinstall) enrollmentConfig(ctx context.Context, q *pgstore.Queries, cfg protocol.EnrollmentConfig) ([]byte, error) {
	org, err := orgOf(ctx)
	if err != nil {
		return nil, err
	}
	u, err := url.Parse(cfg.ServerURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || len(cfg.BundleKeys) == 0 {
		return nil, problem.InvalidRequest.WithDetail("enrollment_config must have an https server_url and bundle_keys, as created with the enrollment token")
	}
	if cfg.OrganizationID != org.String() || cfg.Token == "" {
		return nil, problem.NotFound.WithDetail("the enrollment token of enrollment_config does not exist")
	}
	tok, err := q.GetEnrollmentTokenBySecret(ctx, enrollment.HashSecret(cfg.Token))
	if db.IsNoRows(err) {
		return nil, problem.NotFound.WithDetail("the enrollment token of enrollment_config does not exist")
	}
	if err != nil {
		return nil, err
	}
	if err := usable(tok, a.now()); err != nil {
		return nil, err
	}
	return json.Marshal(cfg)
}
