// Package supervisorpkg installs the paddock-supervisor package of the current release (ADR 0037 decision 3, plan
// M8d decisions 31 and 32). The agent decides and stages; `paddockd supervisor-upgrade`, started in a transient
// systemd unit outside the supervisor's cgroup, installs the package, waits for the agent's next check-in and restores
// the previous supervisor when it does not come. The supervisor never updates itself.
package supervisorpkg

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/phischl/paddock-mdm/agent/internal/buildinfo"
	"github.com/phischl/paddock-mdm/agent/internal/fsutil"
	"github.com/phischl/paddock-mdm/agent/internal/paths"
	"github.com/phischl/paddock-mdm/pkg/bundle"
	"github.com/phischl/paddock-mdm/pkg/semver"
)

// The supervisor's package, files and the transient unit of the upgrade helper.
const (
	Package     = "paddock-supervisor"
	Service     = "paddock-supervisor.service"
	Binary      = "/usr/sbin/paddock-supervisor"
	UnitFile    = "/usr/lib/systemd/system/paddock-supervisor.service"
	UpgradeUnit = "paddock-supervisor-upgrade"
	// BackupDir holds the copy of the installed supervisor binary and unit file during an upgrade (a device path of
	// System).
	BackupDir = "/var/lib/paddock/packages/supervisor-backup"
	// MaxPackage bounds the download (the server accepts packages up to 128 MiB).
	MaxPackage = 128 << 20
	// CheckinWait is how long the helper waits for the agent's check-in after dpkg installed the package.
	CheckinWait = 10 * time.Minute
	// Stable is how long the supervisor must keep running with one PID after that check-in: a supervisor that exits
	// shortly after it started its agent would otherwise pass on the agent's first check-in.
	Stable = time.Minute
	// StaleAfter is the age of a marker without a result at which the agent counts the upgrade as failed (the helper
	// died): longer than dpkg's 15 minutes plus CheckinWait.
	StaleAfter = 30 * time.Minute
)

// Reasons Plan declines an installation.
const (
	ReasonInProgress   = "in_progress"
	ReasonInvalid      = "invalid_package"
	ReasonAgentVersion = "agent_version"
	ReasonFailed       = "failed_before"
	ReasonNotInstalled = "not_installed"
	ReasonCurrent      = "current"
	ReasonPolicy       = "policy"
)

var (
	version   = regexp.MustCompile(`^[0-9A-Za-z.+~-]{1,64}$`)
	sha256Hex = regexp.MustCompile(`^[0-9a-f]{64}$`)
	urlPath   = regexp.MustCompile(`^packages/[0-9A-Za-z.+~-]{1,64}/paddock-supervisor_[0-9A-Za-z.+~-]{1,64}_(amd64|arm64)\.deb$`)
	debName   = regexp.MustCompile(`^paddock-supervisor_([0-9A-Za-z.+~-]{1,64})_(amd64|arm64)\.deb$`)
)

// Validate checks a package reference of the bundle.
func Validate(ref bundle.PackageRef) error {
	if !version.MatchString(ref.Version) || !sha256Hex.MatchString(ref.SHA256) || !urlPath.MatchString(ref.URLPath) {
		return fmt.Errorf("invalid supervisor package %+v", ref)
	}
	return nil
}

// Plan decides whether the supervisor package of the bundle is installed on this device (ADR 0037 decision 3):
// the policy allows updates (automatic, or requested since the last check-in), the agent runs the package's
// release (buildinfo.Version == ref.Version), dpkg reports an older paddock-supervisor version, no upgrade is in
// progress and the version did not fail before.
func Plan(ref bundle.PackageRef, installed string, policyAllows bool, failed string, inProgress bool) (install bool, reason string) {
	switch {
	case inProgress:
		return false, ReasonInProgress
	case Validate(ref) != nil:
		return false, ReasonInvalid
	case ref.Version != buildinfo.Version:
		return false, ReasonAgentVersion
	case ref.Version == failed:
		return false, ReasonFailed
	case installed == "":
		return false, ReasonNotInstalled
	case semver.Compare(fromDebian(installed), ref.Version) >= 0:
		return false, ReasonCurrent
	case !policyAllows:
		return false, ReasonPolicy
	}
	return true, ""
}

// fromDebian turns the Debian version of a package back into its release version: `make deb` writes the SemVer
// pre-release separator as ~ (0.1.0~alpha.1), and dpkg sorts it the same way SemVer sorts 0.1.0-alpha.1.
func fromDebian(v string) string { return strings.Replace(v, "~", "-", 1) }

// Stage downloads the package to <packages>/paddock-supervisor_<version>_<arch>.deb and checks its SHA-256.
func Stage(ctx context.Context, download func(ctx context.Context, url string, max int64) ([]byte, error), l paths.Layout, url string, ref bundle.PackageRef) (path string, err error) {
	if err := Validate(ref); err != nil {
		return "", err
	}
	deb, err := download(ctx, url, MaxPackage)
	if err != nil {
		return "", fmt.Errorf("download %s: %w", ref.URLPath, err)
	}
	if sum := sha256.Sum256(deb); hex.EncodeToString(sum[:]) != ref.SHA256 {
		return "", fmt.Errorf("download %s: SHA-256 %x, want %s", ref.URLPath, sum, ref.SHA256)
	}
	file := filepath.Join(l.Packages(), Package+"_"+ref.Version+"_"+runtime.GOARCH+".deb")
	if err := fsutil.WriteFile(file, deb, 0o600, 0o700); err != nil {
		return "", err
	}
	return file, nil
}

// Marker is supervisor-upgrade.json, written before the helper starts and removed when it wrote its result.
type Marker struct {
	Version     string    `json:"version"`
	FromVersion string    `json:"from_version"`
	StartedAt   time.Time `json:"started_at"`
}

// Result is supervisor-upgrade-result.json, the outcome of one upgrade.
type Result struct {
	Version     string    `json:"version"`
	FromVersion string    `json:"from_version"`
	Outcome     string    `json:"outcome"`
	At          time.Time `json:"at"`
}

// Launch starts the transient unit paddock-supervisor-upgrade.service (systemd-run --unit … --collect
// --no-block --property=KillMode=process <current>/paddockd supervisor-upgrade --deb <path> --from <installed>)
// and writes <state>/supervisor-upgrade.json {version, from_version, started_at}.
func Launch(ctx context.Context, run func(ctx context.Context, name string, args ...string) error, l paths.Layout, deb, version, from string) error {
	// The marker is written first: the helper may finish before systemd-run returns, and the agent must never start a
	// second helper while one runs.
	if err := writeJSON(l.SupervisorUpgrade(), Marker{Version: version, FromVersion: from, StartedAt: time.Now().UTC()}); err != nil {
		return err
	}
	err := run(ctx, "systemd-run", "--unit="+UpgradeUnit, "--collect", "--no-block", "--property=KillMode=process",
		filepath.Join(l.Slots(), "current", "paddockd"), "supervisor-upgrade", "--deb", deb, "--from", from)
	if err != nil {
		_ = remove(l.SupervisorUpgrade())
		return fmt.Errorf("start %s: %w", UpgradeUnit, err)
	}
	return nil
}

// ReadMarker reads supervisor-upgrade.json; nil when no upgrade runs.
func ReadMarker(l paths.Layout) (*Marker, error) {
	var m Marker
	ok, err := readJSON(l.SupervisorUpgrade(), &m)
	if !ok {
		return nil, err
	}
	return &m, nil
}

// ReadResult reads supervisor-upgrade-result.json; nil when there is none.
func ReadResult(l paths.Layout) (*Result, error) {
	var r Result
	ok, err := readJSON(l.SupervisorUpgradeResult(), &r)
	if !ok {
		return nil, err
	}
	return &r, nil
}

// WriteResult writes the result and removes the marker.
func WriteResult(l paths.Layout, r Result) error {
	if err := writeJSON(l.SupervisorUpgradeResult(), r); err != nil {
		return err
	}
	return remove(l.SupervisorUpgrade())
}

// RemoveResult deletes the result once its event was accepted.
func RemoveResult(l paths.Layout) error { return remove(l.SupervisorUpgradeResult()) }

// VersionOf returns the package version of a staged package path (paddock-supervisor_<version>_<arch>.deb).
func VersionOf(deb string) (string, error) {
	m := debName.FindStringSubmatch(path.Base(deb))
	if m == nil {
		return "", fmt.Errorf("%s is not a paddock-supervisor package", deb)
	}
	return m[1], nil
}

func writeJSON(file string, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return fsutil.WriteFile(file, append(data, '\n'), 0o600, 0o700)
}

func readJSON(file string, v any) (bool, error) {
	data, err := os.ReadFile(file) //nolint:gosec // path of the agent layout
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if err := json.Unmarshal(data, v); err != nil {
		return false, fmt.Errorf("parse %s: %w", file, err)
	}
	return true, nil
}

func remove(file string) error {
	if err := os.Remove(file); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}
