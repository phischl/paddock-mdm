package reconcile

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/phischl/paddock-mdm/pkg/bundle"
	"github.com/phischl/paddock-mdm/pkg/protocol"
)

// InventoryID is the plan and report ID of the bundle's inventory section (plan M5a decision 5).
const InventoryID = "inventory"

// fleetd's package, unit and the files Paddock gives it (plan M5a decision 5). fleetd and these paths are a protected
// area: a change is reverted at the next drift pass and reported as tamper.protected_file_changed.
const (
	FleetdPackage    = "fleet-osquery"
	FleetdUnit       = "orbit.service"
	FleetdEnrollFile = "/opt/orbit/secret.txt"
	// FleetdEnv overrides the package's /etc/default/orbit: the drop-in reads it after that file.
	FleetdEnv    = "/etc/paddock/orbit.env"
	FleetdDropIn = "/etc/systemd/system/orbit.service.d/90-paddock.conf"
	// fleetdDownloads keeps a downloaded package until dpkg installed it.
	fleetdDownloads = "/var/lib/paddock/packages"
	// fleetdMaxPackage bounds the download (the server accepts packages up to 128 MiB).
	fleetdMaxPackage = 128 << 20
	// fleetdCACertificates is the system trust store; fleetd and osquery trust the same CAs as the agent.
	fleetdCACertificates = "/etc/ssl/certs/ca-certificates.crt"
)

var (
	fleetdVersion = regexp.MustCompile(`^[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}$`)
	sha256Hex     = regexp.MustCompile(`^[0-9a-f]{64}$`)
	fleetdPath    = regexp.MustCompile(`^packages/[0-9A-Za-z.+~-]{1,64}/fleet-osquery_[0-9.]{5,14}_amd64\.deb$`)
)

// Inventory installs fleetd from Paddock's package store and enrolls it into Fleet with the bundle's enroll secret
// (plan M5a decision 5), and keeps orbit.service running (mutual watch): a stopped service is reported as
// tamper.service_stopped and started again. It changes nothing on a device that is not amd64.
type Inventory struct {
	Sys    System
	Events *Events
	// Download fetches a URL with at most limit bytes (client.Client.Download).
	Download func(ctx context.Context, url string, limit int64) ([]byte, error)
	// BundlesURL is https://bundles.<domain>[:port], the public package store.
	BundlesURL string
	Now        func() time.Time

	// applied is the spec of the last successful Apply: a file that differs from the same spec was changed
	// outside Paddock. stopped is set while a service stop is reported.
	applied []byte
	stopped bool
	// Package installations killed at PackageTimeout back off like the login reconciler's (plan M4b.1 step 6).
	timeouts   int
	retryAt    time.Time
	timeoutErr error
}

// Type implements Reconciler.
func (i *Inventory) Type() string { return InventoryID }

func (i *Inventory) spec(r bundle.Resource) (bundle.Inventory, error) {
	var s bundle.Inventory
	if err := json.Unmarshal(r.Spec, &s); err != nil {
		return s, fmt.Errorf("invalid inventory spec: %w", err)
	}
	if !strings.HasPrefix(s.FleetURL, "https://") || strings.ContainsAny(s.FleetURL, " \t\r\n\"'") {
		return s, fmt.Errorf("invalid fleet_url %q", s.FleetURL)
	}
	if s.EnrollSecret == "" || strings.ContainsAny(s.EnrollSecret, "\r\n") {
		return s, errors.New("invalid enroll_secret")
	}
	p := s.Package
	if !fleetdVersion.MatchString(p.Version) || !sha256Hex.MatchString(p.SHA256) || !fleetdPath.MatchString(p.URLPath) ||
		path.Base(p.URLPath) != "fleet-osquery_"+p.Version+"_amd64.deb" {
		return s, fmt.Errorf("invalid fleetd package %+v", p)
	}
	return s, nil
}

// fleetdFiles are the files Paddock writes for fleetd, with their modes.
func fleetdFiles(s bundle.Inventory) []struct {
	path string
	data []byte
	mode fs.FileMode
} {
	env := "# Managed by Paddock. Do not edit: local changes are reverted.\n" +
		"ORBIT_FLEET_URL=" + s.FleetURL + "\n" +
		"ORBIT_ENROLL_SECRET_PATH=" + FleetdEnrollFile + "\n" +
		"ORBIT_FLEET_CERTIFICATE=" + fleetdCACertificates + "\n" +
		"ORBIT_DISABLE_UPDATES=true\nORBIT_ENABLE_SCRIPTS=false\nORBIT_FLEET_DESKTOP=false\n"
	dropIn := "# Managed by Paddock. Do not edit: local changes are reverted.\n[Service]\nEnvironmentFile=" + FleetdEnv + "\n"
	return []struct {
		path string
		data []byte
		mode fs.FileMode
	}{
		{FleetdEnrollFile, []byte(s.EnrollSecret), 0o600},
		{FleetdEnv, []byte(env), 0o600},
		{FleetdDropIn, []byte(dropIn), 0o644},
	}
}

// Plan implements Reconciler.
func (i *Inventory) Plan(ctx context.Context, r bundle.Resource) ([]string, error) {
	s, err := i.spec(r)
	if err != nil || runtime.GOARCH != "amd64" {
		return nil, err
	}
	var changes []string
	for _, f := range fleetdFiles(s) {
		if !fileHas(i.Sys, f.path, f.data, f.mode) {
			changes = append(changes, "file "+f.path)
		}
	}
	if i.Sys.PackageVersion(FleetdPackage) != s.Package.Version {
		return append(changes, "package "+s.Package.Version), nil
	}
	units, err := unitChanges(ctx, i.Sys, FleetdUnit, true, true)
	if err != nil {
		return nil, err
	}
	return append(changes, units...), nil
}

// Apply implements Reconciler: fleetd's files first, so that the package's postinst starts a configured fleetd, then
// the package, then the unit.
func (i *Inventory) Apply(ctx context.Context, r bundle.Resource) Result {
	s, err := i.spec(r)
	if err != nil {
		return errorResult(r.ID, err)
	}
	if runtime.GOARCH != "amd64" {
		return Result{ID: r.ID, Status: OK}
	}
	changed, err := i.writeFiles(ctx, s, r.Spec)
	if err != nil {
		return errorResult(r.ID, err)
	}
	if i.Sys.PackageVersion(FleetdPackage) != s.Package.Version {
		if err := i.installPackage(ctx, s.Package); err != nil {
			return errorResult(r.ID, fmt.Errorf("install fleetd %s: %w", s.Package.Version, err))
		}
		changed = true
	}
	units, err := unitChanges(ctx, i.Sys, FleetdUnit, true, true)
	if err != nil {
		return errorResult(r.ID, err)
	}
	if len(units) > 0 && bytes.Equal(i.applied, r.Spec) && !i.stopped {
		i.stopped = true
		i.Events.emit(protocol.EventTamperServiceStopped, protocol.TamperServiceStopped{Unit: FleetdUnit})
	}
	if err := run(ctx, i.Sys, units); err != nil {
		return errorResult(r.ID, err)
	}
	i.stopped = false
	i.applied = bytes.Clone(r.Spec)
	if !changed && len(units) == 0 {
		return Result{ID: r.ID, Status: OK}
	}
	return Result{ID: r.ID, Status: Changed}
}

// writeFiles writes fleetd's files that differ and restarts fleetd if it is installed. A file that differs from the
// spec applied before was changed outside Paddock.
func (i *Inventory) writeFiles(ctx context.Context, s bundle.Inventory, raw []byte) (bool, error) {
	changed := false
	for _, f := range fleetdFiles(s) {
		if fileHas(i.Sys, f.path, f.data, f.mode) {
			continue
		}
		if bytes.Equal(i.applied, raw) {
			i.Events.emit(protocol.EventTamperProtectedFileChanged, protocol.TamperProtectedFileChanged{File: f.path})
		}
		if err := i.Sys.WriteFileAtomic(f.path, f.data, f.mode, 0, 0); err != nil {
			return changed, err
		}
		changed = true
	}
	if !changed || !i.Sys.PackageInstalled(FleetdPackage) {
		return changed, nil
	}
	return true, run(ctx, i.Sys, []string{"systemctl daemon-reload", "systemctl restart " + FleetdUnit})
}

// installPackage downloads the package, checks its SHA-256 and installs it with dpkg. A run killed at its timeout is
// retried after a back-off; an interrupted installation is finished with `dpkg --configure -a` first.
func (i *Inventory) installPackage(ctx context.Context, p bundle.InventoryPackage) error {
	now := i.now()
	if now.Before(i.retryAt) {
		return i.timeoutErr
	}
	if i.BundlesURL == "" || i.Download == nil {
		return errors.New("no package store configured")
	}
	deb, err := i.Download(ctx, strings.TrimRight(i.BundlesURL, "/")+"/"+p.URLPath, fleetdMaxPackage)
	if err != nil {
		return fmt.Errorf("download %s: %w", p.URLPath, err)
	}
	if sum := sha256.Sum256(deb); hex.EncodeToString(sum[:]) != p.SHA256 {
		return fmt.Errorf("download %s: SHA-256 %x, want %s", p.URLPath, sum, p.SHA256)
	}
	file := fleetdDownloads + "/" + path.Base(p.URLPath)
	if err := i.Sys.WriteFileAtomic(file, deb, 0o600, 0, 0); err != nil {
		return err
	}
	defer func() { _ = i.Sys.Remove(file) }()
	err = i.dpkg(ctx, "-i", file)
	if err != nil && strings.Contains(err.Error(), "dpkg was interrupted") {
		if err = i.dpkg(ctx, "--configure", "-a"); err == nil {
			err = i.dpkg(ctx, "-i", file)
		}
	}
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		backoff := aptBackoffMax
		if i.timeouts < 4 {
			backoff = min(PackageTimeout<<i.timeouts, aptBackoffMax)
		}
		i.timeouts++
		i.retryAt = now.Add(backoff)
		i.timeoutErr = fmt.Errorf("killed after %s, next attempt in %s: %w", PackageTimeout, backoff, err)
		return i.timeoutErr
	case err != nil:
		return err
	}
	i.timeouts, i.retryAt, i.timeoutErr = 0, time.Time{}, nil
	if v := i.Sys.PackageVersion(FleetdPackage); v != p.Version {
		return fmt.Errorf("fleetd %s is not installed after dpkg -i (installed: %q)", p.Version, v)
	}
	return nil
}

// dpkg runs dpkg; a non-zero exit is an error with the last output lines.
func (i *Inventory) dpkg(ctx context.Context, args ...string) error {
	out, exit, err := i.Sys.Dpkg(ctx, args...)
	if err != nil {
		return fmt.Errorf("dpkg %s: %w", args[0], err)
	}
	if exit != 0 {
		return fmt.Errorf("dpkg %s: exit %d: %s", args[0], exit, strings.TrimSpace(out))
	}
	return nil
}

func (i *Inventory) now() time.Time {
	if i.Now != nil {
		return i.Now()
	}
	return time.Now()
}

// InventoryResource turns the bundle's inventory section into the resource the applier plans and applies.
func InventoryResource(inv *bundle.Inventory) (bundle.Resource, error) {
	spec, err := json.Marshal(inv)
	return bundle.Resource{ID: InventoryID, Type: InventoryID, Spec: spec}, err
}
