package integrity

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/phischl/paddock-mdm/agent/internal/paths"
	"github.com/phischl/paddock-mdm/agent/internal/reconcile"
	"github.com/phischl/paddock-mdm/agent/internal/supervisorpkg"
)

const supervisorPackage = supervisorpkg.Package

// supervisorFiles are the files the supervisor upgrade helper copies back on a rollback (plan M5a C5).
func supervisorFiles() []string { return []string{supervisorpkg.Binary, supervisorpkg.UnitFile} }

// pkgSpec is one dpkg package of plan M5a C2 and the md5sums entries checked for it.
type pkgSpec struct {
	name    string
	checked func(entry string) bool
}

// paddockEntry skips documentation, which no Paddock component reads.
func paddockEntry(entry string) bool {
	return !strings.HasPrefix(entry, "usr/share/doc/") && !strings.HasPrefix(entry, "usr/share/lintian/")
}

// fleetdEntry keeps fleetd's binaries and its unit; the rest of the package is data orbit itself rewrites.
func fleetdEntry(entry string) bool {
	return strings.HasPrefix(entry, "opt/orbit/bin/") || strings.HasSuffix(entry, "systemd/system/"+reconcile.FleetdUnit)
}

func packageSpecs() []pkgSpec {
	return []pkgSpec{
		{name: "paddock-agent", checked: paddockEntry},
		{name: supervisorPackage, checked: paddockEntry},
		{name: "paddock-revoke", checked: paddockEntry},
		{name: "paddock-self-service", checked: paddockEntry},
		{name: reconcile.FleetdPackage, checked: fleetdEntry},
	}
}

// debianArch is the Debian name of a Go architecture, used in the md5sums file name of multi-arch packages.
func debianArch(goarch string) string {
	switch goarch {
	case "386":
		return "i386"
	case "arm":
		return "armhf"
	}
	return goarch
}

// readMD5Sums reads dpkg's md5sums of a package as device path → MD5, with the raw content for the race guard; ok is
// false when the package has no md5sums file (it is not installed). The arch-qualified name comes first (plan M5a
// C5).
func readMD5Sums(l paths.Layout, pkg, arch string) (map[string]string, []byte, error) {
	var raw []byte
	var err error
	for _, name := range []string{pkg + ":" + debianArch(arch), pkg} {
		raw, err = os.ReadFile(l.Join("/var/lib/dpkg/info/" + name + ".md5sums")) //nolint:gosec // dpkg's database below the layout
		if !errors.Is(err, fs.ErrNotExist) {
			break
		}
	}
	if err != nil {
		return nil, nil, err
	}
	sums := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(raw))
	for sc.Scan() {
		sum, entry, ok := strings.Cut(sc.Text(), "  ")
		if ok && entry != "" {
			sums["/"+entry] = sum
		}
	}
	return sums, raw, sc.Err()
}

// packageStatus is dpkg's db:Status-Status of a package ("installed" when it is fully installed).
func (c *Checker) packageStatus(ctx context.Context, pkg string) (string, error) {
	out, err := c.Sys.Output(ctx, "dpkg-query", "-W", "-f=${db:Status-Status}", pkg)
	return strings.TrimSpace(string(out)), err
}

// checkPackages compares the files of the dpkg packages with their md5sums (plan M5a C5). supervisorBusy skips the
// supervisor package while its upgrade runs or its result is not processed.
func (c *Checker) checkPackages(ctx context.Context, b *Baseline, supervisorBusy bool, obs map[string]observed) {
	if c.DpkgBusy() {
		return
	}
	for _, spec := range packageSpecs() {
		if spec.name == supervisorPackage && supervisorBusy {
			continue
		}
		c.checkPackage(ctx, b, spec, obs)
	}
}

// observed is the value of one checked path in a pass and whether it is what the baseline expects.
type observed struct {
	value    string
	expected bool
}

func (c *Checker) checkPackage(ctx context.Context, b *Baseline, spec pkgSpec, obs map[string]observed) {
	sums, raw, err := readMD5Sums(c.Layout, spec.name, c.Arch)
	if errors.Is(err, fs.ErrNotExist) {
		return
	}
	if err != nil {
		c.warn("package:"+spec.name, "reading dpkg's md5sums failed", err)
		return
	}
	if status, err := c.packageStatus(ctx, spec.name); err != nil || status != "installed" {
		if err != nil {
			c.warn("package:"+spec.name, "asking dpkg for the package status failed", err)
		}
		return
	}
	found := map[string]observed{}
	for path, sum := range sums {
		if !spec.checked(strings.TrimPrefix(path, "/")) {
			continue
		}
		sha, md5sum, err := c.hash.file(c.Layout, path)
		if err != nil {
			c.warn(path, "hashing a package file failed", err)
			continue
		}
		found[path] = observed{value: sha, expected: md5sum == sum || excepted(b, path, sum, sha)}
	}
	// dpkg may have rewritten the package meanwhile: its result is checked in the next pass (race guard, C5).
	_, again, err := readMD5Sums(c.Layout, spec.name, c.Arch)
	if err != nil || !bytes.Equal(raw, again) || c.DpkgBusy() {
		return
	}
	for path, o := range found {
		obs[path] = o
	}
	if spec.name == supervisorPackage {
		b.Exceptions = slices.DeleteFunc(b.Exceptions, func(e Exception) bool { return sums[e.Path] != e.MD5 })
	}
}

// excepted reports whether a supervisor rollback exception covers the file (plan M5a C5).
func excepted(b *Baseline, path, sum, sha string) bool {
	for _, e := range b.Exceptions {
		if e.Path == path && e.MD5 == sum && e.SHA256 == sha {
			return true
		}
	}
	return false
}

// unitSpec is one unit of plan M5a C6 with its expected fragment ("" = not checked).
type unitSpec struct {
	name, fragment string
}

func (c *Checker) unitSpecs() []unitSpec {
	orbit := ""
	if sums, _, err := readMD5Sums(c.Layout, reconcile.FleetdPackage, c.Arch); err == nil {
		for path := range sums {
			if strings.HasSuffix(path, "/systemd/system/"+reconcile.FleetdUnit) {
				orbit = path
			}
		}
	}
	return []unitSpec{
		{name: supervisorpkg.Service, fragment: supervisorpkg.UnitFile},
		{name: "paddock-disk-setup.service", fragment: "/usr/lib/systemd/system/paddock-disk-setup.service"},
		{name: reconcile.FleetdUnit, fragment: orbit},
		{name: filepath.Base(reconcile.RegularService), fragment: reconcile.RegularService},
		{name: filepath.Base(reconcile.RegularTimer), fragment: reconcile.RegularTimer},
	}
}

// allowedUnitFile reports the unit files Paddock itself writes into the override directories (plan M5a C6).
func allowedUnitFile(path string) bool {
	return path == reconcile.FleetdDropIn || path == reconcile.RegularService || path == reconcile.RegularTimer
}

// checkUnits finds foreign overrides and drop-ins of the five units (plan M5a C6). A foreign path is observed as
// "present:<SHA-256>" against the expected absence. complete is false when systemd could not be asked for a unit.
func (c *Checker) checkUnits(ctx context.Context, obs map[string]observed) (complete bool) {
	complete = true
	foreign := map[string]bool{}
	for _, u := range c.unitSpecs() {
		for _, dir := range []string{"/etc/systemd/system/", "/run/systemd/system/"} {
			if _, err := os.Lstat(c.Layout.Join(dir + u.name)); err == nil && !allowedUnitFile(dir+u.name) {
				foreign[dir+u.name] = true
			}
			confs, _ := filepath.Glob(c.Layout.Join(dir + u.name + ".d/*.conf"))
			for _, f := range confs {
				if p := devicePath(c.Layout, f); !allowedUnitFile(p) {
					foreign[p] = true
				}
			}
		}
		fragment, dropIns, loaded, err := c.show(ctx, u.name)
		if err != nil {
			c.warn("unit:"+u.name, "asking systemd for the unit's files failed", err)
			complete = false
			continue
		}
		if !loaded {
			continue
		}
		if u.fragment != "" && fragment != "" && c.canonical(fragment) != c.canonical(u.fragment) {
			foreign[fragment] = true
		}
		for _, p := range dropIns {
			if c.canonical(p) != c.canonical(reconcile.FleetdDropIn) {
				foreign[p] = true
			}
		}
	}
	for p := range foreign {
		sha, _, err := c.hash.file(c.Layout, p)
		if err != nil {
			c.warn(p, "hashing a foreign unit file failed", err)
			complete = false
			continue
		}
		obs[p] = observed{value: "present:" + sha}
	}
	return complete
}

// show asks systemd for the effective fragment and drop-ins of a unit; loaded is false for a unit systemd does not
// know (plan M5a C6).
func (c *Checker) show(ctx context.Context, unit string) (fragment string, dropIns []string, loaded bool, err error) {
	out, exit, err := c.Sys.Systemctl(ctx, "show", "-p", "LoadState", "-p", "FragmentPath", "-p", "DropInPaths", "--", unit)
	if err == nil && exit != 0 {
		err = fmt.Errorf("systemctl show: exit %d", exit)
	}
	if err != nil {
		return "", nil, false, err
	}
	for _, line := range strings.Split(out, "\n") {
		key, value, _ := strings.Cut(strings.TrimSpace(line), "=")
		switch key {
		case "LoadState":
			loaded = value != "not-found"
		case "FragmentPath":
			fragment = value
		case "DropInPaths":
			dropIns = strings.Fields(value)
		}
	}
	return fragment, dropIns, loaded, nil
}

// canonical resolves the directory of a unit path, because /lib is a symlink to /usr/lib (plan M5a C6).
func (c *Checker) canonical(path string) string {
	dir, err := filepath.EvalSymlinks(c.Layout.Join(filepath.Dir(path)))
	if err != nil {
		return path
	}
	return filepath.Join(dir, filepath.Base(path))
}
