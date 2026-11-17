package integrity

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
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

// readMD5Sums reads dpkg's md5sums of a package as device path → MD5, with the raw content for the race guard and the
// file name it read (the last one tried when none exists, which is a not-exist error: the package is not installed).
// The arch-qualified name comes first (plan M5a C5).
func readMD5Sums(l paths.Layout, pkg, arch string) (sums map[string]string, raw []byte, file string, err error) {
	for _, name := range []string{pkg + ":" + debianArch(arch), pkg} {
		file = "/var/lib/dpkg/info/" + name + ".md5sums"
		raw, err = readRegular(l.Join(file), maxMD5Sums)
		if !errors.Is(err, fs.ErrNotExist) {
			break
		}
	}
	if err != nil {
		return nil, nil, file, err
	}
	sums = map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(raw))
	for sc.Scan() {
		sum, entry, ok := strings.Cut(sc.Text(), "  ")
		if ok && entry != "" {
			sums["/"+entry] = sum
		}
	}
	return sums, raw, file, sc.Err()
}

// packageStatus is dpkg's db:Status-Status of a package ("installed" when it is fully installed).
func (c *Checker) packageStatus(ctx context.Context, pkg string) (string, error) {
	out, err := c.Sys.Output(ctx, "dpkg-query", "-W", "-f=${db:Status-Status}", pkg)
	return strings.TrimSpace(string(out)), err
}

// observePackages hashes the files of the dpkg packages with their md5sums entries (plan M5a C5, R1). supervisorBusy
// skips the supervisor package while its upgrade runs or its result is not processed.
func (c *Checker) observePackages(ctx context.Context, s *snapshot, supervisorBusy bool) {
	if c.DpkgBusy() {
		for _, spec := range packageSpecs() {
			s.blocked.block("package:"+spec.name, 2, reconcile.DpkgFrontendLock)
		}
		return
	}
	for _, spec := range packageSpecs() {
		if spec.name == supervisorPackage && supervisorBusy {
			continue
		}
		c.observePackage(ctx, spec, s)
	}
}

// observed is the value of one checked path in a pass and whether it is what the baseline expects.
type observed struct {
	value    string
	expected bool
}

// pkgFile is a package file as observed, with its md5sums entry.
type pkgFile struct {
	sha, md5, entry string
}

func (c *Checker) observePackage(ctx context.Context, spec pkgSpec, s *snapshot) {
	sums, raw, file, err := readMD5Sums(c.Layout, spec.name, c.Arch)
	if errors.Is(err, fs.ErrNotExist) {
		return
	}
	key := "package:" + spec.name
	if err != nil {
		c.warn(key, "reading dpkg's md5sums failed", err)
		s.blocked.block(key, 3, file)
		return
	}
	if status, err := c.packageStatus(ctx, spec.name); err != nil || status != "installed" {
		if err != nil {
			c.warn(key, "asking dpkg for the package status failed", err)
			s.blocked.block(key, 3, file)
		}
		return
	}
	found := map[string]pkgFile{}
	for path, sum := range sums {
		if !spec.checked(strings.TrimPrefix(path, "/")) {
			continue
		}
		sha, md5sum, err := c.hash.file(c.Layout, path)
		if err != nil {
			c.warn(path, "hashing a package file failed", err)
			s.blocked.block(key, 4, path)
			continue
		}
		found[path] = pkgFile{sha: sha, md5: md5sum, entry: sum}
	}
	// dpkg may have rewritten the package meanwhile: its result is checked in the next pass (race guard, C5).
	_, again, _, err := readMD5Sums(c.Layout, spec.name, c.Arch)
	if c.DpkgBusy() {
		s.blocked.block(key, 2, reconcile.DpkgFrontendLock)
		return
	}
	if err != nil || !bytes.Equal(raw, again) {
		s.blocked.block(key, 3, file)
		return
	}
	maps.Copy(s.pkgFiles, found)
	if spec.name == supervisorPackage {
		s.supervisorSums = sums
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
	if sums, _, _, err := readMD5Sums(c.Layout, reconcile.FleetdPackage, c.Arch); err == nil {
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

// observeUnits finds foreign overrides and drop-ins of the five units (plan M5a C6). A foreign path is observed as
// "present:<SHA-256>" against the expected absence. unitsComplete is false when systemd could not be asked for a
// unit or a foreign file could not be hashed.
func (c *Checker) observeUnits(ctx context.Context, s *snapshot) {
	s.unitsComplete = true
	foreign := map[string]string{} // path → unit
	for _, u := range c.unitSpecs() {
		for _, dir := range []string{"/etc/systemd/system/", "/run/systemd/system/"} {
			if _, err := os.Lstat(c.Layout.Join(dir + u.name)); err == nil && !allowedUnitFile(dir+u.name) {
				foreign[dir+u.name] = u.name
			}
			confs, _ := filepath.Glob(c.Layout.Join(dir + u.name + ".d/*.conf"))
			for _, f := range confs {
				if p := devicePath(c.Layout, f); !allowedUnitFile(p) {
					foreign[p] = u.name
				}
			}
		}
		fragment, dropIns, loaded, err := c.show(ctx, u.name)
		if err != nil {
			c.warn("unit:"+u.name, "asking systemd for the unit's files failed", err)
			s.blocked.block("unit:"+u.name, 0, "/etc/systemd/system/"+u.name+".d")
			s.unitsComplete = false
			continue
		}
		if !loaded {
			continue
		}
		if u.fragment != "" && fragment != "" && c.canonical(fragment) != c.canonical(u.fragment) {
			foreign[fragment] = u.name
		}
		for _, p := range dropIns {
			if c.canonical(p) != c.canonical(reconcile.FleetdDropIn) {
				foreign[p] = u.name
			}
		}
	}
	for p, unit := range foreign {
		sha, _, err := c.hash.file(c.Layout, p)
		if err != nil {
			c.warn(p, "hashing a foreign unit file failed", err)
			s.blocked.block("unit:"+unit, 1, p)
			s.unitsComplete = false
			continue
		}
		s.obs[p] = observed{value: "present:" + sha}
	}
}

// show asks systemd for the effective fragment and drop-ins of a unit; loaded is false for a unit systemd does not
// know (plan M5a C6). DropInPaths that does not parse is an error, never a clean unit (R9).
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
			if dropIns, err = splitQuoted(value); err != nil {
				return "", nil, false, fmt.Errorf("systemctl show DropInPaths: %w", err)
			}
		}
	}
	return fragment, dropIns, loaded, nil
}

// splitQuoted splits a list of systemctl show: elements are separated by single spaces, systemd quotes an element
// that needs it with ", and a backslash escapes the next character inside and outside quotes (plan M5a R9). An
// unterminated quote is an error: a path with a newline splits the line.
func splitQuoted(s string) ([]string, error) {
	var out []string
	var cur strings.Builder
	quoted, escaped, started := false, false, false
	for _, r := range s {
		switch {
		case escaped:
			cur.WriteRune(r)
			escaped = false
		case r == '\\':
			escaped, started = true, true
		case r == '"':
			quoted, started = !quoted, true
		case r == ' ' && !quoted:
			if started {
				out = append(out, cur.String())
				cur.Reset()
				started = false
			}
		default:
			cur.WriteRune(r)
			started = true
		}
	}
	if quoted || escaped {
		return nil, fmt.Errorf("unterminated quote in %q", s)
	}
	if started {
		out = append(out, cur.String())
	}
	return out, nil
}

// canonical resolves the directory of a unit path, because /lib is a symlink to /usr/lib (plan M5a C6).
func (c *Checker) canonical(path string) string {
	dir, err := filepath.EvalSymlinks(c.Layout.Join(filepath.Dir(path)))
	if err != nil {
		return path
	}
	return filepath.Join(dir, filepath.Base(path))
}
