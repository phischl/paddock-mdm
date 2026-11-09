package reconcile

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/phischl/paddock-mdm/pkg/bundle"
	"github.com/phischl/paddock-mdm/pkg/openpgpkey"
	"github.com/phischl/paddock-mdm/pkg/protocol"
)

// The files of the software reconciler (plan M13a decision 20). They are protected (ADR 0042 decision 9): a change is
// reverted at the next drift pass and reported as tamper.protected_file_changed.
const (
	SoftwareSourceDir  = "/etc/apt/sources.list.d"
	SoftwareKeyringDir = "/etc/apt/keyrings"
	SoftwarePrefix     = "paddock-"
	// SoftwareForbidFile blocks the forbidden packages for apt; it sorts after the updates pin file 50paddock.
	SoftwareForbidFile = "/etc/apt/preferences.d/51paddock-software"
	// softwareInstalledRecord lists the required packages the reconciler saw installed, one per line: a recorded
	// package that is gone was removed locally and is reinstalled as such.
	softwareInstalledRecord = "/var/lib/paddock/state/software-installed"
	// softwareSourcesRecord lists the sources whose files the reconciler wrote, one slug per line: the proof that a
	// bundle without the section may remove them (architect decision 2026-11-03).
	softwareSourcesRecord = "/var/lib/paddock/state/software-sources"
	// softwareRetryPasses is how many passes of an unchanged spec a package whose apt-get install failed waits for its
	// next installation: about an hour at the drift interval, instead of a dpkg run every five minutes.
	softwareRetryPasses = 12
	// RemovalWindow is how long after the last successful check-in the reconciler still removes packages (plan M13a
	// decision 25): nothing is removed while the server is unreachable (design contract 8).
	RemovalWindow = 15 * time.Minute
	// softwareItemError bounds the error of a status item so that 200 failed items fit the check-in (PDK-700);
	// softwareEventError is the bound of SoftwareApplyFailed.Error.
	softwareItemError  = 120
	softwareEventError = 200
	// softwareMessage bounds the list of failures in the resource's message, which every bundle.applied carries.
	softwareMessage = 500
)

// softwareLockWait lets apt wait a minute for a dpkg lock held by another package operation; a longer wait ends the
// pass as pending/dpkg_locked and the drift loop retries (plan M13a decision 23).
var softwareLockWait = []string{"-o", "DPkg::Lock::Timeout=60"}

// errDpkgLocked ends a pass whose apt step found the dpkg lock held.
var errDpkgLocked = errors.New("dpkg locked; retrying at the next pass")

// Software installs, removes and blocks the packages of the bundle's software section and keeps their APT sources
// (plan M13a decisions 20–24). It never calls apt-mark: holds belong to the updates reconciler (ADR 0042 decision 3).
type Software struct {
	Sys    System
	Events *Events
	// ServerReachable reports whether the last successful check-in is recent; removals wait while it is false. Nil
	// counts as unreachable.
	ServerReachable func() bool
	// applied is the spec of the last pass that wrote the files: a file that differs from the same spec was changed
	// outside Paddock.
	applied []byte
	// failures is the last reported failure (stage/reason) per "package:<name>" or "source:<slug>", so that an
	// unchanged failure is reported once; refresh are sources whose scoped apt-get update failed and is repeated.
	failures map[string]string
	refresh  map[string]bool
	// retry counts the passes left before a failed installation runs again, with its error, by package; conflict
	// counts them before a source rolled back for conflicting with a source of the device is written again, by slug.
	retry    map[string]softwareRetry
	conflict map[string]softwareRetry
	// unchecked are written sources whose configuration check did not complete: their scoped update waits for the
	// next check.
	unchecked map[string]bool
	status    *protocol.SoftwareHealth
	// userScoped is set while the spec has Flatpak applications for listed users; seenSessions are the users with a
	// session the last pass or NewUserSession saw.
	userScoped   bool
	seenSessions []int
}

type softwareRetry struct {
	passes int
	err    string
}

// Type implements Reconciler.
func (s *Software) Type() string { return bundle.TypeSoftware }

// KnownPackage reports whether apt has a real package of exactly this name. apt-get and apt-mark read an argument they
// have no package of that name for as a regular expression ("himmelblau." selects every himmelblau package), so a
// package name from a bundle or a command reaches apt only when this holds (architect decision 2026-11-03);
// apt-cache pkgnames lists by prefix, without a regex. A failing apt-cache is an error, not an unknown name: apt that
// cannot read its configuration must not show as "no candidate" (PDK-710).
func KnownPackage(ctx context.Context, sys System, name string) (bool, error) {
	out, exit, err := sys.AptCache(ctx, "pkgnames", name)
	if err != nil {
		return false, fmt.Errorf("apt-cache pkgnames: %w", err)
	}
	if exit != 0 {
		return false, fmt.Errorf("apt-cache pkgnames: exit %d", exit)
	}
	return slices.Contains(strings.Fields(out), name), nil
}

// SoftwareSourcePath is the deb822 file of a source.
func SoftwareSourcePath(slug string) string {
	return SoftwareSourceDir + "/" + SoftwarePrefix + slug + ".sources"
}

// SoftwareKeyringPath is the keyring of a source.
func SoftwareKeyringPath(slug string) string {
	return SoftwareKeyringDir + "/" + SoftwarePrefix + slug + ".gpg"
}

// spec decodes and validates the section. A package the protected tiers refuse fails the whole resource before
// anything is planned: the server never signs such a bundle (bundle.ValidateSoftware), so the agent refuses it again
// in case it does (defence in depth, plan M13a amendment 2026-11-02 M3).
func (s *Software) spec(r bundle.Resource) (bundle.SoftwareSpec, error) {
	var sp bundle.SoftwareSpec
	if err := json.Unmarshal(r.Spec, &sp); err != nil {
		return sp, fmt.Errorf("invalid software spec: %w", err)
	}
	for _, p := range sp.Packages {
		if p.FlatpakRef == "" && bundle.RefusedIntent(p.Package, p.Intent) {
			return sp, fmt.Errorf("refused: software package %q is protected against intent %s", p.Package, p.Intent)
		}
	}
	return sp, bundle.ValidateSoftware(sp)
}

func renderSoftwareSource(src bundle.SoftwareSource) []byte {
	var b strings.Builder
	b.WriteString(managedHeader)
	b.WriteString("Types: deb\n")
	b.WriteString("URIs: " + strings.Join(src.URIs, " ") + "\n")
	b.WriteString("Suites: " + strings.Join(src.Suites, " ") + "\n")
	if len(src.Components) > 0 {
		b.WriteString("Components: " + strings.Join(src.Components, " ") + "\n")
	}
	if len(src.Architectures) > 0 {
		b.WriteString("Architectures: " + strings.Join(src.Architectures, " ") + "\n")
	}
	b.WriteString("Signed-By: " + SoftwareKeyringPath(src.Slug) + "\n")
	return []byte(b.String())
}

func renderForbidPins(pkgs []string) []byte {
	if len(pkgs) == 0 {
		return nil
	}
	var b strings.Builder
	b.WriteString(managedHeader)
	for _, p := range pkgs {
		fmt.Fprintf(&b, "\nPackage: %s\nPin: release *\nPin-Priority: -1\n", p)
	}
	return []byte(b.String())
}

// sourceKeyring decodes the keyring of a source and checks it against the source's fingerprint (plan M13a decision
// 21); a source that fails is not written at all.
func sourceKeyring(src bundle.SoftwareSource) ([]byte, error) {
	keyring, err := base64.StdEncoding.DecodeString(src.Keyring)
	if err != nil {
		return nil, fmt.Errorf("keyring of source %s is not base64: %w", src.Slug, err)
	}
	fp, err := openpgpkey.FingerprintBinary(keyring)
	if err != nil {
		return nil, fmt.Errorf("keyring of source %s: %w", src.Slug, err)
	}
	if !strings.EqualFold(fp, src.Fingerprint) {
		return nil, fmt.Errorf("keyring of source %s has the fingerprint %s, not %s", src.Slug, fp, src.Fingerprint)
	}
	return keyring, nil
}

// forbidden returns the packages with intent forbid, sorted.
func forbidden(sp bundle.SoftwareSpec) []string {
	var out []string
	for _, p := range sp.Packages {
		if p.Intent == bundle.SoftwareForbid && p.FlatpakRef == "" {
			out = append(out, p.Package)
		}
	}
	slices.Sort(out)
	return out
}

// unmanaged returns the source and keyring files to remove. With a section: every paddock-*.sources and paddock-*.gpg
// file the spec does not name (protected area, ADR 0042 decision 9). For the empty section of a bundle without one
// (Residue): only the files of the sources Paddock recorded writing (architect decision 2026-11-03), never a file it
// cannot prove it wrote. The login reconciler's paddock-himmelblau.list and himmelblau.gpg never match, and are
// excluded by name as well.
func (s *Software) unmanaged(sp bundle.SoftwareSpec) []string {
	named := map[string]bool{himmelblauSource: true, himmelblauKeyring: true}
	for _, src := range sp.Sources {
		if !flatpakSource(src) {
			named[SoftwareSourcePath(src.Slug)], named[SoftwareKeyringPath(src.Slug)] = true, true
		}
	}
	var out []string
	if emptySection(sp) {
		for _, slug := range s.sourceSlugs() {
			for _, p := range []string{SoftwareSourcePath(slug), SoftwareKeyringPath(slug)} {
				if !named[p] && !s.absent(p) {
					out = append(out, p)
				}
			}
		}
		return out
	}
	for _, d := range []struct{ dir, suffix string }{{SoftwareSourceDir, ".sources"}, {SoftwareKeyringDir, ".gpg"}} {
		names, _ := s.Sys.ReadDir(d.dir) // a missing directory has no files to remove
		for _, n := range names {
			p := d.dir + "/" + n
			if strings.HasPrefix(n, SoftwarePrefix) && strings.HasSuffix(n, d.suffix) && !named[p] {
				out = append(out, p)
			}
		}
	}
	return out
}

// emptySection reports whether sp is the empty section the applier passes for a bundle without one: the compiler
// never signs an empty section, it omits it.
func emptySection(sp bundle.SoftwareSpec) bool {
	return len(sp.Sources) == 0 && len(sp.Packages) == 0
}

// sourceSlugs returns the sources whose files Paddock wrote (softwareSourcesRecord), sorted.
func (s *Software) sourceSlugs() []string {
	data, _, err := s.Sys.ReadFile(softwareSourcesRecord)
	if err != nil {
		return nil
	}
	out := strings.Fields(string(data))
	slices.Sort(out)
	return slices.Compact(out)
}

// forbidPins returns the forbid pin file the spec asks for (nil: absent) and whether the file on the device differs.
// The empty section of a bundle without one removes only a pin file that carries Paddock's header.
func (s *Software) forbidPins(sp bundle.SoftwareSpec) (pins []byte, differs bool) {
	pins = renderForbidPins(forbidden(sp))
	if pins != nil {
		return pins, !fileHas(s.Sys, SoftwareForbidFile, pins, 0o644)
	}
	data, _, err := s.Sys.ReadFile(SoftwareForbidFile)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil, false
	case emptySection(sp):
		return nil, err == nil && bytes.HasPrefix(data, []byte(managedHeader))
	}
	return nil, true
}

func (s *Software) absent(p string) bool {
	_, _, err := s.Sys.ReadFile(p)
	return errors.Is(err, fs.ErrNotExist)
}

// softwareOp is a planned package operation: verb install, reinstall or remove; target is the package, for a pinned
// installation package=version. An installation that only moves an installed package to its pinned version is no
// first installation.
type softwareOp struct {
	pkg     bundle.SoftwarePackage
	verb    string
	target  string
	upgrade bool
}

func (o softwareOp) line() string { return o.verb + " " + o.target }

// ops returns the APT package operations of a spec (plan M13a decision 22). A required package without version is
// installed when missing and never upgraded here: the update runs move it. Flatpak applications are applyFlatpak's.
func (s *Software) ops(sp bundle.SoftwareSpec) []softwareOp {
	recorded := s.recorded()
	var out []softwareOp
	for _, p := range sp.Packages {
		if p.FlatpakRef != "" {
			continue
		}
		installed := s.Sys.PackageInstalled(p.Package)
		switch p.Intent {
		case bundle.SoftwareRequired:
			target := p.Package
			if p.Version != nil {
				target += "=" + *p.Version
			}
			switch {
			case !installed && slices.Contains(recorded, p.Package):
				out = append(out, softwareOp{p, "reinstall", target, false})
			case !installed:
				out = append(out, softwareOp{p, "install", target, false})
			case p.Version != nil && s.Sys.PackageVersion(p.Package) != *p.Version:
				out = append(out, softwareOp{p, "install", target, true})
			}
		case bundle.SoftwareUninstall, bundle.SoftwareForbid:
			if installed {
				out = append(out, softwareOp{p, "remove", p.Package, false})
			}
		}
	}
	return out
}

// recorded returns the packages of the record, sorted.
func (s *Software) recorded() []string {
	data, _, err := s.Sys.ReadFile(softwareInstalledRecord)
	if err != nil {
		return nil
	}
	out := strings.Fields(string(data))
	slices.Sort(out)
	return out
}

// Plan implements Reconciler. It reads files and package states only (report-only devices run Plan alone, plan M11).
func (s *Software) Plan(ctx context.Context, r bundle.Resource) ([]string, error) {
	sp, err := s.spec(r)
	if err != nil {
		return nil, err
	}
	var changes []string
	for _, p := range s.unmanaged(sp) {
		changes = append(changes, "remove-unmanaged "+p)
	}
	for _, src := range sp.Sources {
		keyring, err := sourceKeyring(src)
		if err != nil || flatpakSource(src) {
			continue // Apply reports a key that fails; nothing of the source is written. A remote is planFlatpak's.
		}
		if !fileHas(s.Sys, SoftwareSourcePath(src.Slug), renderSoftwareSource(src), 0o644) {
			changes = append(changes, "source "+src.Slug)
		}
		if !fileHas(s.Sys, SoftwareKeyringPath(src.Slug), keyring, 0o644) {
			changes = append(changes, "keyring "+src.Slug)
		}
	}
	if _, differs := s.forbidPins(sp); differs {
		changes = append(changes, "file "+SoftwareForbidFile)
	}
	for _, op := range s.ops(sp) {
		changes = append(changes, op.line())
	}
	return append(changes, s.planFlatpak(ctx, sp)...), nil
}

// softwarePass collects the outcome of one Apply.
type softwarePass struct {
	same    bool // the spec equals the last applied one
	changed bool
	// outcome is the state of a package this pass decided (failed or pending), by package.
	outcome map[string]protocol.SoftwareItem
	failed  []string
	// versions are the installed versions before the pass, for the events of removals.
	versions map[string]string
	// flatpak is what the pass found of Flatpak; nil without the runtime.
	flatpak *flatpakPass
}

func (p *softwarePass) set(pkg, state, reason, msg string) {
	p.outcome[pkg] = protocol.SoftwareItem{State: state, Reason: reason, Error: msg}
	if state == protocol.SoftwareStateFailed {
		p.failed = append(p.failed, pkg+" ("+reason+")")
	}
}

// Apply implements Reconciler in the order of plan M13a decision 23: files, scoped apt-get update of changed sources,
// installations, removals (only while the server is reachable), the record, the status.
func (s *Software) Apply(ctx context.Context, r bundle.Resource) Result {
	sp, err := s.spec(r)
	pass := &softwarePass{same: s.applied != nil && bytes.Equal(s.applied, r.Spec), outcome: map[string]protocol.SoftwareItem{},
		versions: map[string]string{}}
	if err != nil {
		return s.abort(r.ID, sp, pass, err)
	}
	if !pass.same || s.failures == nil {
		s.failures, s.retry, s.conflict = map[string]string{}, map[string]softwareRetry{}, map[string]softwareRetry{}
	}
	if s.refresh == nil {
		s.refresh = map[string]bool{}
	}
	if s.unchecked == nil {
		s.unchecked = map[string]bool{}
	}
	for _, p := range sp.Packages {
		if p.FlatpakRef == "" {
			pass.versions[p.Package] = s.Sys.PackageVersion(p.Package)
		}
	}
	updated, err := s.writeFiles(sp, pass)
	if err != nil {
		return s.abort(r.ID, sp, pass, err)
	}
	s.applied = bytes.Clone(r.Spec)
	if updated, err = s.checkSources(ctx, sp, updated, pass); err != nil {
		return s.abort(r.ID, sp, pass, err)
	}
	err = s.updateSources(ctx, sp, updated, pass)
	ops := s.ops(sp)
	var installs, removals []softwareOp
	for _, op := range ops {
		if _, decided := pass.outcome[op.pkg.Package]; decided {
			continue
		}
		if op.verb == "remove" {
			removals = append(removals, op)
		} else {
			installs = append(installs, op)
		}
	}
	reachable := s.ServerReachable != nil && s.ServerReachable()
	var deferred []softwareOp
	if err == nil {
		deferred, err = s.install(ctx, installs, removals, reachable, pass)
	}
	if err == nil {
		err = s.remove(ctx, removals, reachable, pass)
	}
	if err == nil && len(deferred) > 0 {
		_, err = s.install(ctx, deferred, nil, reachable, pass)
	}
	if errors.Is(err, errDpkgLocked) {
		for _, op := range ops {
			if _, decided := pass.outcome[op.pkg.Package]; !decided && !s.done(op) {
				pass.set(op.pkg.Package, protocol.SoftwareStatePending, protocol.SoftwareDpkgLocked, "")
			}
		}
	}
	if fpErr := s.applyFlatpak(ctx, sp, reachable, pass); fpErr != nil && err == nil {
		err = fpErr
	}
	if recErr := s.writeRecord(sp); recErr != nil && err == nil {
		err = recErr
	}
	s.status = s.health(sp, pass)
	note := superseded(sp)
	switch {
	case err != nil:
		return Result{ID: r.ID, Status: Error, Message: joinNote(err.Error(), note)}
	case len(pass.failed) > 0:
		return Result{ID: r.ID, Status: Error, Message: joinNote(cut("software failed: "+strings.Join(pass.failed, ", "), softwareMessage), note)}
	case pass.changed:
		return Result{ID: r.ID, Status: Changed, Message: note}
	}
	return Result{ID: r.ID, Status: OK, Message: note}
}

// abort ends a pass that could not start or write its files: every package of the spec reports the error, so that the
// check-in does not keep the status of an earlier pass. A spec that did not decode keeps the earlier status.
func (s *Software) abort(id string, sp bundle.SoftwareSpec, pass *softwarePass, err error) Result {
	if len(sp.Packages) > 0 {
		for _, p := range sp.Packages {
			pass.outcome[softwareKey(p)] = protocol.SoftwareItem{State: protocol.SoftwareStateFailed, Reason: protocol.SoftwareAptFailed, Error: err.Error()}
		}
		s.status = s.health(sp, pass)
	}
	return errorResult(id, err)
}

// done reports whether an operation of this pass reached its goal (it ran before the lock was found).
func (s *Software) done(op softwareOp) bool {
	installed := s.Sys.PackageInstalled(op.pkg.Package)
	if op.verb == "remove" {
		return !installed
	}
	return installed && (op.pkg.Version == nil || s.Sys.PackageVersion(op.pkg.Package) == *op.pkg.Version)
}

// superseded is the status note of forbid and uninstall results that replaced a package hold of the same package
// (architect decision 2026-11-02): the hold is not in the updates section, so the overlap is visible here.
func superseded(sp bundle.SoftwareSpec) string {
	var pkgs []string
	for _, p := range sp.Packages {
		if p.SupersededHold {
			pkgs = append(pkgs, softwareKey(p))
		}
	}
	if len(pkgs) == 0 {
		return ""
	}
	return "package hold superseded by forbid or uninstall: " + strings.Join(pkgs, ", ")
}

func joinNote(msg, note string) string {
	if note == "" {
		return msg
	}
	return msg + "; " + note
}

// writeFiles removes unmanaged files and writes the keyrings, sources and forbid pins that differ, and returns the
// sources whose files changed. A file that differs while the spec is the one applied before was changed outside
// Paddock (the updates.writeFiles rule). Every removal is logged.
func (s *Software) writeFiles(sp bundle.SoftwareSpec, pass *softwarePass) (updated []string, err error) {
	for _, p := range s.unmanaged(sp) {
		s.tamper(pass, p)
		if err := s.Sys.Remove(p); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return nil, err
		}
		slog.Info("software source file removed", "path", p)
		pass.changed = true
	}
	for _, src := range sp.Sources {
		if flatpakSource(src) {
			continue
		}
		c, rolledBack := s.conflict[src.Slug]
		if rolledBack && c.passes > 0 {
			s.conflict[src.Slug] = softwareRetry{passes: c.passes - 1, err: c.err}
			s.failSource(pass, sp, src.Slug, protocol.SoftwareStageSourceUpdate, protocol.SoftwareConflictingSource, c.err)
			continue
		}
		keyring, err := sourceKeyring(src)
		if err != nil {
			s.failSource(pass, sp, src.Slug, protocol.SoftwareStageKeyring, protocol.SoftwareFingerprintMismatch, err.Error())
			continue
		}
		s.clearFailure("source:"+src.Slug, protocol.SoftwareStageKeyring)
		wrote := false
		// The keyring first: a source whose Signed-By file is missing stops every apt update.
		for _, f := range []struct {
			path string
			data []byte
		}{{SoftwareKeyringPath(src.Slug), keyring}, {SoftwareSourcePath(src.Slug), renderSoftwareSource(src)}} {
			if fileHas(s.Sys, f.path, f.data, 0o644) {
				continue
			}
			if err := s.recordSource(src.Slug); err != nil {
				return nil, err
			}
			if !rolledBack { // the reconciler removed the file itself
				s.tamper(pass, f.path)
			}
			if err := s.Sys.WriteFileAtomic(f.path, f.data, 0o644, 0, 0); err != nil {
				return nil, err
			}
			wrote = true
		}
		if wrote {
			updated = append(updated, src.Slug)
			pass.changed = true
		}
	}
	switch pins, differs := s.forbidPins(sp); {
	case !differs:
	case pins == nil:
		s.tamper(pass, SoftwareForbidFile)
		if err := s.Sys.Remove(SoftwareForbidFile); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return nil, err
		}
		slog.Info("software forbid pins removed", "path", SoftwareForbidFile)
		pass.changed = true
	default:
		s.tamper(pass, SoftwareForbidFile)
		if err := s.Sys.WriteFileAtomic(SoftwareForbidFile, pins, 0o644, 0, 0); err != nil {
			return nil, err
		}
		pass.changed = true
	}
	return updated, s.pruneSourceRecord()
}

// recordSource adds slug to the record of written sources before its first file is written.
func (s *Software) recordSource(slug string) error {
	slugs := s.sourceSlugs()
	if slices.Contains(slugs, slug) {
		return nil
	}
	return s.writeSourceRecord(append(slugs, slug))
}

// pruneSourceRecord drops the sources whose files are gone from the record.
func (s *Software) pruneSourceRecord() error {
	slugs := s.sourceSlugs()
	kept := slices.DeleteFunc(slices.Clone(slugs), func(slug string) bool {
		return s.absent(SoftwareSourcePath(slug)) && s.absent(SoftwareKeyringPath(slug))
	})
	if len(kept) == len(slugs) {
		return nil
	}
	return s.writeSourceRecord(kept)
}

func (s *Software) writeSourceRecord(slugs []string) error {
	if len(slugs) == 0 {
		if err := s.Sys.Remove(softwareSourcesRecord); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		return nil
	}
	slices.Sort(slugs)
	return s.Sys.WriteFileAtomic(softwareSourcesRecord, []byte(strings.Join(slugs, "\n")+"\n"), 0o600, 0, 0)
}

func (s *Software) tamper(pass *softwarePass, file string) {
	if pass.same {
		s.Events.emit(protocol.EventTamperProtectedFileChanged, protocol.TamperProtectedFileChanged{File: file})
	}
}

// checkSources reads the device's whole apt configuration once per pass while Paddock sources are on disk: apt refuses
// all of it when a Paddock source repeats a repository the device has with other options (a different Signed-By), also
// one the user adds later, and the scoped update cannot see that. A source the failing check names is rolled back —
// its file and keyring are removed, never the device's own entry — and fails as conflicting_source; it is written again
// after softwareRetryPasses passes of the same spec (architect decisions 2026-11-03, PDK-710). The check is a
// simulation and changes nothing. It returns the written sources that stay and still need their scoped update.
func (s *Software) checkSources(ctx context.Context, sp bundle.SoftwareSpec, updated []string, pass *softwarePass) ([]string, error) {
	var check []string
	for _, src := range sp.Sources {
		if slices.Contains(updated, src.Slug) || !s.absent(SoftwareSourcePath(src.Slug)) {
			check = append(check, src.Slug)
		}
	}
	for slug := range s.unchecked {
		if !slices.Contains(check, slug) {
			delete(s.unchecked, slug)
		}
	}
	if len(check) == 0 {
		return nil, nil
	}
	out, checkErr := s.apt(ctx, "-s", "check", "-q")
	if incomplete(out, checkErr) {
		slog.Warn("apt configuration check did not complete; the written sources are checked at the next pass", "sources", check, "error", checkErr)
		for _, slug := range check {
			if slices.Contains(updated, slug) {
				s.unchecked[slug] = true
			}
		}
		return nil, nil
	}
	var kept []string
	rolledBack := false
	for _, src := range sp.Sources {
		if !slices.Contains(check, src.Slug) {
			continue
		}
		written := slices.Contains(updated, src.Slug) || s.unchecked[src.Slug]
		delete(s.unchecked, src.Slug)
		line := ""
		if checkErr != nil {
			line = conflictLine(out, src)
		}
		if line == "" {
			if written {
				kept = append(kept, src.Slug)
			}
			delete(s.conflict, src.Slug)
			continue
		}
		for _, p := range []string{SoftwareSourcePath(src.Slug), SoftwareKeyringPath(src.Slug)} {
			if err := s.Sys.Remove(p); err != nil && !errors.Is(err, fs.ErrNotExist) {
				return nil, err
			}
		}
		slog.Warn("software source rolled back: the device already has its repository with other options", "source", src.Slug, "apt", line)
		msg := "apt cannot read the source: " + strings.TrimPrefix(line, "E: ")
		if _, rest, ok := strings.Cut(line, "regarding source "); ok {
			repo, _, _ := strings.Cut(rest, ": ")
			msg = "the device already has a source for " + repo + " with other options; apt: " + strings.TrimPrefix(line, "E: ")
		}
		s.conflict[src.Slug] = softwareRetry{passes: softwareRetryPasses - 1, err: msg}
		delete(s.refresh, src.Slug)
		s.failSource(pass, sp, src.Slug, protocol.SoftwareStageSourceUpdate, protocol.SoftwareConflictingSource, msg)
		rolledBack = true
	}
	switch {
	case rolledBack:
		if _, err := s.apt(ctx, "-s", "check", "-q"); err != nil {
			slog.Warn("apt configuration check still fails after the rollback of Paddock's sources", "error", err)
		}
	case checkErr != nil:
		slog.Warn("apt configuration check failed without naming a Paddock source", "error", checkErr)
	}
	return kept, nil
}

// incomplete reports whether a configuration check ended before apt judged the sources: killed or timed out, stopped
// at the dpkg lock, or failed without an error line. Such a check proves nothing either way.
func incomplete(out string, err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, errDpkgLocked) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	for line := range strings.Lines(out) {
		if strings.HasPrefix(strings.TrimSpace(line), "E: ") {
			return false
		}
	}
	return true
}

// conflictLine returns apt's error line that names src: its file, its keyring (the Signed-By values of a conflict) or
// one of its URIs as the source of conflicting options.
func conflictLine(out string, src bundle.SoftwareSource) string {
	for line := range strings.Lines(out) {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "E: ") {
			continue
		}
		if strings.Contains(line, SoftwareSourcePath(src.Slug)) || strings.Contains(line, SoftwareKeyringPath(src.Slug)) ||
			slices.ContainsFunc(src.URIs, func(u string) bool {
				u = "regarding source " + strings.TrimSuffix(u, "/")
				return strings.Contains(line, u+" ") || strings.Contains(line, u+"/ ")
			}) {
			return line
		}
	}
	return ""
}

// updateSources refreshes the package lists of every source whose files changed or whose last refresh did not
// complete, each on its own: a failing source fails its packages only. A source is marked for refresh before its
// update runs, so that a lock or a crash leaves it marked.
func (s *Software) updateSources(ctx context.Context, sp bundle.SoftwareSpec, updated []string, pass *softwarePass) error {
	for slug := range s.refresh {
		if !slices.ContainsFunc(sp.Sources, func(src bundle.SoftwareSource) bool { return src.Slug == slug }) {
			delete(s.refresh, slug)
		}
	}
	for _, src := range sp.Sources {
		if (!slices.Contains(updated, src.Slug) && !s.refresh[src.Slug]) || s.unchecked[src.Slug] {
			continue
		}
		s.refresh[src.Slug] = true
		_, err := s.apt(ctx, "update", "-q", "-o", "Dir::Etc::sourcelist=sources.list.d/"+SoftwarePrefix+src.Slug+".sources",
			"-o", "Dir::Etc::sourceparts=-", "-o", "APT::Get::List-Cleanup=0", softwareLockWait[0], softwareLockWait[1])
		switch {
		case errors.Is(err, errDpkgLocked):
			return err
		case err != nil:
			s.failSource(pass, sp, src.Slug, protocol.SoftwareStageSourceUpdate, protocol.SoftwareSourceUnreachable, err.Error())
		default:
			delete(s.refresh, src.Slug)
			s.clearFailure("source:"+src.Slug, protocol.SoftwareStageSourceUpdate)
		}
	}
	return nil
}

// failSource reports a failed source once and fails the required packages and Flatpak applications of it; its other
// packages (uninstall, forbid, hold) do not need it.
func (s *Software) failSource(pass *softwarePass, sp bundle.SoftwareSpec, slug, stage, reason, msg string) {
	s.report("source:"+slug, protocol.SoftwareApplyFailed{Source: slug, Stage: stage, Reason: reason, Error: msg})
	pass.failed = append(pass.failed, "source "+slug+" ("+reason+")")
	for _, p := range sp.Packages {
		if p.Source == slug && p.Intent == bundle.SoftwareRequired {
			pass.set(softwareKey(p), protocol.SoftwareStateFailed, reason, msg)
		}
	}
}

// failPackage reports a failed package once per unchanged failure.
func (s *Software) failPackage(pass *softwarePass, p bundle.SoftwarePackage, stage, reason, msg string) {
	key := softwareKey(p)
	pass.set(key, protocol.SoftwareStateFailed, reason, msg)
	s.report("package:"+key, protocol.SoftwareApplyFailed{Package: key, Source: p.Source, Stage: stage, Reason: reason, Error: msg})
}

func (s *Software) report(key string, data protocol.SoftwareApplyFailed) {
	data.Error = cut(data.Error, softwareEventError)
	if k := data.Stage + "/" + data.Reason; s.failures[key] != k {
		s.failures[key] = k
		s.Events.emit(protocol.EventSoftwareApplyFailed, data)
	}
}

func (s *Software) clearFailure(key, stage string) {
	if strings.HasPrefix(s.failures[key], stage+"/") {
		delete(s.failures, key)
	}
}

// unknown returns the operations whose package apt does not know by its exact name.
func (s *Software) unknown(ctx context.Context, ops []softwareOp) ([]softwareOp, error) {
	var out []softwareOp
	for _, op := range ops {
		known, err := KnownPackage(ctx, s.Sys, op.pkg.Package)
		if err != nil {
			return nil, err
		}
		if !known {
			out = append(out, op)
		}
	}
	return out, nil
}

// install simulates the installations first and runs them in one apt-get install --no-remove when the simulation
// removes nothing and touches no fully protected package (plan M13a decision 23 d, amendment 2026-11-03). A
// simulation that removes only planned removals returns the operations as deferred: the caller installs them again
// after the removal step. Packages apt has no candidate for leave the step after one full apt-get update; the others
// go on. A package whose real installation failed waits softwareRetryPasses passes of the same spec before it runs
// again.
func (s *Software) install(ctx context.Context, ops, removals []softwareOp, reachable bool, pass *softwarePass) (deferred []softwareOp, err error) {
	var removable []string
	if reachable {
		for _, op := range removals {
			removable = append(removable, op.pkg.Package)
		}
	}
	ops = slices.DeleteFunc(ops, func(op softwareOp) bool {
		r, waiting := s.retry[op.pkg.Package]
		if !waiting || r.passes <= 0 {
			return false
		}
		s.retry[op.pkg.Package] = softwareRetry{passes: r.passes - 1, err: r.err}
		pass.set(op.pkg.Package, protocol.SoftwareStateFailed, protocol.SoftwareAptFailed, r.err)
		return true
	})
	refreshed := false
	noCandidateKey := protocol.SoftwareStageSimulate + "/" + protocol.SoftwareNoCandidate
	for len(ops) > 0 {
		missing, lookupErr := s.unknown(ctx, ops)
		if lookupErr != nil {
			for _, op := range ops {
				s.failPackage(pass, op.pkg, protocol.SoftwareStageSimulate, protocol.SoftwareAptFailed, lookupErr.Error())
			}
			return nil, nil
		}
		var simErr error
		var args []string
		if len(missing) == 0 {
			args = append([]string{"install", "-y", "-q", softwareLockWait[0], softwareLockWait[1], "-o", "Dpkg::Options::=--force-confdef",
				"-o", "Dpkg::Options::=--force-confold", "--allow-downgrades"}, targets(ops)...)
			var out string
			out, simErr = s.apt(ctx, append([]string{"-s"}, args...)...)
			if errors.Is(simErr, errDpkgLocked) {
				return nil, simErr
			}
			if simErr != nil {
				missing = noCandidate(out, ops)
				if len(missing) == 0 {
					for _, op := range ops {
						s.failPackage(pass, op.pkg, protocol.SoftwareStageSimulate, protocol.SoftwareAptFailed, simErr.Error())
					}
					return nil, nil
				}
			} else if touched, ok := simulatedProtected(out); !ok || len(touched) > 0 {
				msg := "the installation would change the protected packages " + strings.Join(touched, " ")
				if !ok {
					msg = "the simulation does not show which packages the installation changes"
				}
				for _, op := range ops {
					s.failPackage(pass, op.pkg, protocol.SoftwareStageSimulate, protocol.SoftwareProtectedAffected, msg)
				}
				return nil, nil
			} else if extra, ok := simulatedRemovals(out); !ok || len(except(extra, removable)) > 0 {
				msg := "the installation would remove " + strings.Join(except(extra, removable), " ")
				if !ok {
					msg = "the simulation does not show which packages the installation removes"
				}
				for _, op := range ops {
					s.failPackage(pass, op.pkg, protocol.SoftwareStageSimulate, protocol.SoftwareWouldRemoveDependents, msg)
				}
				return nil, nil
			} else if len(extra) > 0 {
				// --no-remove would make the real run fail on the planned removals; after the removal step it needs none.
				return ops, nil
			}
		}
		if len(missing) > 0 {
			if !refreshed && !s.reported(missing, noCandidateKey) {
				refreshed = true
				_, err := s.apt(ctx, "update", "-q", softwareLockWait[0], softwareLockWait[1])
				if errors.Is(err, errDpkgLocked) {
					return nil, err
				}
				if err == nil {
					continue
				}
			}
			for _, op := range missing {
				s.failPackage(pass, op.pkg, protocol.SoftwareStageSimulate, protocol.SoftwareNoCandidate, "apt has no installation candidate for "+op.target)
			}
			ops = slices.DeleteFunc(ops, func(op softwareOp) bool { return slices.Contains(missing, op) })
			continue
		}
		// The real run may resolve differently than the simulation a moment before (a daily update in between); it must
		// never remove a package the simulation did not show (plan M13a amendment 2026-11-03).
		_, err := s.apt(ctx, slices.Insert(slices.Clone(args), 1, "--no-remove")...)
		if errors.Is(err, errDpkgLocked) {
			return nil, err
		}
		for _, op := range ops {
			msg := ""
			switch {
			case err != nil && !s.done(op):
				msg = err.Error()
			case !s.done(op):
				msg = fmt.Sprintf("%s is not installed after apt-get install (installed: %q)", op.target, s.Sys.PackageVersion(op.pkg.Package))
			default:
				s.succeeded(pass, op)
				continue
			}
			s.retry[op.pkg.Package] = softwareRetry{passes: softwareRetryPasses - 1, err: msg}
			s.failPackage(pass, op.pkg, protocol.SoftwareStageInstall, protocol.SoftwareAptFailed, msg)
		}
		return nil, nil
	}
	return nil, nil
}

// reported reports whether every op already failed with key (stage/reason): a repeated refresh would not help.
func (s *Software) reported(ops []softwareOp, key string) bool {
	return !slices.ContainsFunc(ops, func(op softwareOp) bool { return s.failures["package:"+op.pkg.Package] != key })
}

func (s *Software) succeeded(pass *softwarePass, op softwareOp) {
	delete(s.failures, "package:"+op.pkg.Package)
	delete(s.retry, op.pkg.Package)
	pass.changed = true
	data := protocol.SoftwareChange{Package: op.pkg.Package, Version: s.Sys.PackageVersion(op.pkg.Package), Intent: op.pkg.Intent,
		CatalogEntryID: op.pkg.CatalogEntryID}
	switch {
	case op.upgrade:
		// The plan defines events for installations and removals only; the new version shows in the status.
	case op.verb == "reinstall":
		data.Reason = protocol.SoftwareReasonLocallyRemoved
		s.Events.emit(protocol.EventSoftwareReinstalled, data)
	default:
		data.Reason = protocol.SoftwareReasonFirstInstall
		s.Events.emit(protocol.EventSoftwareInstalled, data)
	}
}

// remove removes the uninstall and forbid packages in one apt-get remove (no purge) after a simulation that removes
// exactly those (plan M13a decision 23 e). While the server is unreachable nothing is removed (design contract 8).
func (s *Software) remove(ctx context.Context, ops []softwareOp, reachable bool, pass *softwarePass) error {
	if len(ops) == 0 {
		return nil
	}
	if !reachable {
		for _, op := range ops {
			pass.set(op.pkg.Package, protocol.SoftwareStatePending, protocol.SoftwareDeferredOffline, "")
		}
		return nil
	}
	missing, err := s.unknown(ctx, ops)
	if err != nil {
		for _, op := range ops {
			s.failPackage(pass, op.pkg, protocol.SoftwareStageSimulate, protocol.SoftwareAptFailed, err.Error())
		}
		return nil
	}
	for _, op := range missing {
		s.failPackage(pass, op.pkg, protocol.SoftwareStageSimulate, protocol.SoftwareNoCandidate, "apt knows no package named "+op.target)
		ops = slices.DeleteFunc(ops, func(o softwareOp) bool { return o == op })
	}
	if len(ops) == 0 {
		return nil
	}
	pkgs := targets(ops)
	args := append([]string{"remove", "-y", "-q", softwareLockWait[0], softwareLockWait[1]}, s.removalArgs(pkgs)...)
	out, err := s.apt(ctx, append([]string{"-s"}, args...)...)
	if errors.Is(err, errDpkgLocked) {
		return err
	}
	fail := func(stage, reason, msg string) {
		for _, op := range ops {
			s.failPackage(pass, op.pkg, stage, reason, msg)
		}
	}
	if err != nil {
		fail(protocol.SoftwareStageSimulate, protocol.SoftwareAptFailed, err.Error())
		return nil
	}
	if touched, ok := simulatedProtected(out); !ok {
		fail(protocol.SoftwareStageSimulate, protocol.SoftwareProtectedAffected, "the simulation does not show which packages the removal changes")
		return nil
	} else if len(touched) > 0 {
		fail(protocol.SoftwareStageSimulate, protocol.SoftwareProtectedAffected, "the removal would change the protected packages "+strings.Join(touched, " "))
		return nil
	}
	if removed, ok := simulatedRemovals(out); !ok {
		fail(protocol.SoftwareStageSimulate, protocol.SoftwareWouldRemoveDependents, "the simulation does not show which packages the removal removes")
		return nil
	} else if extra := except(removed, pkgs); len(extra) > 0 {
		fail(protocol.SoftwareStageSimulate, protocol.SoftwareWouldRemoveDependents, "the removal would also remove "+strings.Join(extra, " "))
		return nil
	}
	_, err = s.apt(ctx, args...)
	if errors.Is(err, errDpkgLocked) {
		return err
	}
	for _, op := range ops {
		if !s.done(op) {
			msg := op.target + " is still installed after apt-get remove"
			if err != nil {
				msg = err.Error()
			}
			s.failPackage(pass, op.pkg, protocol.SoftwareStageRemove, protocol.SoftwareAptFailed, msg)
			continue
		}
		delete(s.failures, "package:"+op.pkg.Package)
		pass.changed = true
		s.Events.emit(protocol.EventSoftwareRemoved, protocol.SoftwareChange{Package: op.pkg.Package, Version: pass.versions[op.pkg.Package],
			Intent: op.pkg.Intent, CatalogEntryID: op.pkg.CatalogEntryID})
	}
	return nil
}

// removalArgs expands every package to the arguments that remove all its installed architectures. The qualifiers
// come from dpkg, the names from the exact-name check.
func (s *Software) removalArgs(pkgs []string) []string {
	var out []string
	for _, p := range pkgs {
		out = append(out, s.Sys.PackageRemovalNames(p)...)
	}
	return out
}

func targets(ops []softwareOp) []string {
	out := make([]string, len(ops))
	for i, op := range ops {
		out[i] = op.target
	}
	return out
}

// apt runs apt-get; output that says dpkg was interrupted (an installation killed at its timeout) is repaired with
// dpkg --configure -a and the call repeated once. A non-zero exit is an error with the last output line, wrapping
// errDpkgLocked when apt or dpkg gave up on the dpkg lock: a run that waited for the lock and then succeeded prints
// the same lock message and is no error.
func (s *Software) apt(ctx context.Context, args ...string) (string, error) {
	out, exit, err := s.Sys.AptGet(ctx, args...)
	if (err != nil || exit != 0) && strings.Contains(out, "dpkg was interrupted") {
		dout, dexit, derr := s.Sys.Dpkg(ctx, "--configure", "-a")
		if derr != nil || dexit != 0 {
			if locked(dout) {
				return dout, errDpkgLocked
			}
			return dout, fmt.Errorf("dpkg --configure -a: exit %d %v: %s", dexit, derr, lastLine(dout))
		}
		out, exit, err = s.Sys.AptGet(ctx, args...)
	}
	if err == nil && exit == 0 {
		return out, nil
	}
	if locked(out) {
		return out, errDpkgLocked
	}
	verb := args[0]
	if verb == "-s" {
		verb = "-s " + args[1]
	}
	if err != nil {
		return out, fmt.Errorf("apt-get %s: %w", verb, err)
	}
	return out, fmt.Errorf("apt-get %s: exit %d: %s", verb, exit, lastLine(out))
}

// dpkgLockErrors start the error lines of apt and dpkg when another process holds the dpkg lock past the lock timeout.
// The "Waiting for cache lock: Could not get lock …" lines of a run that waited are no error: such a run that failed
// later failed for its own reason.
var dpkgLockErrors = []string{"E: Could not get lock", "E: Unable to acquire the dpkg frontend lock", "dpkg: error: dpkg frontend lock was locked"}

func locked(out string) bool {
	for line := range strings.Lines(out) {
		if slices.ContainsFunc(dpkgLockErrors, func(m string) bool { return strings.HasPrefix(line, m) }) {
			return true
		}
	}
	return false
}

// noCandidate returns the operations apt names as unknown, without candidate or without the pinned version.
func noCandidate(out string, ops []softwareOp) []softwareOp {
	lines := strings.Split(out, "\n")
	var missing []softwareOp
	for _, op := range ops {
		name := op.pkg.Package
		if slices.ContainsFunc(lines, func(l string) bool {
			l = strings.TrimSpace(l)
			return l == "E: Unable to locate package "+name || strings.Contains(l, "Package '"+name+"' has no installation candidate") ||
				(strings.HasPrefix(l, "E: Version '") && strings.HasSuffix(l, "' for '"+name+"' was not found"))
		}) {
			missing = append(missing, op)
		}
	}
	return missing
}

// simulationRemoving is the number of removals in the summary of apt-get -s: "N to remove" (apt-get's classic
// output) or "Removing: N" within apt 3's one-line summary "Upgrading: 0, Installing: 0, Removing: N, Not Upgrading: 0"
// (APT::Output-Version 30).
var simulationRemoving = regexp.MustCompile(`(?:\b(\d+) to remove\b|\bRemoving: (\d+)\b)`)

// simulatedRemovals returns the packages an apt-get -s run removes: the names of its "Remv <pkg>" lines, which every
// apt version prints in a simulation, without the architecture qualifier. ok is false — the caller refuses, fail
// closed — when the summary is missing or counts more removals than the Remv lines name.
func simulatedRemovals(out string) (pkgs []string, ok bool) {
	lines := 0
	for line := range strings.Lines(out) {
		if rest, found := strings.CutPrefix(line, "Remv "); found {
			if f := strings.Fields(rest); len(f) > 0 {
				name, _, _ := strings.Cut(f[0], ":")
				pkgs = append(pkgs, name)
				lines++
			}
		}
	}
	slices.Sort(pkgs)
	pkgs = slices.Compact(pkgs)
	m := simulationRemoving.FindStringSubmatch(out)
	if m == nil {
		return pkgs, false
	}
	n, err := strconv.Atoi(m[1] + m[2])
	// A package removed for two architectures is two Remv lines and two removals but one name.
	return pkgs, err == nil && n <= lines
}

// simulationCounts are the counters of apt-get -s's summary line: classic "N upgraded, N newly installed[, N reinstalled]
// [, N downgraded], N to remove and N not upgraded." and apt 3's "Upgrading: N, Installing: N[, Reinstalling: N]
// [, Downgrading: N], Removing: N, Not Upgrading: N". "not upgraded" and "Not Upgrading" print no Inst line, so
// "Not " is captured (group 3) to skip it: RE2 has no lookbehind.
var simulationCounts = regexp.MustCompile(`\b(\d+) (upgraded|newly installed|reinstalled|downgraded|to remove)\b|\b(Not )?(Upgrading|Installing|Reinstalling|Downgrading|Removing): (\d+)`)

// simulatedProtected returns the fully protected packages an apt-get -s run installs, upgrades or removes: the names of
// its "Inst <pkg>" and "Remv <pkg>" lines (every apt version prints them, LC_ALL=C), without an architecture qualifier.
// Paddock's own packages move only through the signed A/B update path and the login stack only through its own
// reconciler (plan M13a amendment 2026-11-03). ok is false — the caller refuses, fail closed — when the summary line is
// missing or counts more installations, upgrades or removals than the Inst and Remv lines name.
func simulatedProtected(out string) (pkgs []string, ok bool) {
	inst, remv := 0, 0
	for line := range strings.Lines(out) {
		for _, prefix := range []string{"Inst ", "Remv "} {
			if rest, found := strings.CutPrefix(line, prefix); found {
				if f := strings.Fields(rest); len(f) > 0 {
					if prefix == "Inst " {
						inst++
					} else {
						remv++
					}
					if name, _, _ := strings.Cut(f[0], ":"); bundle.FullyProtected(name) {
						pkgs = append(pkgs, name)
					}
				}
			}
		}
	}
	slices.Sort(pkgs)
	pkgs = slices.Compact(pkgs)
	for line := range strings.Lines(out) {
		if !simulationRemoving.MatchString(line) {
			continue
		}
		wantInst, wantRemv := 0, 0
		for _, m := range simulationCounts.FindAllStringSubmatch(line, -1) {
			if m[3] != "" {
				continue
			}
			n, err := strconv.Atoi(m[1] + m[5])
			if err != nil {
				return pkgs, false
			}
			if kind := m[2] + m[4]; kind == "to remove" || kind == "Removing" {
				wantRemv += n
			} else {
				wantInst += n
			}
		}
		return pkgs, wantInst <= inst && wantRemv <= remv
	}
	return pkgs, false
}

// except returns the names of pkgs that are not in allowed.
func except(pkgs, allowed []string) []string {
	return slices.DeleteFunc(slices.Clone(pkgs), func(p string) bool { return slices.Contains(allowed, p) })
}

// writeRecord records the required packages that are installed; packages no longer required leave the record.
func (s *Software) writeRecord(sp bundle.SoftwareSpec) error {
	var record []string
	for _, p := range sp.Packages {
		if p.FlatpakRef == "" && p.Intent == bundle.SoftwareRequired && s.Sys.PackageInstalled(p.Package) {
			record = append(record, p.Package)
		}
	}
	slices.Sort(record)
	current := s.recorded()
	switch {
	case slices.Equal(record, current) && (len(record) > 0 || s.absent(softwareInstalledRecord)):
		return nil
	case len(record) == 0:
		if err := s.Sys.Remove(softwareInstalledRecord); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		return nil
	}
	return s.Sys.WriteFileAtomic(softwareInstalledRecord, []byte(strings.Join(record, "\n")+"\n"), 0o600, 0, 0)
}

// health is the status of every package of the spec (plan M13a §6.2) with its digest.
func (s *Software) health(sp bundle.SoftwareSpec, pass *softwarePass) *protocol.SoftwareHealth {
	items := make([]protocol.SoftwareItem, 0, len(sp.Packages))
	for _, p := range sp.Packages {
		if p.FlatpakRef != "" {
			it := s.flatpakItem(p, pass)
			it.Error = cut(it.Error, softwareItemError)
			items = append(items, it)
			continue
		}
		it, decided := pass.outcome[p.Package]
		installed := s.Sys.PackageInstalled(p.Package)
		if !decided {
			switch {
			case (p.Intent == bundle.SoftwareRequired || p.Intent == bundle.SoftwareAvailable) && installed:
				it.State = protocol.SoftwareStateInstalled
			case p.Intent == bundle.SoftwareHold && installed:
				it.State = protocol.SoftwareStateHeld
			case p.Intent != bundle.SoftwareRequired && !installed:
				it.State = protocol.SoftwareStateAbsent
			default:
				it.State, it.Reason = protocol.SoftwareStatePending, protocol.SoftwareNotYetApplied
			}
		}
		it.CatalogEntryID, it.Package, it.Intent = p.CatalogEntryID, p.Package, p.Intent
		if installed {
			it.Version = s.Sys.PackageVersion(p.Package)
		}
		it.Error = cut(it.Error, softwareItemError)
		items = append(items, it)
	}
	data, _ := json.Marshal(items)
	sum := sha256.Sum256(data)
	return &protocol.SoftwareHealth{Digest: hex.EncodeToString(sum[:]), Items: &items}
}

// Status returns the software status of the last Apply for the check-in health (plan M13a decision 27), nil before
// the first Apply. Items is never nil then: an empty list tells the server that nothing is managed (PDK-701).
func (s *Software) Status() *protocol.SoftwareHealth {
	if s.status == nil {
		return nil
	}
	items := slices.Clone(*s.status.Items)
	return &protocol.SoftwareHealth{Digest: s.status.Digest, Items: &items}
}

// Residue reports whether the device has software state Paddock wrote for an earlier section: the files of a recorded
// source, forbid pins with Paddock's header, the record of installed packages or of Flatpak remotes and masks. A bundle without the section then
// still runs the reconciler with an empty section, which removes those files and nothing else (architect decision
// 2026-11-03); installed packages stay.
func (s *Software) Residue() bool {
	empty := bundle.SoftwareSpec{}
	_, pins := s.forbidPins(empty)
	return len(s.unmanaged(empty)) > 0 || pins || !s.absent(softwareInstalledRecord) || !s.absent(softwareSourcesRecord) ||
		!s.absent(flatpakRemotesRecord) || !s.absent(flatpakMasksRecord)
}

// cut bounds a message to n characters.
func cut(msg string, n int) string {
	if r := []rune(msg); len(r) > n {
		return string(r[:n])
	}
	return msg
}
