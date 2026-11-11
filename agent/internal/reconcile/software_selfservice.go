package reconcile

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/phischl/paddock-mdm/pkg/bundle"
	"github.com/phischl/paddock-mdm/pkg/protocol"
)

// SelfServiceResult is the outcome of one self-service operation on the device (plan M13b decision 13). Reason is ""
// when the operation reached its goal, else a reason of protocol.SoftwareApplyFailed or protocol.SelfServiceTimeout;
// Version is the installed version afterwards, "" when the application is not installed. Present reports an install
// that found the application already installed and changed nothing: self-service did not install it, so it never
// becomes removable through self-service (ADR 0049 decision 3).
type SelfServiceResult struct {
	Reason  string
	Error   string
	Version string
	Present bool
}

// Failed reports whether the operation did not reach its goal.
func (r SelfServiceResult) Failed() bool { return r.Reason != "" }

// aptFetchErrors are the lines of apt-get that say a repository could not be reached.
var aptFetchErrors = []string{"Failed to fetch", "Temporary failure resolving", "Could not resolve", "Could not connect", "Unable to connect"}

func selfServiceFailed(reason string, err error) SelfServiceResult {
	return SelfServiceResult{Reason: reason, Error: cut(err.Error(), softwareEventError)}
}

// selfServiceErr classifies the error of a package command: the dpkg lock (F7), a timeout, an unreachable repository
// (F5, F6) or otherwise; other is the reason of the last case.
func selfServiceErr(err error, out, other string) SelfServiceResult {
	switch {
	case errors.Is(err, errDpkgLocked):
		return selfServiceFailed(protocol.SoftwareDpkgLocked, err)
	case errors.Is(err, context.DeadlineExceeded):
		return selfServiceFailed(protocol.SelfServiceTimeout, err)
	case slices.ContainsFunc(aptFetchErrors, func(m string) bool { return strings.Contains(out, m) }):
		return selfServiceFailed(protocol.SoftwareSourceUnreachable, err)
	}
	return selfServiceFailed(other, err)
}

// InstallOne installs one application of the spec for a self-service operation (plan M13b decision 13). It runs the
// same guards as Apply: the exact-name check, a simulation that may neither remove a package nor touch a fully
// protected one, then the installation with --no-remove; a user-scope Flatpak application goes into the installation
// of uid, never the system one. It changes none of the reconciler's pass state, so it may run while a pass runs: the
// dpkg lock orders the two (F7). An application that is already installed is left alone and reported Present.
func (s *Software) InstallOne(ctx context.Context, sp bundle.SoftwareSpec, p bundle.SoftwarePackage, uid int) SelfServiceResult {
	if p.FlatpakRef != "" {
		return s.flatpakOne(ctx, sp, p, uid, protocol.SelfServiceInstall)
	}
	if s.Sys.PackageInstalled(p.Package) {
		return SelfServiceResult{Version: s.Sys.PackageVersion(p.Package), Present: true}
	}
	return s.aptInstallOne(ctx, p, false)
}

// UpdateOne moves one installed application to the newest version its source offers, with the guards of InstallOne.
func (s *Software) UpdateOne(ctx context.Context, sp bundle.SoftwareSpec, p bundle.SoftwarePackage, uid int) SelfServiceResult {
	if p.FlatpakRef != "" {
		return s.flatpakOne(ctx, sp, p, uid, protocol.SelfServiceUpdate)
	}
	return s.aptInstallOne(ctx, p, true)
}

// RemoveOne removes one application for a self-service operation: apt-get remove (no purge) after a simulation that
// removes exactly this package and touches no fully protected one, or flatpak uninstall without --delete-data. The user
// asked for it, so it does not wait for the server (plan M13b F6); an application that is not installed is done.
func (s *Software) RemoveOne(ctx context.Context, sp bundle.SoftwareSpec, p bundle.SoftwarePackage, uid int) SelfServiceResult {
	if p.FlatpakRef != "" {
		return s.flatpakOne(ctx, sp, p, uid, protocol.SelfServiceRemove)
	}
	if !s.Sys.PackageInstalled(p.Package) {
		return SelfServiceResult{}
	}
	if known, err := KnownPackage(ctx, s.Sys, p.Package); err != nil || !known {
		if err == nil {
			err = errors.New("apt knows no package named " + p.Package)
			return selfServiceFailed(protocol.SoftwareNoCandidate, err)
		}
		return selfServiceFailed(protocol.SoftwareAptFailed, err)
	}
	args := append([]string{"remove", "-y", "-q", softwareLockWait[0], softwareLockWait[1]}, s.removalArgs([]string{p.Package})...)
	out, err := s.apt(ctx, append([]string{"-s"}, args...)...)
	if err != nil {
		return selfServiceErr(err, out, protocol.SoftwareAptFailed)
	}
	if res, refused := simulationRefused(out, []string{p.Package}); refused {
		return res
	}
	if out, err = s.apt(ctx, args...); err != nil {
		return selfServiceErr(err, out, protocol.SoftwareAptFailed)
	}
	if s.Sys.PackageInstalled(p.Package) {
		return selfServiceFailed(protocol.SoftwareAptFailed, errors.New(p.Package+" is still installed after apt-get remove"))
	}
	return SelfServiceResult{}
}

// aptInstallOne installs or upgrades one APT package. A name apt does not know refreshes the entry's source once (its
// lists may predate the entry), and an unreachable source then fails the installation as source_unreachable (F6).
func (s *Software) aptInstallOne(ctx context.Context, p bundle.SoftwarePackage, upgrade bool) SelfServiceResult {
	if upgrade && !s.Sys.PackageInstalled(p.Package) {
		return selfServiceFailed(protocol.SoftwareAptFailed, errors.New(p.Package+" is not installed"))
	}
	known, err := KnownPackage(ctx, s.Sys, p.Package)
	if err != nil {
		return selfServiceFailed(protocol.SoftwareAptFailed, err)
	}
	if !known {
		if out, err := s.apt(ctx, refreshArgs(p.Source)...); err != nil {
			return selfServiceErr(err, out, protocol.SoftwareSourceUnreachable)
		}
		if known, err = KnownPackage(ctx, s.Sys, p.Package); err != nil {
			return selfServiceFailed(protocol.SoftwareAptFailed, err)
		}
		if !known {
			return selfServiceFailed(protocol.SoftwareNoCandidate, errors.New("apt has no installation candidate for "+p.Package))
		}
	}
	args := []string{"install", "-y", "-q", softwareLockWait[0], softwareLockWait[1], "-o", "Dpkg::Options::=--force-confdef",
		"-o", "Dpkg::Options::=--force-confold"}
	if upgrade {
		args = append(args, "--only-upgrade")
	}
	args = append(args, p.Package)
	out, err := s.apt(ctx, append([]string{"-s"}, args...)...)
	if err != nil {
		if len(noCandidate(out, []softwareOp{{pkg: p, target: p.Package}})) > 0 {
			return selfServiceFailed(protocol.SoftwareNoCandidate, errors.New("apt has no installation candidate for "+p.Package))
		}
		return selfServiceErr(err, out, protocol.SoftwareAptFailed)
	}
	if res, refused := simulationRefused(out, nil); refused {
		return res
	}
	// --no-remove: the real run must never remove a package the simulation did not show (the rule of Apply).
	if out, err = s.apt(ctx, slices.Insert(slices.Clone(args), 1, "--no-remove")...); err != nil {
		return selfServiceErr(err, out, protocol.SoftwareAptFailed)
	}
	if !s.Sys.PackageInstalled(p.Package) {
		return selfServiceFailed(protocol.SoftwareAptFailed, errors.New(p.Package+" is not installed after apt-get install"))
	}
	return SelfServiceResult{Version: s.Sys.PackageVersion(p.Package)}
}

// simulationRefused checks a simulation like Apply does: no fully protected package changes, and nothing but the
// allowed packages is removed; a simulation whose summary does not show it is refused (fail closed).
func simulationRefused(out string, allowed []string) (SelfServiceResult, bool) {
	if touched, ok := simulatedProtected(out); !ok || len(touched) > 0 {
		msg := "the operation would change the protected packages " + strings.Join(touched, " ")
		if !ok {
			msg = "the simulation does not show which packages the operation changes"
		}
		return selfServiceFailed(protocol.SoftwareProtectedAffected, errors.New(msg)), true
	}
	if removed, ok := simulatedRemovals(out); !ok || len(except(removed, allowed)) > 0 {
		msg := "the operation would remove " + strings.Join(except(removed, allowed), " ")
		if !ok {
			msg = "the simulation does not show which packages the operation removes"
		}
		return selfServiceFailed(protocol.SoftwareWouldRemoveDependents, errors.New(msg)), true
	}
	return SelfServiceResult{}, false
}

// refreshArgs refreshes the package lists of one Paddock source, or of every source for the distribution's own.
func refreshArgs(slug string) []string {
	if slug == "" {
		return []string{"update", "-q", softwareLockWait[0], softwareLockWait[1]}
	}
	return []string{"update", "-q", "-o", "Dir::Etc::sourcelist=sources.list.d/" + SoftwarePrefix + slug + ".sources",
		"-o", "Dir::Etc::sourceparts=-", "-o", "APT::Get::List-Cleanup=0", softwareLockWait[0], softwareLockWait[1]}
}

// flatpakOne installs, updates or removes one Flatpak application: system scope in the system installation through the
// remote the pass keeps, user scope in the installation of uid through systemd-run in the user's service manager
// (decision Q14), with the source's checked key for the user's own remote. A user without a running service manager
// fails as flatpak_failed (F8); a flatpak transaction leaves nothing half installed.
func (s *Software) flatpakOne(ctx context.Context, sp bundle.SoftwareSpec, p bundle.SoftwarePackage, uid int, action string) SelfServiceResult {
	if !s.Sys.PackageInstalled(FlatpakRuntime) {
		return selfServiceFailed(protocol.SoftwareFlatpakMissing, errors.New("the flatpak runtime is not installed"))
	}
	user := userScope(p)
	scope := "--system"
	run := func(args ...string) (string, error) { return s.runFlatpak(ctx, args...) }
	if user {
		scope = "--user"
		run = func(args ...string) (string, error) { return s.runUserFlatpak(ctx, uid, args...) }
	}
	installed, err := s.selfServiceApps(ctx, user, uid)
	if err != nil {
		return selfServiceErr(err, "", protocol.SoftwareFlatpakFailed)
	}
	_, present := installed[p.FlatpakRef]
	remote := FlatpakRemoteName(p.Source)
	switch action {
	case protocol.SelfServiceRemove:
		if !present {
			return SelfServiceResult{}
		}
		// No --delete-data and no --unused: the user's data and the shared runtimes stay (plan M13b decision 10).
		_, err = run("uninstall", "-y", "--noninteractive", scope, "--app", p.FlatpakRef)
	case protocol.SelfServiceUpdate:
		if !present {
			return selfServiceFailed(protocol.SoftwareFlatpakFailed, fmt.Errorf("%s is not installed", p.FlatpakRef))
		}
		_, err = run("update", "-y", "--noninteractive", scope, p.FlatpakRef)
	default:
		if present {
			return SelfServiceResult{Version: installed[p.FlatpakRef], Present: true}
		}
		if res, ok := s.selfServiceRemote(ctx, sp, p, user, uid); !ok {
			return res
		}
		_, err = run("install", "-y", "--noninteractive", scope, remote, p.FlatpakRef)
	}
	if err != nil {
		return selfServiceErr(err, "", protocol.SoftwareFlatpakFailed)
	}
	after, err := s.selfServiceApps(ctx, user, uid)
	if err != nil {
		return selfServiceErr(err, "", protocol.SoftwareFlatpakFailed)
	}
	version, ok := after[p.FlatpakRef]
	switch {
	case action == protocol.SelfServiceRemove && ok:
		return selfServiceFailed(protocol.SoftwareFlatpakFailed, fmt.Errorf("%s is still installed after flatpak uninstall", p.FlatpakRef))
	case action != protocol.SelfServiceRemove && !ok:
		return selfServiceFailed(protocol.SoftwareFlatpakFailed, fmt.Errorf("%s is not installed after flatpak %s", p.FlatpakRef, action))
	}
	return SelfServiceResult{Version: version}
}

// selfServiceRemote makes sure the remote of a Flatpak application is in place: the system remote the pass added, or
// the user's own remote added with the source's key, which is checked against its fingerprint first (F12).
func (s *Software) selfServiceRemote(ctx context.Context, sp bundle.SoftwareSpec, p bundle.SoftwarePackage, user bool, uid int) (SelfServiceResult, bool) {
	name := FlatpakRemoteName(p.Source)
	notInPlace := selfServiceFailed(protocol.SoftwareFlatpakFailed, errors.New("the remote "+name+" is not in place"))
	if !user {
		remotes, err := s.systemRemotes(ctx)
		if err != nil {
			return selfServiceErr(err, "", protocol.SoftwareFlatpakFailed), false
		}
		if r, ok := remotes[name]; !ok || !r.usable {
			return notInPlace, false
		}
		return SelfServiceResult{}, true
	}
	i := slices.IndexFunc(sp.Sources, func(src bundle.SoftwareSource) bool { return src.Slug == p.Source && flatpakSource(src) })
	if i < 0 {
		return notInPlace, false
	}
	keyring, err := sourceKeyring(sp.Sources[i])
	if err != nil {
		return selfServiceFailed(protocol.SoftwareFingerprintMismatch, err), false
	}
	if err := s.addUserRemote(ctx, uid, name, sp.Sources[i].URIs[0], keyring); err != nil {
		return selfServiceErr(err, "", protocol.SoftwareFlatpakFailed), false
	}
	return SelfServiceResult{}, true
}

func (s *Software) selfServiceApps(ctx context.Context, user bool, uid int) (map[string]string, error) {
	if user {
		return s.userApps(ctx, uid)
	}
	return s.systemApps(ctx)
}

// SelfServiceInstalled reports whether an application is installed, with its version: the APT package, the system
// installation's Flatpak application, or a user-scope one in the installation of uid (which needs the user's service
// manager; an error then means the state is unknown, not absent).
func (s *Software) SelfServiceInstalled(ctx context.Context, p bundle.SoftwarePackage, uid int) (bool, string, error) {
	if p.FlatpakRef == "" {
		installed := s.Sys.PackageInstalled(p.Package)
		if !installed {
			return false, "", nil
		}
		return true, s.Sys.PackageVersion(p.Package), nil
	}
	if !s.Sys.PackageInstalled(FlatpakRuntime) {
		return false, "", nil
	}
	apps, err := s.selfServiceApps(ctx, userScope(p), uid)
	if err != nil {
		return false, "", err
	}
	version, ok := apps[p.FlatpakRef]
	return ok, version, nil
}
