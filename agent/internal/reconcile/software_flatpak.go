package reconcile

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"maps"
	"slices"
	"strconv"
	"strings"

	"github.com/phischl/paddock-mdm/agent/internal/sessions"
	"github.com/phischl/paddock-mdm/pkg/bundle"
	"github.com/phischl/paddock-mdm/pkg/protocol"
)

// Flatpak in the software reconciler (plan M13b decision 10, ADR 0049 decision 4). A Flatpak source is a system remote
// paddock-<slug> with the source's pinned key; Paddock's remotes are a protected area like its APT sources: a
// paddock-* remote the spec does not name, or one of Paddock's that changed, is removed or restored and reported as
// tamper.protected_file_changed{file: "flatpak:remote/<name>"}.
const (
	// FlatpakRuntime is the package that brings the flatpak binary; the compiler requires it with every Flatpak source
	// (plan M13b decision 9), and without it no Flatpak intent acts.
	FlatpakRuntime = "flatpak"
	// FlatpakItemPrefix starts the package of a Flatpak application in status items and events.
	FlatpakItemPrefix = "flatpak:"
	// flatpakRemotesRecord lists the remotes Paddock added, one "name url fingerprint" per line: a recorded remote that
	// is missing or changed was changed outside Paddock, an unrecorded paddock-* remote is not Paddock's.
	flatpakRemotesRecord = "/var/lib/paddock/state/flatpak-remotes"
	// flatpakMasksRecord lists the applications Paddock masked (forbid, hold), one per line: only those are unmasked
	// when the intent ends, never a mask of the device's own.
	flatpakMasksRecord = "/var/lib/paddock/state/flatpak-masks"
	// flatpakKeyFile holds a source's key for the --gpg-import of one remote-add, in a directory only root reads.
	flatpakKeyFile = "/var/lib/paddock/state/flatpak-import.gpg"
	// flatpakUserKeyDir holds the key file of one remote-add in a user's installation. flatpak 1.14 imports nothing
	// from --gpg-import=- and the user's flatpak runs as the user, who cannot read flatpakKeyFile (PDK-996). Root owns
	// the directory and the user cannot write it, so no file in it can be swapped or redirected by a symlink; the
	// file holds a public key only, so it is world-readable.
	flatpakUserKeyDir = "/run/paddock/flatpak-keys"
)

// FlatpakRemoteName is the system remote of a Flatpak source.
func FlatpakRemoteName(slug string) string { return SoftwarePrefix + slug }

// FlatpakTamperFile is the file of the tamper event of a remote.
func FlatpakTamperFile(name string) string { return "flatpak:remote/" + name }

// softwareKey names a package in the pass, status items and events: the APT package, or "flatpak:<ref>".
func softwareKey(p bundle.SoftwarePackage) string {
	if p.FlatpakRef != "" {
		return FlatpakItemPrefix + p.FlatpakRef
	}
	return p.Package
}

func flatpakSource(src bundle.SoftwareSource) bool { return src.Kind == bundle.SoftwareSourceFlatpak }

func userScope(p bundle.SoftwarePackage) bool { return p.Scope == bundle.SoftwareScopeUser }

// perUser reports whether the agent applies the application in the installations of its listed users. A user-scope
// application without a list acts in system scope, never for every user (architect decision A10-11).
func perUser(p bundle.SoftwarePackage) bool { return userScope(p) && p.Users != nil }

// systemActs reports whether the application's intent acts on the system installation: every system-scope
// application, and a user-scope required, forbid or uninstall without a user list (A10-11). A user-scope available or
// hold application never touches the system installation.
func systemActs(p bundle.SoftwarePackage) bool {
	return !userScope(p) || !perUser(p) && (p.Intent == bundle.SoftwareRequired || removal(p))
}

// flatpakPackages returns the Flatpak applications of the spec.
func flatpakPackages(sp bundle.SoftwareSpec) []bundle.SoftwarePackage {
	return slices.DeleteFunc(slices.Clone(sp.Packages), func(p bundle.SoftwarePackage) bool { return p.FlatpakRef == "" })
}

// flatpakPass is what a pass found of Flatpak on the device for the status: the system installation's applications
// (ID → version) after the pass.
type flatpakPass struct {
	apps map[string]string
}

// flatpakRemote is a system remote as `flatpak remotes` lists it; usable is enabled and verified with GPG.
type flatpakRemote struct {
	url    string
	usable bool
}

type flatpakRecorded struct{ url, fingerprint string }

// remoteChange is what a pass does to one paddock-* system remote: restore it from src (remove it first when it
// exists) or, without src, remove it.
type remoteChange struct {
	name    string
	src     *bundle.SoftwareSource
	keyring []byte
	exists  bool
	tamper  bool
}

func sameURL(a, b string) bool { return strings.TrimSuffix(a, "/") == strings.TrimSuffix(b, "/") }

// runFlatpak runs flatpak on the system installation; a non-zero exit is an error with the last output line.
func (s *Software) runFlatpak(ctx context.Context, args ...string) (string, error) {
	out, exit, err := s.Sys.Flatpak(ctx, args...)
	return out, flatpakErr("flatpak "+args[0], out, exit, err)
}

// runUserFlatpak runs flatpak in the service manager of user uid (plan M13b decision 10, Q14): the user's own
// installation, never escalated to the system one. The UID, not the name: systemd splits --machine at the first "@",
// which a directory user's name contains. RuntimeMaxSec: killing systemd-run at the timeout leaves the transient unit
// running in the user's service manager, so the unit ends itself at the same limit.
func (s *Software) runUserFlatpak(ctx context.Context, uid int, args ...string) (string, error) {
	full := append([]string{"--machine=" + strconv.Itoa(uid) + "@.host", "--user", "--wait", "--pipe", "--quiet", "--collect",
		"--property=RuntimeMaxSec=" + strconv.Itoa(int(PackageTimeout.Seconds())), "--setenv=LC_ALL=C", "flatpak"}, args...)
	out, exit, err := s.Sys.SystemdRun(ctx, nil, full...)
	return out, flatpakErr("flatpak "+args[0]+" (uid "+strconv.Itoa(uid)+")", out, exit, err)
}

func flatpakErr(what, out string, exit int, err error) error {
	switch {
	case err != nil:
		return fmt.Errorf("%s: %w", what, err)
	case exit != 0:
		return fmt.Errorf("%s: exit %d: %s", what, exit, lastLine(out))
	}
	return nil
}

// columns splits a line of flatpak's table output: tab-separated when stdout is no terminal.
func columns(line string) []string {
	line = strings.TrimRight(line, "\r\n")
	if strings.Contains(line, "\t") {
		return strings.Split(line, "\t")
	}
	return strings.Fields(line)
}

// systemRemotes lists the system remotes, disabled ones included: a disabled paddock-* remote is a changed one.
func (s *Software) systemRemotes(ctx context.Context) (map[string]flatpakRemote, error) {
	out, err := s.runFlatpak(ctx, "remotes", "--system", "--show-disabled", "--columns=name,url,options")
	if err != nil {
		return nil, err
	}
	remotes := map[string]flatpakRemote{}
	for line := range strings.Lines(out) {
		f := columns(line)
		if len(f) < 2 || f[0] == "" {
			continue
		}
		var opts []string
		if len(f) > 2 {
			opts = strings.Split(f[2], ",")
		}
		remotes[f[0]] = flatpakRemote{url: f[1], usable: !slices.Contains(opts, "disabled") && !slices.Contains(opts, "no-gpg-verify")}
	}
	return remotes, nil
}

// apps lists the applications of an installation's `flatpak list` output (ID → version).
func apps(out string) map[string]string {
	m := map[string]string{}
	for line := range strings.Lines(out) {
		f := columns(line)
		if len(f) == 0 || f[0] == "" {
			continue
		}
		v := ""
		if len(f) > 1 {
			v = f[1]
		}
		m[f[0]] = v
	}
	return m
}

func (s *Software) systemApps(ctx context.Context) (map[string]string, error) {
	out, err := s.runFlatpak(ctx, "list", "--system", "--app", "--columns=application,version")
	if err != nil {
		return nil, err
	}
	return apps(out), nil
}

func (s *Software) userApps(ctx context.Context, uid int) (map[string]string, error) {
	out, err := s.runUserFlatpak(ctx, uid, "list", "--user", "--app", "--columns=application,version")
	if err != nil {
		return nil, err
	}
	return apps(out), nil
}

// masks returns the masked patterns of the system installation: one per line, indented; a heading ends with ":".
func (s *Software) masks(ctx context.Context) (map[string]bool, error) {
	out, err := s.runFlatpak(ctx, "mask", "--system")
	if err != nil {
		return nil, err
	}
	m := map[string]bool{}
	for line := range strings.Lines(out) {
		line = strings.TrimSpace(line)
		if line != "" && !strings.ContainsAny(line, " \t") && !strings.HasSuffix(line, ":") {
			m[line] = true
		}
	}
	return m, nil
}

// sessionUsers returns the directory users with a logind session of class user that is active or online, by
// lower-cased user name (the UPN the bundle lists, plan M13b decision 11): the users a listed user-scope application
// can be applied for (decision Q14). A listed user without a session gets it at the next pass after the session starts
// (NewUserSession).
func (s *Software) sessionUsers(ctx context.Context) (map[string]int, error) {
	list, err := sessions.List(ctx, s.Sys.Loginctl)
	if err != nil {
		return nil, err
	}
	users := map[string]int{}
	for _, ss := range list {
		if ss.Class == "user" && (ss.State == "active" || ss.State == "online") && ss.UID >= sessions.FirstDirectoryUID {
			users[strings.ToLower(ss.User)] = ss.UID
		}
	}
	return users, nil
}

// targetUIDs returns the UIDs of the listed users of an application that have a session, sorted; users with a session
// that the list does not name are never targeted (A10-11).
func targetUIDs(p bundle.SoftwarePackage, users map[string]int) []int {
	if !perUser(p) {
		return nil
	}
	var uids []int
	for _, name := range *p.Users {
		if uid, ok := users[name]; ok {
			uids = append(uids, uid)
		}
	}
	slices.Sort(uids)
	return slices.Compact(uids)
}

func sortedUIDs(users map[string]int) []int {
	uids := make([]int, 0, len(users))
	for _, uid := range users {
		uids = append(uids, uid)
	}
	slices.Sort(uids)
	return slices.Compact(uids)
}

// NewUserSession reports whether a user started a session since the last pass or call while the spec has user-scope
// Flatpak applications: the agent then runs a drift pass, so that the user gets them at the session start (plan M13b
// decision 10) instead of up to a drift interval later.
func (s *Software) NewUserSession(ctx context.Context) bool {
	if !s.userScoped {
		return false
	}
	users, err := s.sessionUsers(ctx)
	if err != nil {
		return false
	}
	uids := sortedUIDs(users)
	fresh := slices.ContainsFunc(uids, func(u int) bool { return !slices.Contains(s.seenSessions, u) })
	s.seenSessions = uids
	return fresh
}

func (s *Software) remoteRecord() map[string]flatpakRecorded {
	rec := map[string]flatpakRecorded{}
	data, _, err := s.Sys.ReadFile(flatpakRemotesRecord)
	if err != nil {
		return rec
	}
	for line := range strings.Lines(string(data)) {
		if f := strings.Fields(line); len(f) == 3 {
			rec[f[0]] = flatpakRecorded{url: f[1], fingerprint: f[2]}
		}
	}
	return rec
}

func (s *Software) writeRemoteRecord(rec map[string]flatpakRecorded) error {
	if len(rec) == 0 {
		if err := s.Sys.Remove(flatpakRemotesRecord); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		return nil
	}
	var b strings.Builder
	for _, name := range slices.Sorted(maps.Keys(rec)) {
		fmt.Fprintf(&b, "%s %s %s\n", name, rec[name].url, rec[name].fingerprint)
	}
	return s.Sys.WriteFileAtomic(flatpakRemotesRecord, []byte(b.String()), 0o600, 0, 0)
}

func (s *Software) maskRecord() []string {
	data, _, err := s.Sys.ReadFile(flatpakMasksRecord)
	if err != nil {
		return nil
	}
	out := strings.Fields(string(data))
	slices.Sort(out)
	return slices.Compact(out)
}

func (s *Software) writeMaskRecord(refs []string) error {
	slices.Sort(refs)
	refs = slices.Compact(refs)
	if slices.Equal(refs, s.maskRecord()) && (len(refs) > 0 || s.absent(flatpakMasksRecord)) {
		return nil
	}
	if len(refs) == 0 {
		if err := s.Sys.Remove(flatpakMasksRecord); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		return nil
	}
	return s.Sys.WriteFileAtomic(flatpakMasksRecord, []byte(strings.Join(refs, "\n")+"\n"), 0o600, 0, 0)
}

// remoteChanges compares the system remotes with the spec and the record. A source of the spec is (re)added when its
// remote is missing, disabled, unverified, points elsewhere or is not the recorded one with the spec's key: the remote
// is removed and added again, because --gpg-import adds a key and never drops one a changed remote may carry. A
// paddock-* remote the spec does not name is removed; for the empty section of a bundle without one, only a recorded
// remote (the rule of the APT sources). A change is tamper when the remote differs from what Paddock recorded, or is a
// paddock-* remote Paddock never added. badKeys are the sources whose key fails its fingerprint: nothing of them is
// written (plan M13b F12).
func (s *Software) remoteChanges(sp bundle.SoftwareSpec, device map[string]flatpakRemote, rec map[string]flatpakRecorded) (changes []remoteChange, badKeys map[string]error) {
	badKeys = map[string]error{}
	named := map[string]bool{}
	for i, src := range sp.Sources {
		if !flatpakSource(src) {
			continue
		}
		name := FlatpakRemoteName(src.Slug)
		named[name] = true
		keyring, err := sourceKeyring(src)
		if err != nil {
			badKeys[src.Slug] = err
			continue
		}
		url := src.URIs[0]
		dev, exists := device[name]
		r, recorded := rec[name]
		if exists && dev.usable && sameURL(dev.url, url) && recorded && sameURL(r.url, url) && r.fingerprint == src.Fingerprint {
			continue
		}
		changes = append(changes, remoteChange{name: name, src: &sp.Sources[i], keyring: keyring, exists: exists,
			tamper: recorded && (!exists || !dev.usable || !sameURL(dev.url, r.url))})
	}
	empty := emptySection(sp)
	for _, name := range slices.Sorted(maps.Keys(device)) {
		_, recorded := rec[name]
		if named[name] || !strings.HasPrefix(name, SoftwarePrefix) || (empty && !recorded) {
			continue
		}
		changes = append(changes, remoteChange{name: name, exists: true, tamper: !recorded})
	}
	return changes, badKeys
}

// wantedMasks returns the system-scope applications the spec forbids or holds: masked refs are neither installed nor
// updated (plan M13b decision 10). A user-scope forbid without a user list is a system-scope forbid (A10-11).
func wantedMasks(sp bundle.SoftwareSpec) []string {
	var out []string
	for _, p := range flatpakPackages(sp) {
		if p.Intent == bundle.SoftwareForbid && !perUser(p) || p.Intent == bundle.SoftwareHold && !userScope(p) {
			out = append(out, p.FlatpakRef)
		}
	}
	slices.Sort(out)
	return out
}

// hasUserScope reports whether the spec has applications the agent installs or removes for listed users.
func hasUserScope(sp bundle.SoftwareSpec) bool {
	return slices.ContainsFunc(flatpakPackages(sp), perUser)
}

// removal reports whether the intent removes the application.
func removal(p bundle.SoftwarePackage) bool {
	return p.Intent == bundle.SoftwareUninstall || p.Intent == bundle.SoftwareForbid
}

// planFlatpak returns the Flatpak changes of a spec; it only reads (report-only devices run Plan alone).
func (s *Software) planFlatpak(ctx context.Context, sp bundle.SoftwareSpec) []string {
	if !s.Sys.PackageInstalled(FlatpakRuntime) {
		return nil
	}
	var out []string
	if device, err := s.systemRemotes(ctx); err == nil {
		changes, _ := s.remoteChanges(sp, device, s.remoteRecord())
		for _, c := range changes {
			if c.src != nil {
				out = append(out, "remote "+c.src.Slug)
			} else {
				out = append(out, "remove-remote "+c.name)
			}
		}
	}
	out = append(out, s.planMasks(ctx, sp)...)
	if len(flatpakPackages(sp)) == 0 {
		return out
	}
	system, err := s.systemApps(ctx)
	if err != nil {
		return out
	}
	var users map[string]int
	if hasUserScope(sp) {
		users, _ = s.sessionUsers(ctx)
	}
	userApps := map[int]map[string]string{}
	unreadable := map[int]bool{}
	for _, p := range flatpakPackages(sp) {
		if p.Intent != bundle.SoftwareRequired && !removal(p) {
			continue
		}
		if !perUser(p) {
			out = append(out, flatpakPlanLine(p, system, ""))
			continue
		}
		for _, uid := range targetUIDs(p, users) {
			if _, ok := userApps[uid]; !ok && !unreadable[uid] {
				a, err := s.userApps(ctx, uid)
				userApps[uid], unreadable[uid] = a, err != nil
			}
			suffix := " uid " + strconv.Itoa(uid)
			if unreadable[uid] {
				// A drift pass applies only what the plan lists: dropping the user here would leave the item
				// pending/not_yet_applied for good and hide the failure, which only Apply reports (PDK-996).
				out = append(out, flatpakUnreadLine(p, suffix))
				continue
			}
			out = append(out, flatpakPlanLine(p, userApps[uid], suffix))
		}
	}
	return slices.DeleteFunc(out, func(l string) bool { return l == "" })
}

// planMasks returns the masks to add and remove; without masks to manage it lists none.
func (s *Software) planMasks(ctx context.Context, sp bundle.SoftwareSpec) []string {
	want, recorded := wantedMasks(sp), s.maskRecord()
	if len(want) == 0 && len(recorded) == 0 {
		return nil
	}
	have, err := s.masks(ctx)
	if err != nil {
		return nil
	}
	var out []string
	for _, ref := range want {
		if !have[ref] {
			out = append(out, "mask "+ref)
		}
	}
	for _, ref := range recorded {
		if have[ref] && !slices.Contains(want, ref) {
			out = append(out, "unmask "+ref)
		}
	}
	return out
}

func flatpakPlanLine(p bundle.SoftwarePackage, installed map[string]string, suffix string) string {
	_, ok := installed[p.FlatpakRef]
	switch {
	case p.Intent == bundle.SoftwareRequired && !ok:
		return "flatpak-install " + p.FlatpakRef + suffix
	case removal(p) && ok:
		return "flatpak-remove " + p.FlatpakRef + suffix
	}
	return ""
}

// flatpakUnreadLine is the plan line of an application for a listed user whose installation could not be read: what
// the application's intent would do there, since whether it is needed is unknown.
func flatpakUnreadLine(p bundle.SoftwarePackage, suffix string) string {
	if p.Intent == bundle.SoftwareRequired {
		return "flatpak-install " + p.FlatpakRef + suffix
	}
	return "flatpak-remove " + p.FlatpakRef + suffix
}

// applyFlatpak runs the Flatpak part of a pass after the APT steps, which install the flatpak runtime (plan M13b
// decision 10): the remotes, the masks, then the applications. Without the runtime nothing acts: a required
// application fails as flatpak_missing (F13); forbid, uninstall and hold need nothing where Flatpak is absent
// (architect decision A10-7). A failing flatpak command fails its applications for the pass, never more (design
// contract 8).
func (s *Software) applyFlatpak(ctx context.Context, sp bundle.SoftwareSpec, reachable, outside bool, pass *softwarePass) error {
	s.userScoped = hasUserScope(sp)
	pkgs := flatpakPackages(sp)
	if !s.Sys.PackageInstalled(FlatpakRuntime) {
		for _, p := range pkgs {
			if _, decided := pass.outcome[softwareKey(p)]; !decided && p.Intent == bundle.SoftwareRequired {
				s.failPackage(pass, p, protocol.SoftwareStageInstall, protocol.SoftwareFlatpakMissing, "the flatpak runtime is not installed")
			}
		}
		return nil
	}
	usable, err := s.applyRemotes(ctx, sp, pass)
	if err != nil {
		return err
	}
	if err := s.applyMasks(ctx, sp, pass); err != nil {
		return err
	}
	if len(pkgs) == 0 {
		return nil
	}
	system, err := s.systemApps(ctx)
	if err != nil {
		for _, p := range pkgs {
			if _, decided := pass.outcome[softwareKey(p)]; !decided && (p.Intent == bundle.SoftwareRequired || removal(p)) {
				s.failPackage(pass, p, protocol.SoftwareStageInstall, protocol.SoftwareFlatpakFailed, err.Error())
			}
		}
		return nil
	}
	pass.flatpak = &flatpakPass{apps: system}
	var users map[string]int
	if s.userScoped {
		if users, err = s.sessionUsers(ctx); err != nil {
			slog.Warn("listing the sessions for user-scope Flatpak applications failed", "error", err)
		}
		s.seenSessions = sortedUIDs(users)
	}
	sources := map[string]bundle.SoftwareSource{}
	for _, src := range sp.Sources {
		sources[src.Slug] = src
	}
	f := &flatpakApply{s: s, pass: pass, reachable: reachable, outside: outside, usable: usable, sources: sources, users: users,
		userApps: map[int]map[string]string{}}
	for _, p := range pkgs {
		if _, decided := pass.outcome[softwareKey(p)]; decided {
			continue
		}
		switch {
		case p.Intent == bundle.SoftwareRequired && perUser(p):
			f.installUser(ctx, p)
		case p.Intent == bundle.SoftwareRequired:
			f.installSystem(ctx, p)
		case removal(p) && perUser(p):
			f.removeUser(ctx, p)
		case removal(p):
			f.removeSystem(ctx, p)
		}
	}
	return nil
}

// applyRemotes restores and removes the paddock-* system remotes (remoteChanges) and returns the Flatpak sources whose
// remote is in place. A remote that cannot be listed or written fails the source's required applications for the pass.
func (s *Software) applyRemotes(ctx context.Context, sp bundle.SoftwareSpec, pass *softwarePass) (map[string]bool, error) {
	usable := map[string]bool{}
	device, err := s.systemRemotes(ctx)
	if err != nil {
		for _, src := range sp.Sources {
			if flatpakSource(src) {
				s.failSource(pass, sp, src.Slug, protocol.SoftwareStageSourceUpdate, protocol.SoftwareFlatpakFailed, err.Error())
			}
		}
		return usable, nil
	}
	rec := s.remoteRecord()
	changes, badKeys := s.remoteChanges(sp, device, rec)
	for _, src := range sp.Sources {
		if !flatpakSource(src) {
			continue
		}
		if err, bad := badKeys[src.Slug]; bad {
			s.failSource(pass, sp, src.Slug, protocol.SoftwareStageKeyring, protocol.SoftwareFingerprintMismatch, err.Error())
			continue
		}
		s.clearFailure("source:"+src.Slug, protocol.SoftwareStageKeyring)
		usable[src.Slug] = true
	}
	for _, c := range changes {
		if c.tamper {
			s.Events.emit(protocol.EventTamperProtectedFileChanged, protocol.TamperProtectedFileChanged{File: FlatpakTamperFile(c.name)})
		}
		if c.exists {
			// --force keeps the applications installed from the remote: removing a remote never removes software.
			if _, err := s.runFlatpak(ctx, "remote-delete", "--system", "--force", c.name); err != nil {
				s.failRemote(pass, sp, c, err)
				continue
			}
			slog.Info("flatpak remote removed", "remote", c.name)
			pass.changed = true
		}
		if c.src == nil {
			delete(rec, c.name)
			continue
		}
		if err := s.addRemote(ctx, *c.src, c.keyring); err != nil {
			delete(rec, c.name)
			s.failRemote(pass, sp, c, err)
			continue
		}
		rec[c.name] = flatpakRecorded{url: c.src.URIs[0], fingerprint: c.src.Fingerprint}
		s.clearFailure("source:"+c.src.Slug, protocol.SoftwareStageSourceUpdate)
		pass.changed = true
	}
	for name := range rec {
		if _, ok := device[name]; !ok && !slices.ContainsFunc(changes, func(c remoteChange) bool { return c.name == name && c.src != nil }) {
			delete(rec, name)
		}
	}
	return usable, s.writeRemoteRecord(rec)
}

// failRemote reports a remote that could not be restored or removed; a source's required applications fail with it.
func (s *Software) failRemote(pass *softwarePass, sp bundle.SoftwareSpec, c remoteChange, err error) {
	if c.src != nil {
		s.failSource(pass, sp, c.src.Slug, protocol.SoftwareStageSourceUpdate, protocol.SoftwareFlatpakFailed, err.Error())
		return
	}
	slog.Warn("flatpak remote not removed", "remote", c.name, "error", err)
	pass.failed = append(pass.failed, "remote "+c.name+" ("+protocol.SoftwareFlatpakFailed+")")
}

// addRemote adds the remote of src with its checked key (plan M13b decision 10). The key file lives only for the call.
func (s *Software) addRemote(ctx context.Context, src bundle.SoftwareSource, keyring []byte) error {
	if err := s.Sys.WriteFileAtomic(flatpakKeyFile, keyring, 0o600, 0, 0); err != nil {
		return err
	}
	defer func() {
		if err := s.Sys.Remove(flatpakKeyFile); err != nil && !errors.Is(err, fs.ErrNotExist) {
			slog.Warn("removing the flatpak key file failed", "error", err)
		}
	}()
	_, err := s.runFlatpak(ctx, "remote-add", "--if-not-exists", "--system", "--gpg-import="+flatpakKeyFile, FlatpakRemoteName(src.Slug), src.URIs[0])
	return err
}

// addUserRemote adds the remote name with its checked key to the installation of user uid. The key file lives only
// for the call, under a name of its own, so that concurrent operations never share one.
func (s *Software) addUserRemote(ctx context.Context, uid int, name, uri string, keyring []byte) error {
	path := flatpakUserKeyDir + "/" + strconv.Itoa(uid) + "-" + strconv.FormatUint(s.keySeq.Add(1), 10) + ".gpg"
	// Registered before the write: a write that fails after the rename, at the directory sync, leaves the file.
	defer func() {
		if err := s.Sys.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
			slog.Warn("removing the flatpak key file failed", "path", path, "error", err)
		}
	}()
	if err := s.Sys.WriteFileAtomic(path, keyring, 0o644, 0, 0); err != nil {
		return fmt.Errorf("writing the key of remote %s: %w", name, err)
	}
	_, err := s.runUserFlatpak(ctx, uid, "remote-add", "--user", "--if-not-exists", "--gpg-import="+path, name, uri)
	return err
}

// applyMasks masks the forbidden and held system applications and unmasks those Paddock masked whose intent ended.
// Only the masks Paddock added are recorded, so a mask the device already had survives the end of the intent.
func (s *Software) applyMasks(ctx context.Context, sp bundle.SoftwareSpec, pass *softwarePass) error {
	want := wantedMasks(sp)
	recorded := s.maskRecord()
	if len(want) == 0 && len(recorded) == 0 {
		return nil
	}
	have, err := s.masks(ctx)
	if err != nil {
		for _, p := range flatpakPackages(sp) {
			if slices.Contains(want, p.FlatpakRef) {
				s.failPackage(pass, p, protocol.SoftwareStageRemove, protocol.SoftwareFlatpakFailed, err.Error())
			}
		}
		return nil
	}
	var keep []string
	for _, p := range flatpakPackages(sp) {
		if !slices.Contains(want, p.FlatpakRef) {
			continue
		}
		if have[p.FlatpakRef] {
			// A mask the device set itself is never adopted into the record: ending the intent must leave it.
			if slices.Contains(recorded, p.FlatpakRef) {
				keep = append(keep, p.FlatpakRef)
			}
			continue
		}
		if _, err := s.runFlatpak(ctx, "mask", "--system", p.FlatpakRef); err != nil {
			s.failPackage(pass, p, protocol.SoftwareStageRemove, protocol.SoftwareFlatpakFailed, err.Error())
			continue
		}
		pass.changed = true
		keep = append(keep, p.FlatpakRef)
	}
	for _, ref := range recorded {
		switch {
		case slices.Contains(want, ref):
			if !slices.Contains(keep, ref) && have[ref] {
				keep = append(keep, ref)
			}
		case have[ref]:
			if _, err := s.runFlatpak(ctx, "mask", "--remove", "--system", ref); err != nil {
				slog.Warn("flatpak mask not removed; retrying at the next pass", "ref", ref, "error", err)
				keep = append(keep, ref)
				continue
			}
			pass.changed = true
		}
	}
	return s.writeMaskRecord(keep)
}

// flatpakApply carries one pass over the applications.
type flatpakApply struct {
	s         *Software
	pass      *softwarePass
	reachable bool
	// outside is set while the device is outside its maintenance windows: the policy's installations and removals
	// of non-urgent applications wait (plan M13c decision 6).
	outside  bool
	usable   map[string]bool
	sources  map[string]bundle.SoftwareSource
	users    map[string]int
	userApps map[int]map[string]string
}

// targets returns the listed users with a session whose installation a user-scope application is applied to (A10-11).
func (f *flatpakApply) targets(p bundle.SoftwarePackage) []int { return targetUIDs(p, f.users) }

// waiting reports an installation that failed and waits softwareRetryPasses passes of the same spec, like the APT
// installations.
func (f *flatpakApply) waiting(p bundle.SoftwarePackage, key string) bool {
	r, ok := f.s.retry[key]
	if !ok || r.passes <= 0 {
		return false
	}
	f.s.retry[key] = softwareRetry{passes: r.passes - 1, err: r.err}
	f.pass.set(softwareKey(p), protocol.SoftwareStateFailed, protocol.SoftwareFlatpakFailed, r.err)
	return true
}

// waitsForWindow reports an operation of a non-urgent application outside the maintenance window.
func (f *flatpakApply) waitsForWindow(p bundle.SoftwarePackage) bool { return f.outside && !p.Urgent }

func (f *flatpakApply) installSystem(ctx context.Context, p bundle.SoftwarePackage) {
	key := softwareKey(p)
	if _, ok := f.pass.flatpak.apps[p.FlatpakRef]; ok {
		return
	}
	if f.waitsForWindow(p) {
		f.pass.set(key, protocol.SoftwareStatePending, protocol.SoftwareOutsideWindow, "")
		return
	}
	if f.waiting(p, key) {
		return
	}
	if !f.usable[p.Source] {
		f.s.failPackage(f.pass, p, protocol.SoftwareStageInstall, protocol.SoftwareFlatpakFailed, "the remote "+FlatpakRemoteName(p.Source)+" is not in place")
		return
	}
	_, err := f.s.runFlatpak(ctx, "install", "-y", "--noninteractive", "--system", FlatpakRemoteName(p.Source), p.FlatpakRef)
	if err != nil {
		f.s.retry[key] = softwareRetry{passes: softwareRetryPasses - 1, err: err.Error()}
		f.s.failPackage(f.pass, p, protocol.SoftwareStageInstall, protocol.SoftwareFlatpakFailed, err.Error())
		return
	}
	if system, err := f.s.systemApps(ctx); err == nil {
		f.pass.flatpak.apps = system
	}
	f.installed(p, f.pass.flatpak.apps[p.FlatpakRef])
}

func (f *flatpakApply) installed(p bundle.SoftwarePackage, version string) {
	key := softwareKey(p)
	delete(f.s.failures, "package:"+key)
	delete(f.s.retry, key)
	f.pass.changed = true
	f.s.Events.emit(protocol.EventSoftwareInstalled, protocol.SoftwareChange{Package: key, Version: version, Intent: p.Intent,
		CatalogEntryID: p.CatalogEntryID, Reason: protocol.SoftwareReasonFirstInstall})
}

// removeSystem uninstalls an application from the system installation. A user-scope forbid or uninstall without a user
// list lands here too and deliberately leaves the users' own installations of the application alone: the agent acts
// in a user's installation only for the users a bundle lists, never for every user (A10-11); the system mask does not
// reach them either.
func (f *flatpakApply) removeSystem(ctx context.Context, p bundle.SoftwarePackage) {
	version, ok := f.pass.flatpak.apps[p.FlatpakRef]
	if !ok {
		return
	}
	key := softwareKey(p)
	if f.waitsForWindow(p) {
		f.pass.set(key, protocol.SoftwareStatePending, protocol.SoftwareOutsideWindow, "")
		return
	}
	if !f.reachable {
		f.pass.set(key, protocol.SoftwareStatePending, protocol.SoftwareDeferredOffline, "")
		return
	}
	// No --delete-data and no --unused: the user's data and the shared runtimes stay (plan M13b decision 10).
	if _, err := f.s.runFlatpak(ctx, "uninstall", "-y", "--noninteractive", "--system", "--app", p.FlatpakRef); err != nil {
		f.s.failPackage(f.pass, p, protocol.SoftwareStageRemove, protocol.SoftwareFlatpakFailed, err.Error())
		return
	}
	delete(f.pass.flatpak.apps, p.FlatpakRef)
	f.removed(p, version)
}

func (f *flatpakApply) removed(p bundle.SoftwarePackage, version string) {
	key := softwareKey(p)
	delete(f.s.failures, "package:"+key)
	f.pass.changed = true
	f.s.Events.emit(protocol.EventSoftwareRemoved, protocol.SoftwareChange{Package: key, Version: version, Intent: p.Intent,
		CatalogEntryID: p.CatalogEntryID})
}

func (f *flatpakApply) apps(ctx context.Context, uid int) (map[string]string, error) {
	if a, ok := f.userApps[uid]; ok {
		return a, nil
	}
	a, err := f.s.userApps(ctx, uid)
	if err == nil {
		f.userApps[uid] = a
	}
	return a, err
}

// installUser installs a user-scope application in the installation of every listed user with a session, adding the
// source's remote there first (addUserRemote). Without such a user it stays pending: it is never installed system
// wide instead (decision Q14).
func (f *flatpakApply) installUser(ctx context.Context, p bundle.SoftwarePackage) {
	key := softwareKey(p)
	if len(f.targets(p)) == 0 {
		f.pass.set(key, protocol.SoftwareStatePending, protocol.SoftwareNotYetApplied, "")
		return
	}
	if f.waiting(p, key) {
		return
	}
	src, ok := f.sources[p.Source]
	keyring, err := sourceKeyring(src)
	if !ok || err != nil || !f.usable[p.Source] {
		f.s.failPackage(f.pass, p, protocol.SoftwareStageInstall, protocol.SoftwareFlatpakFailed, "the remote "+FlatpakRemoteName(p.Source)+" is not in place")
		return
	}
	var errs []string
	windowed, backoff := false, false
	for _, uid := range f.targets(p) {
		installed, err := f.apps(ctx, uid)
		if err == nil {
			if _, ok := installed[p.FlatpakRef]; ok {
				continue
			}
			if f.waitsForWindow(p) {
				windowed = true
				continue
			}
			name := FlatpakRemoteName(p.Source)
			err = f.s.addUserRemote(ctx, uid, name, src.URIs[0], keyring)
			if err == nil {
				_, err = f.s.runUserFlatpak(ctx, uid, "install", "-y", "--noninteractive", "--user", name, p.FlatpakRef)
			}
			if err == nil {
				delete(f.userApps, uid)
				version := ""
				if a, lerr := f.apps(ctx, uid); lerr == nil {
					version = a[p.FlatpakRef]
				}
				f.installed(p, version)
				continue
			}
			backoff = true
		}
		errs = append(errs, err.Error())
	}
	if len(errs) > 0 {
		msg := strings.Join(errs, "; ")
		// Only a failed remote-add or install waits: an installation that cannot be listed yet, such as a user
		// manager still starting at the sign-in, is tried again at the next pass (PDK-996 Review 1).
		if backoff {
			f.s.retry[key] = softwareRetry{passes: softwareRetryPasses - 1, err: msg}
		}
		f.s.failPackage(f.pass, p, protocol.SoftwareStageInstall, protocol.SoftwareFlatpakFailed, msg)
		return
	}
	if windowed {
		f.pass.set(key, protocol.SoftwareStatePending, protocol.SoftwareOutsideWindow, "")
		return
	}
	f.pass.set(key, protocol.SoftwareStateInstalled, "", "")
}

// removeUser removes a user-scope application from the installation of every listed user with a session that has it.
func (f *flatpakApply) removeUser(ctx context.Context, p bundle.SoftwarePackage) {
	key := softwareKey(p)
	var errs []string
	deferred, windowed := false, false
	for _, uid := range f.targets(p) {
		installed, err := f.apps(ctx, uid)
		if err == nil {
			version, ok := installed[p.FlatpakRef]
			if !ok {
				continue
			}
			if f.waitsForWindow(p) {
				windowed = true
				continue
			}
			if !f.reachable {
				deferred = true
				continue
			}
			if _, err = f.s.runUserFlatpak(ctx, uid, "uninstall", "-y", "--noninteractive", "--user", "--app", p.FlatpakRef); err == nil {
				delete(installed, p.FlatpakRef)
				f.removed(p, version)
				continue
			}
		}
		errs = append(errs, err.Error())
	}
	switch {
	case len(errs) > 0:
		f.s.failPackage(f.pass, p, protocol.SoftwareStageRemove, protocol.SoftwareFlatpakFailed, strings.Join(errs, "; "))
	case windowed:
		f.pass.set(key, protocol.SoftwareStatePending, protocol.SoftwareOutsideWindow, "")
	case deferred:
		f.pass.set(key, protocol.SoftwareStatePending, protocol.SoftwareDeferredOffline, "")
	}
}

// flatpakItem is the status of a Flatpak application. A user-scope application reports what the pass decided for
// its listed users with a session; the per-user status is the self-service's (plan M13b decision 14).
func (s *Software) flatpakItem(p bundle.SoftwarePackage, pass *softwarePass) protocol.SoftwareItem {
	key := softwareKey(p)
	it, decided := pass.outcome[key]
	version, installed := "", false
	if pass.flatpak != nil && systemActs(p) {
		version, installed = pass.flatpak.apps[p.FlatpakRef]
	}
	if !decided {
		switch {
		case perUser(p) && p.Intent == bundle.SoftwareRequired:
			it.State, it.Reason = protocol.SoftwareStatePending, protocol.SoftwareNotYetApplied
		case p.Intent == bundle.SoftwareHold && installed:
			it.State = protocol.SoftwareStateHeld
		case installed && (p.Intent == bundle.SoftwareRequired || p.Intent == bundle.SoftwareAvailable):
			it.State = protocol.SoftwareStateInstalled
		case p.Intent != bundle.SoftwareRequired && !installed:
			it.State = protocol.SoftwareStateAbsent
		default:
			it.State, it.Reason = protocol.SoftwareStatePending, protocol.SoftwareNotYetApplied
		}
	}
	it.CatalogEntryID, it.Package, it.Intent = p.CatalogEntryID, key, p.Intent
	if installed {
		it.Version = version
	}
	return it
}
