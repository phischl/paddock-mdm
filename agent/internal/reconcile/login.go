package reconcile

import (
	"bufio"
	"bytes"
	"context"
	_ "embed" // the Himmelblau repository key
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/paddock-mdm/paddock/agent/internal/sessions"
	"github.com/paddock-mdm/paddock/pkg/bundle"
	"github.com/paddock-mdm/paddock/pkg/protocol"
)

// Files of the login reconciler.
const (
	HimmelblauConf    = "/etc/himmelblau/himmelblau.conf"
	DenyList          = "/etc/paddock/login-deny"
	himmelblauKeyring = "/etc/apt/keyrings/himmelblau.gpg"
	himmelblauSource  = "/etc/apt/sources.list.d/paddock-himmelblau.list"
	commonAuth        = "/etc/pam.d/common-auth"
	commonAccount     = "/etc/pam.d/common-account"
)

// The PAM lines the pam-auth-update profile paddock-deny of the paddock-agent package produces (plan M3b decision
// 9); the agent verifies them and never edits PAM files.
const (
	DenyAuthLine    = "auth requisite pam_listfile.so item=user sense=deny file=/etc/paddock/login-deny onerr=succeed"
	DenyAccountLine = "account required pam_listfile.so item=user sense=deny file=/etc/paddock/login-deny onerr=succeed"
)

// himmelblauKey is the repository signing key "Himmelblau Build (2025)", fingerprint
// E87F D8D4 63A5 E481 4B9C DBA9 0CC0 D400 2C42 5E03 (binary OpenPGP, checked by TestHimmelblauKeyFingerprint).
//
//go:embed himmelblau.gpg
var himmelblauKey []byte

// himmelblauPackages is the upstream installer's selection for a GDM desktop with sshd (PoC M1).
var himmelblauPackages = []string{"himmelblau", "pam-himmelblau", "nss-himmelblau", "himmelblau-qr-greeter", "himmelblau-sshd-config"}

// himmelblauUnits read pam_allow_groups only at start and are restarted after every configuration change.
var himmelblauUnits = []string{"himmelblaud.service", "himmelblaud-tasks.service"}

// restartWait bounds the wait for himmelblaud to become active after a restart.
const restartWait = 30 * time.Second

// Login reconciles the login resource (plan M3b decisions 6–10): the Himmelblau packages, himmelblau.conf, the deny
// list of locked users and the sessions of newly locked users or, when logins are suspended, of all directory
// users. It verifies the PAM configuration but never edits it.
type Login struct {
	Sys    System
	Events *Events
	// lastFailure is the login.apply_failed reported last; the same failure is not reported again by every drift
	// pass.
	lastFailure string
	pamBroken   bool
}

// Type implements Reconciler.
func (l *Login) Type() string { return bundle.TypeLogin }

func (l *Login) spec(r bundle.Resource) (bundle.LoginSpec, error) {
	var s bundle.LoginSpec
	if err := json.Unmarshal(r.Spec, &s); err != nil {
		return s, fmt.Errorf("invalid login spec: %w", err)
	}
	if s.Provider != bundle.ProviderHimmelblau {
		return s, fmt.Errorf("unsupported login provider %q", s.Provider)
	}
	if !bundle.ValidHimmelblauVersion(s.Himmelblau.PackageVersion) {
		return s, fmt.Errorf("invalid himmelblau package_version %q", s.Himmelblau.PackageVersion)
	}
	if s.SessionAction != bundle.SessionActionLockScreen && s.SessionAction != bundle.SessionActionTerminate {
		return s, fmt.Errorf("invalid session_action %q", s.SessionAction)
	}
	// Defence in depth: every value ends up in a line-based file.
	h := s.Himmelblau
	values := append([]string{h.OIDCIssuerURL, h.AppID, h.Domain}, h.PamAllowGroups...)
	values = append(append(values, s.LockedUsers...), s.BreakGlassAccounts...)
	for _, v := range values {
		if !plainValue(v) {
			return s, fmt.Errorf("invalid login value %q", v)
		}
	}
	return s, nil
}

// plainValue is a non-empty value without whitespace, control characters, comment or list separators.
func plainValue(v string) bool {
	if v == "" {
		return false
	}
	for _, r := range v {
		if r <= ' ' || r == 0x7f || r == '#' || r == ';' || r == ',' {
			return false
		}
	}
	return true
}

// loginState is what Plan and Apply compare the device with: the local accounts and the desired files.
type loginState struct {
	local              map[string]int
	wantConf, wantDeny []byte
}

func (l *Login) state(s bundle.LoginSpec) (loginState, error) {
	var st loginState
	passwd, _, err := l.Sys.ReadFile("/etc/passwd")
	if err != nil {
		return st, fmt.Errorf("read /etc/passwd: %w", err)
	}
	st.local = sessions.LocalUIDs(passwd)
	st.wantConf = renderHimmelblauConf(s)
	st.wantDeny = renderDenyList(s, st.local)
	return st, nil
}

// Plan implements Reconciler.
func (l *Login) Plan(_ context.Context, r bundle.Resource) ([]string, error) {
	s, err := l.spec(r)
	if err != nil {
		return nil, err
	}
	st, err := l.state(s)
	if err != nil {
		return nil, err
	}
	var changes []string
	if !l.installed(s.Himmelblau.PackageVersion) {
		changes = append(changes, "package")
	}
	if !l.fileIs(HimmelblauConf, st.wantConf) {
		changes = append(changes, "config")
	}
	if !l.fileIs(DenyList, st.wantDeny) {
		changes = append(changes, "deny_list")
	}
	if file := l.pamProblem(); file != "" {
		changes = append(changes, "pam "+file)
	}
	return changes, nil
}

// Apply implements Reconciler: package, deny list, configuration with daemon restart, sessions, PAM check. The deny
// list and the sessions do not depend on the package: a failed installation never delays a lock.
func (l *Login) Apply(ctx context.Context, r bundle.Resource) Result {
	s, err := l.spec(r)
	if err != nil {
		return errorResult(r.ID, err)
	}
	st, err := l.state(s)
	if err != nil {
		return errorResult(r.ID, err)
	}
	var changed []string
	var aptErr error
	if !l.installed(s.Himmelblau.PackageVersion) {
		if aptErr = l.install(ctx, s.Himmelblau.PackageVersion); aptErr == nil {
			changed = append(changed, "package")
		}
	}
	wasDenied := denied(l.read(DenyList))
	if !l.fileIs(DenyList, st.wantDeny) {
		if err := l.writeOrRemove(DenyList, st.wantDeny); err != nil {
			return l.fail(r.ID, protocol.LoginStageDenyList, err)
		}
		changed = append(changed, "deny_list")
	}
	wasSuspended := suspendedConf(l.read(HimmelblauConf))
	if aptErr == nil && !l.fileIs(HimmelblauConf, st.wantConf) {
		if err := l.Sys.WriteFileAtomic(HimmelblauConf, st.wantConf, 0o644, 0, 0); err != nil {
			return l.fail(r.ID, protocol.LoginStageConfig, err)
		}
		changed = append(changed, "config")
		if err := l.restart(ctx); err != nil {
			return l.fail(r.ID, protocol.LoginStageRestart, err)
		}
	}
	if len(changed) > 0 {
		l.Events.emit(protocol.EventLoginApplied, protocol.LoginApplied{Changed: changed})
	}
	if err := l.sessions(ctx, s, st.local, wasDenied, s.Suspended && !wasSuspended); err != nil {
		return l.fail(r.ID, protocol.LoginStageSessions, err)
	}
	if aptErr != nil {
		return l.fail(r.ID, protocol.LoginStageApt, aptErr)
	}
	if res, ok := l.checkPAM(r.ID); !ok {
		return res
	}
	l.lastFailure = ""
	if len(changed) == 0 {
		return Result{ID: r.ID, Status: OK}
	}
	return Result{ID: r.ID, Status: Changed}
}

// fail reports login.apply_failed once per distinct failure and returns the error result.
func (l *Login) fail(id, stage string, err error) Result {
	if key := stage + ": " + err.Error(); key != l.lastFailure {
		l.lastFailure = key
		l.Events.emit(protocol.EventLoginApplyFailed, protocol.LoginApplyFailed{Stage: stage, Message: err.Error()})
	}
	return errorResult(id, fmt.Errorf("%s: %w", stage, err))
}

// checkPAM verifies the deny-list PAM lines; a deviation is reported once as login.apply_failed (stage pam) and
// tamper.protected_file_changed until the package reconfiguration restored them.
func (l *Login) checkPAM(id string) (Result, bool) {
	file := l.pamProblem()
	if file == "" {
		l.pamBroken = false
		return Result{}, true
	}
	if !l.pamBroken {
		l.pamBroken = true
		l.Events.emit(protocol.EventTamperProtectedFileChanged, protocol.TamperProtectedFileChanged{File: file})
	}
	return l.fail(id, protocol.LoginStagePAM, fmt.Errorf("the paddock-deny PAM profile is not in effect in %s; run dpkg-reconfigure paddock-agent", file)), false
}

// pamProblem returns the PAM file that lacks its deny line ("" if both are in place): common-account must contain
// DenyAccountLine, common-auth DenyAuthLine before any pam_himmelblau line.
func (l *Login) pamProblem() string {
	auth := pamLines(l.read(commonAuth))
	deny := slices.Index(auth, DenyAuthLine)
	himmelblau := slices.IndexFunc(auth, func(line string) bool { return strings.Contains(line, "pam_himmelblau.so") })
	if deny < 0 || (himmelblau >= 0 && himmelblau < deny) {
		return commonAuth
	}
	if !slices.Contains(pamLines(l.read(commonAccount)), DenyAccountLine) {
		return commonAccount
	}
	return ""
}

// pamLines returns the non-comment lines of a PAM file with single spaces between fields.
func pamLines(data []byte) []string {
	var out []string
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		if f := strings.Fields(sc.Text()); len(f) > 0 && !strings.HasPrefix(f[0], "#") {
			out = append(out, strings.Join(f, " "))
		}
	}
	return out
}

// installed reports whether every Himmelblau package is installed in version (Debian versions "<version>-…").
func (l *Login) installed(version string) bool {
	for _, p := range himmelblauPackages {
		if v := l.Sys.PackageVersion(p); v != version && !strings.HasPrefix(v, version+"-") {
			return false
		}
	}
	return true
}

// install adds the official repository of version with the embedded key, updates only that source and installs the
// packages non-interactively with the dpkg options of the upstream installer (PoC M1). apt waits up to 10 minutes
// for a dpkg lock held by e.g. unattended-upgrades (plan M3b risk R1).
func (l *Login) install(ctx context.Context, version string) error {
	versionID, err := l.ubuntuVersion()
	if err != nil {
		return err
	}
	source := fmt.Sprintf("deb [signed-by=%s] https://packages.himmelblau-idm.org/stable/%s/deb/ubuntu%s/ ./\n", himmelblauKeyring, version, versionID)
	if err := l.Sys.WriteFileAtomic(himmelblauKeyring, himmelblauKey, 0o644, 0, 0); err != nil {
		return err
	}
	if err := l.Sys.WriteFileAtomic(himmelblauSource, []byte(source), 0o644, 0, 0); err != nil {
		return err
	}
	if err := l.apt(ctx, "update", "-q", "-o", "Dir::Etc::sourcelist=sources.list.d/paddock-himmelblau.list",
		"-o", "Dir::Etc::sourceparts=-", "-o", "APT::Get::List-Cleanup=0", "-o", "DPkg::Lock::Timeout=600"); err != nil {
		return err
	}
	args := append([]string{"install", "-y", "-q", "-o", "DPkg::Lock::Timeout=600", "-o", "Dpkg::Options::=--force-confdef",
		"-o", "Dpkg::Options::=--force-confold"}, himmelblauPackages...)
	if err := l.apt(ctx, args...); err != nil {
		return err
	}
	if !l.installed(version) {
		return fmt.Errorf("himmelblau %s is not installed after apt-get install (installed: %q)", version, l.Sys.PackageVersion("himmelblau"))
	}
	return nil
}

func (l *Login) apt(ctx context.Context, args ...string) error {
	out, exit, err := l.Sys.AptGet(ctx, args...)
	if err != nil {
		return fmt.Errorf("apt-get %s: %w", args[0], err)
	}
	if exit != 0 {
		return fmt.Errorf("apt-get %s: exit %d: %s", args[0], exit, lastLine(out))
	}
	return nil
}

// ubuntuVersion returns VERSION_ID of an Ubuntu system; the repository has one tree per release. /etc/os-release is
// usually a symlink to /usr/lib/os-release, which os-release(5) names as the fallback.
func (l *Login) ubuntuVersion() (string, error) {
	data, _, err := l.Sys.ReadFile("/etc/os-release")
	if data == nil {
		data, _, err = l.Sys.ReadFile("/usr/lib/os-release")
	}
	if err != nil {
		return "", fmt.Errorf("read os-release: %w", err)
	}
	vars := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		if k, v, ok := strings.Cut(sc.Text(), "="); ok {
			if u, err := strconv.Unquote(v); err == nil {
				v = u
			}
			vars[k] = v
		}
	}
	if vars["ID"] != "ubuntu" || !plainValue(vars["VERSION_ID"]) {
		return "", fmt.Errorf("unsupported distribution %q %q", vars["ID"], vars["VERSION_ID"])
	}
	return vars["VERSION_ID"], nil
}

// restart restarts the Himmelblau daemons, which read pam_allow_groups only at start, and waits until himmelblaud
// is active. reset-failed first: the package starts the daemon before a configuration exists, which hits the
// start limit (PoC M1).
func (l *Login) restart(ctx context.Context) error {
	for _, verb := range []string{"reset-failed", "restart"} {
		for _, u := range himmelblauUnits {
			if err := run(ctx, l.Sys, []string{"systemctl " + verb + " " + u}); err != nil {
				return err
			}
		}
	}
	deadline := time.Now().Add(restartWait)
	for {
		out, _, err := l.Sys.Systemctl(ctx, "is-active", himmelblauUnits[0])
		if err != nil {
			return err
		}
		if firstLine(out) == "active" {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("%s is %s %s after the restart", himmelblauUnits[0], firstLine(out), restartWait)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
}

// sessions locks or terminates the sessions of newly locked users (not in wasDenied) and, when logins became
// suspended, terminates the sessions of all directory users (plan M3b decision 10).
func (l *Login) sessions(ctx context.Context, s bundle.LoginSpec, local map[string]int, wasDenied map[string]bool, suspended bool) error {
	var locked []string
	for _, u := range s.LockedUsers {
		if !wasDenied[u] && !slices.Contains(s.BreakGlassAccounts, u) {
			locked = append(locked, u)
		}
	}
	if len(locked) == 0 && !suspended {
		return nil
	}
	list, err := sessions.List(ctx, l.Sys.Loginctl)
	if err != nil {
		return err
	}
	var errs []error
	for _, u := range locked {
		short, _, _ := strings.Cut(u, "@")
		var own []sessions.Session
		for _, ss := range list {
			if (ss.User == u || ss.User == short) && sessions.IsDirectoryUser(ss, local, s.BreakGlassAccounts) {
				own = append(own, ss)
			}
		}
		ev := protocol.UserLockApplied{Username: u}
		if s.SessionAction == bundle.SessionActionTerminate {
			n, err := l.terminate(ctx, own)
			ev.SessionsTerminated, errs = n, append(errs, err)
		} else {
			for _, ss := range own {
				err := l.loginctl(ctx, "lock-session", ss.ID)
				if err == nil {
					ev.SessionsLocked++
				}
				errs = append(errs, err)
			}
		}
		l.Events.emit(protocol.EventUserLockApplied, ev)
	}
	if suspended {
		var dir []sessions.Session
		for _, ss := range list {
			if sessions.IsDirectoryUser(ss, local, s.BreakGlassAccounts) {
				dir = append(dir, ss)
			}
		}
		n, err := l.terminate(ctx, dir)
		errs = append(errs, err)
		l.Events.emit(protocol.EventLoginsSuspensionApplied, protocol.LoginsSuspensionApplied{SessionsTerminated: n})
	}
	return errors.Join(errs...)
}

// terminate ends the sessions' users (`loginctl terminate-user`, once per UID) and returns the number of sessions
// ended.
func (l *Login) terminate(ctx context.Context, list []sessions.Session) (int, error) {
	var errs []error
	done := map[int]bool{}
	n := 0
	for _, ss := range list {
		if !done[ss.UID] {
			done[ss.UID] = true
			if err := l.loginctl(ctx, "terminate-user", strconv.Itoa(ss.UID)); err != nil {
				errs = append(errs, err)
				continue
			}
		}
		n++
	}
	return n, errors.Join(errs...)
}

func (l *Login) loginctl(ctx context.Context, args ...string) error {
	out, exit, err := l.Sys.Loginctl(ctx, args...)
	if err != nil {
		return err
	}
	if exit != 0 {
		return fmt.Errorf("loginctl %s: exit %d: %s", strings.Join(args, " "), exit, lastLine(out))
	}
	return nil
}

// read returns the content of a regular file, nil if it is missing or not a regular file.
func (l *Login) read(path string) []byte {
	data, _, err := l.Sys.ReadFile(path)
	if err != nil {
		return nil
	}
	return data
}

// fileIs reports whether path is a regular file 0644 root:root with content want; want nil means absent.
func (l *Login) fileIs(path string, want []byte) bool {
	data, info, err := l.Sys.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return want == nil
	}
	if err != nil || data == nil || want == nil || !bytes.Equal(data, want) || info.Mode().Perm() != 0o644 {
		return false
	}
	uid, gid := l.Sys.Owner(info)
	return uid == 0 && gid == 0
}

func (l *Login) writeOrRemove(path string, data []byte) error {
	if data != nil {
		return l.Sys.WriteFileAtomic(path, data, 0o644, 0, 0)
	}
	if err := l.Sys.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

// renderHimmelblauConf renders himmelblau.conf as in PoC M1 (plan M3b decision 7). pam_allow_groups is always
// written: empty denies everyone (suspension), a missing line would allow everyone.
func renderHimmelblauConf(s bundle.LoginSpec) []byte {
	h := s.Himmelblau
	var b bytes.Buffer
	b.WriteString("# Managed by Paddock. Do not edit: local changes are reverted.\n[global]\n")
	fmt.Fprintf(&b, "oidc_issuer_url = %s\napp_id = %s\ndomain = %s\n", h.OIDCIssuerURL, h.AppID, h.Domain)
	b.WriteString(strings.TrimSpace("pam_allow_groups = "+strings.Join(h.PamAllowGroups, ",")) + "\n")
	fmt.Fprintf(&b, "allow_console_password_only = false\nenable_hello = %t\nhello_pin_min_length = %d\nlocal_groups = users\n",
		h.EnableHello, h.HelloPinMinLength)
	return b.Bytes()
}

// suspendedConf reports whether a himmelblau.conf denies everyone (pam_allow_groups present and empty).
func suspendedConf(conf []byte) bool {
	for _, line := range strings.Split(string(conf), "\n") {
		if k, v, ok := strings.Cut(line, "="); ok && strings.TrimSpace(k) == "pam_allow_groups" {
			return strings.TrimSpace(v) == ""
		}
	}
	return false
}

// renderDenyList returns the deny list (plan M3b decision 8): for every locked user that is no break-glass account
// the UPN and the short name, except a short name that is a local account below the directory UIDs. nil means no
// file.
func renderDenyList(s bundle.LoginSpec, local map[string]int) []byte {
	var names []string
	add := func(n string) {
		if !slices.Contains(names, n) {
			names = append(names, n)
		}
	}
	for _, u := range s.LockedUsers {
		if slices.Contains(s.BreakGlassAccounts, u) {
			continue
		}
		add(u)
		if short, _, ok := strings.Cut(u, "@"); ok && short != "" {
			if uid, isLocal := local[short]; !isLocal || uid >= sessions.FirstDirectoryUID {
				add(short)
			}
		}
	}
	if len(names) == 0 {
		return nil
	}
	return []byte(strings.Join(names, "\n") + "\n")
}

// denied parses a deny list into a set of names.
func denied(data []byte) map[string]bool {
	out := map[string]bool{}
	for _, n := range strings.Fields(string(data)) {
		out[n] = true
	}
	return out
}

func lastLine(out string) string {
	lines := strings.Split(strings.TrimSpace(out), "\n")
	return strings.TrimSpace(lines[len(lines)-1])
}
