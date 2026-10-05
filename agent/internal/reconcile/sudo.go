package reconcile

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/paddock-mdm/paddock/pkg/bundle"
	"github.com/paddock-mdm/paddock/pkg/protocol"
	"github.com/paddock-mdm/paddock/pkg/sudoers"
)

// Files of the sudo reconciler (architecture §10.3).
const (
	SudoersDir    = "/etc/sudoers.d"
	Sudoers       = "/etc/sudoers"
	rollbackDir   = "/var/lib/paddock/rollback"
	QuarantineDir = "/var/lib/paddock/quarantine/sudoers.d"
	// sudoersHash records the SHA-256 of /etc/sudoers the agent last saw (plan M3b decision 14).
	sudoersHash = "/var/lib/paddock/state/sudoers.sha256"
)

// The sudo and visudo of the active sudo implementation: on Ubuntu 26.04 both are alternatives (visudo follows sudo)
// that point to sudo-rs or to classic sudo.
const (
	sudoBinary   = "/usr/bin/sudo"
	visudoBinary = "/usr/sbin/visudo"
)

// SudoFlavor detects the active sudo implementation: the version output of the binary /usr/bin/sudo resolves to
// starts with "sudo-rs" for sudo-rs; anything else is classic sudo. It also returns the resolved visudo that belongs
// to it. An operator can switch the alternative at any time, so it is detected at every plan and apply.
func SudoFlavor(ctx context.Context, sys System) (sudoers.Flavor, string, error) {
	bin, err := sys.EvalSymlinks(sudoBinary)
	if err != nil {
		return "", "", fmt.Errorf("resolve %s: %w", sudoBinary, err)
	}
	out, exit, err := sys.SudoVersion(ctx, bin)
	if err == nil && exit != 0 {
		err = fmt.Errorf("exit %d", exit)
	}
	if err != nil {
		return "", "", fmt.Errorf("%s --version: %w", bin, err)
	}
	visudo, err := sys.EvalSymlinks(visudoBinary)
	if err != nil {
		return "", "", fmt.Errorf("resolve %s: %w", visudoBinary, err)
	}
	if strings.HasPrefix(firstLine(out), "sudo-rs") {
		return sudoers.SudoRS, visudo, nil
	}
	return sudoers.Classic, visudo, nil
}

// includedir is the line of /etc/sudoers that makes sudo read /etc/sudoers.d.
var includedir = regexp.MustCompile(`(?m)^[@#]includedir\s+/etc/sudoers\.d\s*$`)

// Sudo reconciles the sudo resource (plan M3b decisions 12–15): one sudoers file per user with an effective profile,
// rendered with the user's UID, the lecture file, the quarantine of foreign files in /etc/sudoers.d, the detection
// of changes of /etc/sudoers and the members of the privileged local groups.
type Sudo struct {
	Sys    System
	Events *Events
	// reported holds the last sudo.apply_failed per username ("" for the configuration as a whole) and the users
	// reported as unresolved, so that a drift pass does not repeat them.
	failed     map[string]string
	unresolved map[string]bool
}

// Type implements Reconciler.
func (s *Sudo) Type() string { return bundle.TypeSudo }

func (s *Sudo) spec(r bundle.Resource) (bundle.SudoSpec, error) {
	var spec bundle.SudoSpec
	if err := json.Unmarshal(r.Spec, &spec); err != nil {
		return spec, fmt.Errorf("invalid sudo spec: %w", err)
	}
	for _, e := range spec.Entries {
		if err := sudoers.Validate(e); err != nil {
			return spec, fmt.Errorf("sudo entry %s: %w", e.Username, err)
		}
	}
	names := append(append(slices.Clone(spec.PrivilegedGroups), spec.SudoersDAllowlist...), spec.BreakGlassAccounts...)
	for _, n := range names {
		if !plainValue(n) || strings.Contains(n, "/") {
			return spec, fmt.Errorf("invalid name %q in the sudo spec", n)
		}
	}
	return spec, nil
}

// sudoPlan is what Apply has to do.
type sudoPlan struct {
	flavor     sudoers.Flavor
	visudo     string
	lecture    bool
	write      map[string][]byte // file name → content
	users      map[string]string // file name → username
	unresolved []string
	rejected   map[string]error // username → why its file cannot be rendered
	remove     []string         // stale paddock-u-* files
	quarantine []string         // foreign files
	sudoersSum string           // current SHA-256 of /etc/sudoers if it differs from the recorded one
	members    map[string][]string
}

func (p sudoPlan) changes() []string {
	var out []string
	if p.lecture {
		out = append(out, "lecture")
	}
	for name := range p.write {
		out = append(out, "write "+name)
	}
	for _, u := range p.unresolved {
		out = append(out, "resolve "+u)
	}
	for u := range p.rejected {
		out = append(out, "render "+u)
	}
	for _, name := range p.remove {
		out = append(out, "remove "+name)
	}
	for _, name := range p.quarantine {
		out = append(out, "quarantine "+name)
	}
	if p.sudoersSum != "" {
		out = append(out, "check "+Sudoers)
	}
	for g, members := range p.members {
		for _, m := range members {
			out = append(out, "remove "+m+" from "+g)
		}
	}
	slices.Sort(out)
	return out
}

func (s *Sudo) plan(ctx context.Context, spec bundle.SudoSpec) (sudoPlan, error) {
	p := sudoPlan{write: map[string][]byte{}, users: map[string]string{}, members: map[string][]string{}, rejected: map[string]error{}}
	var err error
	if p.flavor, p.visudo, err = SudoFlavor(ctx, s.Sys); err != nil {
		return p, err
	}
	p.lecture = !fileHas(s.Sys, sudoers.LectureFile, []byte(spec.LectureText), 0o644)
	wanted := map[string]bool{}
	for _, e := range spec.Entries {
		name := sudoers.FileName(e.Username)
		wanted[name] = true
		uid, ok, err := s.uid(ctx, e.Username)
		if err != nil {
			return p, err
		}
		if !ok {
			p.unresolved = append(p.unresolved, e.Username)
			continue
		}
		content, err := sudoers.Render(e, uid, p.flavor)
		if err != nil { // e.g. a UID sudo-rs cannot handle: reported for the user, never skipped silently
			p.rejected[e.Username] = err
			continue
		}
		if !fileHas(s.Sys, SudoersDir+"/"+name, content, 0o440) {
			p.write[name], p.users[name] = content, e.Username
		}
	}
	names, err := s.Sys.ReadDir(SudoersDir)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return p, err
	}
	for _, name := range names {
		switch {
		case strings.HasPrefix(name, "paddock-u-"):
			if !wanted[name] {
				p.remove = append(p.remove, name)
			}
		case !slices.Contains(spec.SudoersDAllowlist, name):
			p.quarantine = append(p.quarantine, name)
		}
	}
	data, _, err := s.Sys.ReadFile(Sudoers)
	if err != nil {
		return p, fmt.Errorf("read %s: %w", Sudoers, err)
	}
	sum := sha256.Sum256(data)
	recorded, _, _ := s.Sys.ReadFile(sudoersHash)
	if cur := hex.EncodeToString(sum[:]); strings.TrimSpace(string(recorded)) != cur {
		p.sudoersSum = cur
	}
	p.members, err = s.groupMembers(ctx, spec)
	return p, err
}

// Plan implements Reconciler.
func (s *Sudo) Plan(ctx context.Context, r bundle.Resource) ([]string, error) {
	spec, err := s.spec(r)
	if err != nil {
		return nil, err
	}
	p, err := s.plan(ctx, spec)
	if err != nil {
		return nil, err
	}
	return p.changes(), nil
}

// Apply implements Reconciler. Foreign files are quarantined before any Paddock file is written, so that the
// whole-configuration check of the apply procedure is not failed by them.
func (s *Sudo) Apply(ctx context.Context, r bundle.Resource) Result {
	spec, err := s.spec(r)
	if err != nil {
		return errorResult(r.ID, err)
	}
	p, err := s.plan(ctx, spec)
	if err != nil {
		return errorResult(r.ID, err)
	}
	changed := false
	var errs []error
	if p.sudoersSum != "" {
		errs = append(errs, s.checkSudoers(ctx, p.visudo, p.sudoersSum))
	}
	for _, name := range p.quarantine {
		err := s.quarantine(name)
		changed = changed || err == nil
		errs = append(errs, err)
	}
	if p.lecture {
		err := s.Sys.WriteFileAtomic(sudoers.LectureFile, []byte(spec.LectureText), 0o644, 0, 0)
		changed = changed || err == nil
		errs = append(errs, err)
	}
	s.reportUnresolved(p.unresolved)
	for _, username := range sortedKeys(p.rejected) {
		s.reportFailure(username, p.rejected[username])
		errs = append(errs, fmt.Errorf("%s: %w", username, p.rejected[username]))
	}
	for _, name := range sortedKeys(p.write) {
		username := p.users[name]
		if err := s.install(ctx, p.visudo, name, p.write[name]); err != nil {
			s.reportFailure(username, err)
			errs = append(errs, fmt.Errorf("%s: %w", username, err))
			continue
		}
		delete(s.failed, username)
		changed = true
	}
	for _, name := range p.remove {
		err := s.Sys.Remove(SudoersDir + "/" + name)
		changed = changed || err == nil
		errs = append(errs, err)
	}
	removed, err := s.cleanGroups(ctx, p.members)
	changed = changed || removed
	errs = append(errs, err)
	if err := errors.Join(errs...); err != nil {
		return errorResult(r.ID, err)
	}
	if !changed {
		return Result{ID: r.ID, Status: OK}
	}
	return Result{ID: r.ID, Status: Changed}
}

// uid resolves a username through NSS (Himmelblau answers online and from its cache).
func (s *Sudo) uid(ctx context.Context, username string) (uint32, bool, error) {
	out, exit, err := s.Sys.Getent(ctx, "passwd", username)
	if err != nil {
		return 0, false, fmt.Errorf("getent passwd %s: %w", username, err)
	}
	f := strings.Split(strings.TrimSpace(out), ":")
	if exit != 0 || len(f) < 3 {
		return 0, false, nil
	}
	uid, err := strconv.ParseUint(f[2], 10, 32)
	if err != nil {
		return 0, false, nil
	}
	return uint32(uid), true, nil
}

// install applies one sudoers file with the procedure of architecture §10.3: rollback copy, a temporary file sudo
// ignores (dot name), `visudo -c -f`, rename into place, `visudo -c` over the whole configuration, and on failure
// the previous state is restored.
func (s *Sudo) install(ctx context.Context, visudo, name string, content []byte) error {
	path := SudoersDir + "/" + name
	old, _, err := s.Sys.ReadFile(path)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if old != nil {
		if err := s.Sys.WriteFileAtomic(rollbackDir+"/"+name, old, 0o600, 0, 0); err != nil {
			return fmt.Errorf("rollback copy: %w", err)
		}
	}
	tmp := SudoersDir + "/.paddock-tmp-" + randomHex()
	if err := s.Sys.WriteFileAtomic(tmp, content, 0o440, 0, 0); err != nil {
		return err
	}
	if err := s.visudo(ctx, visudo, "-c", "-f", tmp); err != nil {
		_ = s.Sys.Remove(tmp)
		// The message names the target, not the random temporary file, so the same failure is reported once.
		return errors.New(strings.ReplaceAll(err.Error(), tmp, path))
	}
	if err := s.Sys.Rename(tmp, path); err != nil {
		_ = s.Sys.Remove(tmp)
		return err
	}
	if err := s.visudo(ctx, visudo, "-c"); err != nil {
		if old != nil {
			return errors.Join(err, s.Sys.WriteFileAtomic(path, old, 0o440, 0, 0))
		}
		return errors.Join(err, s.Sys.Remove(path))
	}
	return nil
}

func (s *Sudo) visudo(ctx context.Context, path string, args ...string) error {
	out, exit, err := s.Sys.Visudo(ctx, path, args...)
	if err != nil {
		return fmt.Errorf("visudo: %w", err)
	}
	if exit != 0 {
		return fmt.Errorf("visudo %s: %s", strings.Join(args, " "), lastLine(out))
	}
	return nil
}

// checkSudoers reports a changed /etc/sudoers (never at the first apply, which only records it) and checks that
// it still includes /etc/sudoers.d and passes visudo; the agent never rewrites it (plan M3b decision 14).
func (s *Sudo) checkSudoers(ctx context.Context, visudo, sum string) error {
	recorded, _, err := s.Sys.ReadFile(sudoersHash)
	if err == nil {
		s.Events.emit(protocol.EventTamperSudoersChanged, protocol.TamperSudoersChanged{
			SHA256Before: strings.TrimSpace(string(recorded)), SHA256After: sum,
		})
	}
	data, _, err := s.Sys.ReadFile(Sudoers)
	if err != nil {
		return err
	}
	var problem error
	if !includedir.Match(data) {
		problem = fmt.Errorf("%s lacks @includedir %s", Sudoers, SudoersDir)
	} else {
		problem = s.visudo(ctx, visudo, "-c")
	}
	if problem != nil {
		s.reportFailure("", problem)
		return problem
	}
	delete(s.failed, "")
	return s.Sys.WriteFileAtomic(sudoersHash, []byte(sum+"\n"), 0o600, 0, 0)
}

// quarantine moves a foreign regular file of /etc/sudoers.d to the quarantine directory (0600, copied, so that it
// also works across file systems) and reports it. Anything else (a symlink) is removed and reported without a
// quarantine copy.
func (s *Sudo) quarantine(name string) error {
	src := SudoersDir + "/" + name
	dst := ""
	data, _, err := s.Sys.ReadFile(src)
	if err != nil {
		return err
	}
	if data != nil {
		dst = fmt.Sprintf("%s/%s.%d", QuarantineDir, name, time.Now().Unix())
		if err := s.Sys.WriteFileAtomic(dst, data, 0o600, 0, 0); err != nil {
			return err
		}
	}
	if err := s.Sys.Remove(src); err != nil {
		return err
	}
	s.Events.emit(protocol.EventTamperSudoersDFile, protocol.TamperSudoersDFile{File: name, QuarantinedAs: dst})
	return nil
}

// reportUnresolved reports each unresolved user once until it resolves (retried every drift pass).
func (s *Sudo) reportUnresolved(users []string) {
	if s.unresolved == nil {
		s.unresolved = map[string]bool{}
	}
	now := map[string]bool{}
	for _, u := range users {
		now[u] = true
		if !s.unresolved[u] {
			s.Events.emit(protocol.EventSudoUserUnresolved, protocol.SudoUserUnresolved{Username: u})
		}
	}
	s.unresolved = now
}

// reportFailure reports sudo.apply_failed once per user and message.
func (s *Sudo) reportFailure(username string, err error) {
	if s.failed == nil {
		s.failed = map[string]string{}
	}
	if s.failed[username] == err.Error() {
		return
	}
	s.failed[username] = err.Error()
	s.Events.emit(protocol.EventSudoApplyFailed, protocol.SudoApplyFailed{Username: username, Message: err.Error()})
}

// fileHas reports whether path is a regular file with content and mode, owned by root:root.
func fileHas(sys System, path string, content []byte, mode fs.FileMode) bool {
	data, info, err := sys.ReadFile(path)
	if err != nil || data == nil || !bytes.Equal(data, content) || info.Mode().Perm() != mode {
		return false
	}
	uid, gid := sys.Owner(info)
	return uid == 0 && gid == 0
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

func randomHex() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
