package fakesys

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"
)

// FlatpakInstallation is a fake Flatpak installation: its remotes by name, its applications (ID → version) and its
// masked patterns.
type FlatpakInstallation struct {
	Remotes map[string]*FlatpakRemote
	Apps    map[string]string
	Masks   map[string]bool
}

// FlatpakRemote is a fake remote with the key its last --gpg-import read.
type FlatpakRemote struct {
	URL         string
	Key         []byte
	Disabled    bool
	NoGPGVerify bool
}

// NewFlatpakInstallation returns an empty installation.
func NewFlatpakInstallation() *FlatpakInstallation {
	return &FlatpakInstallation{Remotes: map[string]*FlatpakRemote{}, Apps: map[string]string{}, Masks: map[string]bool{}}
}

// errNoFlatpak is the error exec returns for a missing binary.
var errNoFlatpak = errors.New(`exec: "flatpak": executable file not found in $PATH`)

// Flatpak implements reconcile.System on FlatpakSystem.
func (s *System) Flatpak(_ context.Context, args ...string) (string, int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	line := strings.Join(append([]string{"flatpak"}, args...), " ")
	s.FlatpakCalls = append(s.FlatpakCalls, line)
	if r, ok := s.FlatpakScript[line]; ok {
		return string(r.Data), r.Exit, r.Err
	}
	if !s.Packages["flatpak"] {
		return "", -1, errNoFlatpak
	}
	if s.FlatpakSystem == nil {
		s.FlatpakSystem = NewFlatpakInstallation()
	}
	return s.flatpak(s.FlatpakSystem, "system", nil, args)
}

// SystemdRun implements reconcile.System for `systemd-run --machine=<uid>@.host --user … flatpak …` on the user's
// installation in FlatpakUsers; a UID without one has no service manager to reach.
func (s *System) SystemdRun(_ context.Context, stdin []byte, args ...string) (string, int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	line := strings.Join(append([]string{"systemd-run"}, args...), " ")
	s.FlatpakCalls = append(s.FlatpakCalls, line)
	s.FlatpakStdin = append(s.FlatpakStdin, stdin)
	if r, ok := s.FlatpakScript[line]; ok {
		return string(r.Data), r.Exit, r.Err
	}
	uid := -1
	for _, a := range args {
		if m, ok := strings.CutPrefix(a, "--machine="); ok {
			if n, err := strconv.Atoi(strings.TrimSuffix(m, "@.host")); err == nil {
				uid = n
			}
		}
	}
	i := slices.Index(args, "flatpak")
	inst := s.FlatpakUsers[uid]
	switch {
	case i < 0 || !slices.Contains(args[:i], "--user"):
		return "unsupported systemd-run " + line, 1, nil
	case inst == nil:
		return "Failed to connect to user scope bus via local transport: No such file or directory\n", 1, nil
	case !s.Packages["flatpak"]:
		return "systemd-run: flatpak: No such file or directory\n", 1, nil
	}
	return s.flatpak(inst, "user", stdin, args[i+1:])
}

// flatpak runs one flatpak command on inst; scope is "system" or "user", the option the command must name.
func (s *System) flatpak(inst *FlatpakInstallation, scope string, stdin []byte, args []string) (string, int, error) {
	if len(args) == 0 {
		return "usage", 1, nil
	}
	var flags, pos []string
	for _, a := range args[1:] {
		if strings.HasPrefix(a, "-") {
			flags = append(flags, a)
		} else {
			pos = append(pos, a)
		}
	}
	if !slices.Contains(flags, "--"+scope) {
		return "error: the fake needs --" + scope, 1, nil
	}
	flag := func(name string) (string, bool) {
		for _, f := range flags {
			if f == name {
				return "", true
			}
			if v, ok := strings.CutPrefix(f, name+"="); ok {
				return v, true
			}
		}
		return "", false
	}
	switch args[0] {
	case "remotes":
		_, all := flag("--show-disabled")
		var b strings.Builder
		for _, name := range slices.Sorted(maps.Keys(inst.Remotes)) {
			r := inst.Remotes[name]
			if r.Disabled && !all {
				continue
			}
			opts := scope
			if r.Disabled {
				opts += ",disabled"
			}
			if r.NoGPGVerify {
				opts += ",no-gpg-verify"
			}
			fmt.Fprintf(&b, "%s\t%s\t%s\n", name, r.URL, opts)
		}
		return b.String(), 0, nil
	case "remote-add":
		if len(pos) != 2 {
			return "error: remote-add NAME URL", 1, nil
		}
		if _, ok := inst.Remotes[pos[0]]; ok {
			if _, ifNot := flag("--if-not-exists"); ifNot {
				return "", 0, nil
			}
			return "error: Remote " + pos[0] + " already exists", 1, nil
		}
		r := &FlatpakRemote{URL: pos[1]}
		if path, ok := flag("--gpg-import"); ok {
			if path == "-" {
				r.Key = stdin
			} else if f := s.Files[path]; f != nil {
				r.Key = f.Data
			} else {
				return "error: " + path + ": No such file or directory", 1, nil
			}
		}
		inst.Remotes[pos[0]] = r
		s.Calls = append(s.Calls, "flatpak remote-add "+scope+" "+pos[0])
		return "", 0, nil
	case "remote-delete":
		if len(pos) != 1 || inst.Remotes[pos[0]] == nil {
			return "error: Remote not found", 1, nil
		}
		delete(inst.Remotes, pos[0])
		s.Calls = append(s.Calls, "flatpak remote-delete "+scope+" "+pos[0])
		return "", 0, nil
	case "list":
		var b strings.Builder
		for _, app := range slices.Sorted(maps.Keys(inst.Apps)) {
			fmt.Fprintf(&b, "%s\t%s\n", app, inst.Apps[app])
		}
		return b.String(), 0, nil
	case "install":
		if len(pos) != 2 {
			return "error: install REMOTE REF", 1, nil
		}
		if inst.Remotes[pos[0]] == nil {
			return "error: No remote refs found for ‘" + pos[0] + "’", 1, nil
		}
		if inst.Masks[pos[1]] {
			return "error: " + pos[1] + " is masked", 1, nil
		}
		if _, ok := inst.Apps[pos[1]]; !ok {
			inst.Apps[pos[1]] = "1.0"
			s.Calls = append(s.Calls, "flatpak install "+scope+" "+pos[1])
		}
		return "", 0, nil
	case "uninstall":
		if len(pos) != 1 {
			return "error: uninstall REF", 1, nil
		}
		if _, ok := inst.Apps[pos[0]]; !ok {
			return "error: " + pos[0] + " not installed", 1, nil
		}
		delete(inst.Apps, pos[0])
		s.Calls = append(s.Calls, "flatpak uninstall "+scope+" "+pos[0])
		return "", 0, nil
	case "mask":
		_, remove := flag("--remove")
		if len(pos) == 0 {
			var b strings.Builder
			for _, m := range slices.Sorted(maps.Keys(inst.Masks)) {
				b.WriteString("  " + m + "\n")
			}
			return b.String(), 0, nil
		}
		for _, p := range pos {
			if remove {
				if !inst.Masks[p] {
					return "error: No current mask matching " + p, 1, nil
				}
				delete(inst.Masks, p)
				s.Calls = append(s.Calls, "flatpak mask --remove "+scope+" "+p)
				continue
			}
			inst.Masks[p] = true
			s.Calls = append(s.Calls, "flatpak mask "+scope+" "+p)
		}
		return "", 0, nil
	}
	return "error: unknown command " + args[0], 1, nil
}
