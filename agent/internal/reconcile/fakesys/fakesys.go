// Package fakesys is an in-memory reconcile.System for tests: files, users, systemd units, timedated, installed
// packages, apt-get and logind sessions, with a log of every state-changing call.
package fakesys

import (
	"context"
	"fmt"
	"io/fs"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"
)

// File is a fake file.
type File struct {
	Data     []byte
	Mode     fs.FileMode
	UID, GID int
	Symlink  bool
}

// Unit is a fake systemd unit; State is the `systemctl is-enabled` answer.
type Unit struct {
	State  string // enabled, disabled, static, masked
	Active bool
}

// System is the fake. Fields may be changed between calls (not concurrently).
type System struct {
	mu       sync.Mutex
	Files    map[string]*File
	Units    map[string]*Unit
	Packages map[string]bool
	NTP      bool
	Users    map[string]int
	Groups   map[string]int
	FailCmd  string   // a command ("systemctl start x.service") that fails
	Calls    []string // state-changing calls
	// Versions are the versions of installed packages (PackageVersion); AptVersion is the version apt-get install
	// installs.
	Versions   map[string]string
	AptVersion string
	// Sessions are the logind sessions loginctl lists.
	Sessions []Session
	// Passwd are the users getent passwd resolves (name → UID); Members the members of groups getent group lists.
	Passwd  map[string]int
	Members map[string][]string
	// VisudoReject makes visudo fail for a file (or, with -c alone, a configuration) that contains it. A visudo
	// below /usr/lib/cargo (sudo-rs) also refuses lecture_file, like sudo-rs 0.2.
	VisudoReject string
	// Links resolve paths for EvalSymlinks (unlisted paths resolve to themselves); SudoVersions are the --version
	// outputs of sudo binaries (default: classic sudo).
	Links        map[string]string
	SudoVersions map[string]string
}

// Session is a fake logind session.
type Session struct {
	ID    string
	UID   int
	User  string
	Class string
}

// New returns a fake with root/root, nobody and an empty file system.
func New() *System {
	return &System{
		Files: map[string]*File{}, Units: map[string]*Unit{}, Packages: map[string]bool{}, Versions: map[string]string{},
		Passwd: map[string]int{}, Members: map[string][]string{},
		Users: map[string]int{"root": 0, "nobody": 65534}, Groups: map[string]int{"root": 0, "adm": 4},
	}
}

type info struct {
	name string
	f    *File
}

func (i info) Name() string { return i.name }
func (i info) Size() int64  { return int64(len(i.f.Data)) }
func (i info) Mode() fs.FileMode {
	if i.f.Symlink {
		return fs.ModeSymlink | 0o777
	}
	return i.f.Mode
}
func (i info) ModTime() time.Time { return time.Time{} }
func (i info) IsDir() bool        { return false }
func (i info) Sys() any           { return i.f }

// ReadFile implements reconcile.System.
func (s *System) ReadFile(path string) ([]byte, fs.FileInfo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, ok := s.Files[path]
	if !ok {
		return nil, nil, fs.ErrNotExist
	}
	if f.Symlink {
		return nil, info{path, f}, nil
	}
	return append([]byte{}, f.Data...), info{path, f}, nil
}

// WriteFileAtomic implements reconcile.System.
func (s *System) WriteFileAtomic(path string, data []byte, mode fs.FileMode, uid, gid int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Calls = append(s.Calls, "write "+path)
	s.Files[path] = &File{Data: append([]byte{}, data...), Mode: mode, UID: uid, GID: gid}
	return nil
}

// Remove implements reconcile.System.
func (s *System) Remove(path string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.Files[path]; !ok {
		return fs.ErrNotExist
	}
	s.Calls = append(s.Calls, "remove "+path)
	delete(s.Files, path)
	return nil
}

// LookupUser implements reconcile.System.
func (s *System) LookupUser(name string) (int, error) {
	if id, ok := s.Users[name]; ok {
		return id, nil
	}
	return 0, fmt.Errorf("unknown user %s", name)
}

// LookupGroup implements reconcile.System.
func (s *System) LookupGroup(name string) (int, error) {
	if id, ok := s.Groups[name]; ok {
		return id, nil
	}
	return 0, fmt.Errorf("unknown group %s", name)
}

// Owner implements reconcile.System.
func (s *System) Owner(fi fs.FileInfo) (int, int) {
	f := fi.Sys().(*File)
	return f.UID, f.GID
}

// Systemctl implements reconcile.System for is-enabled, is-active, enable, disable, start and stop.
func (s *System) Systemctl(_ context.Context, args ...string) (string, int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(args) != 2 {
		return "", 1, fmt.Errorf("fake systemctl: unsupported %v", args)
	}
	verb, name := args[0], args[1]
	u, ok := s.Units[name]
	switch verb {
	case "is-enabled":
		if !ok {
			return "Failed to get unit file state for " + name + ": No such file or directory\n", 1, nil
		}
		if u.State == "disabled" || u.State == "masked" {
			return u.State + "\n", 1, nil
		}
		return u.State + "\n", 0, nil
	case "is-active":
		if ok && u.Active {
			return "active\n", 0, nil
		}
		return "inactive\n", 3, nil
	}
	cmd := "systemctl " + strings.Join(args, " ")
	s.Calls = append(s.Calls, cmd)
	if !ok || cmd == s.FailCmd {
		return "Failed to " + verb + " " + name + "\n", 1, nil
	}
	switch verb {
	case "enable":
		u.State = "enabled"
	case "disable":
		u.State = "disabled"
	case "start", "restart":
		u.Active = true
	case "stop":
		u.Active = false
	case "reset-failed":
	default:
		return "", 1, fmt.Errorf("fake systemctl: unsupported %v", args)
	}
	return "", 0, nil
}

// Timedatectl implements reconcile.System for show NTP and set-ntp.
func (s *System) Timedatectl(_ context.Context, args ...string) (string, int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if args[0] == "show" {
		if s.NTP {
			return "yes\n", 0, nil
		}
		return "no\n", 0, nil
	}
	s.Calls = append(s.Calls, "timedatectl "+strings.Join(args, " "))
	s.NTP = args[len(args)-1] == "true"
	return "", 0, nil
}

// PackageInstalled implements reconcile.System.
func (s *System) PackageInstalled(name string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.Packages[name]
}

// PackageVersion implements reconcile.System.
func (s *System) PackageVersion(name string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.Packages[name] {
		return ""
	}
	return s.Versions[name]
}

// AptGet implements reconcile.System: "install" installs its package arguments with AptVersion; a call equal to
// FailCmd fails with exit 100.
func (s *System) AptGet(_ context.Context, args ...string) (string, int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var words []string // arguments without options and their -o values
	for i := 0; i < len(args); i++ {
		switch {
		case args[i] == "-o":
			i++
		case !strings.HasPrefix(args[i], "-"):
			words = append(words, args[i])
		}
	}
	cmd := "apt-get " + strings.Join(words, " ")
	s.Calls = append(s.Calls, cmd)
	if strings.HasPrefix(s.FailCmd, "apt-get") && strings.HasPrefix(cmd, s.FailCmd) {
		return "E: Could not get lock /var/lib/dpkg/lock-frontend\n", 100, nil
	}
	if len(words) > 0 && words[0] == "install" {
		for _, p := range words[1:] {
			s.Packages[p] = true
			s.Versions[p] = s.AptVersion
		}
	}
	return "", 0, nil
}

// Loginctl implements reconcile.System for list-sessions --no-legend and show-session of Sessions, lock-session and
// terminate-user.
func (s *System) Loginctl(_ context.Context, args ...string) (string, int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch args[0] {
	case "list-sessions":
		var b strings.Builder
		for _, ss := range s.Sessions {
			fmt.Fprintf(&b, "%6s %5d %s -\n", ss.ID, ss.UID, ss.User)
		}
		return b.String(), 0, nil
	case "show-session":
		var blocks []string
		for _, id := range args[1:] {
			for _, ss := range s.Sessions {
				if ss.ID == id {
					blocks = append(blocks, fmt.Sprintf("Id=%s\nUser=%d\nName=%s\nClass=%s\n", ss.ID, ss.UID, ss.User, ss.Class))
				}
			}
		}
		return strings.Join(blocks, "\n"), 0, nil
	}
	cmd := "loginctl " + strings.Join(args, " ")
	s.Calls = append(s.Calls, cmd)
	if cmd == s.FailCmd {
		return "Failed\n", 1, nil
	}
	return "", 0, nil
}

// Getent implements reconcile.System for passwd (Passwd) and group (Members).
func (s *System) Getent(_ context.Context, database, key string) (string, int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch database {
	case "passwd":
		if uid, ok := s.Passwd[key]; ok {
			return fmt.Sprintf("%s:x:%d:%d::/home/%s:/bin/bash\n", key, uid, uid, key), 0, nil
		}
	case "group":
		if members, ok := s.Members[key]; ok {
			return fmt.Sprintf("%s:x:27:%s\n", key, strings.Join(members, ",")), 0, nil
		}
	}
	return "", 2, nil
}

// Visudo implements reconcile.System: `-c -f <file>` checks one file, `-c` every regular file in /etc/sudoers.d that
// sudo reads (no "." in the name); both fail on VisudoReject and, for sudo-rs's visudo, on lecture_file. The call is
// logged as "visudo <args>" for classic sudo and "visudo-rs <args>" for sudo-rs.
func (s *System) Visudo(_ context.Context, path string, args ...string) (string, int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rs := strings.HasPrefix(path, "/usr/lib/cargo/")
	name := "visudo"
	if rs {
		name = "visudo-rs"
	}
	s.Calls = append(s.Calls, name+" "+strings.Join(args, " "))
	var check []string
	if len(args) == 3 && args[0] == "-c" && args[1] == "-f" {
		check = []string{args[2]}
	} else {
		for path := range s.Files {
			if dir, name := filepath.Split(path); dir == "/etc/sudoers.d/" && !strings.Contains(name, ".") {
				check = append(check, path)
			}
		}
		check = append(check, "/etc/sudoers")
	}
	for _, file := range check {
		f, ok := s.Files[file]
		if !ok {
			continue
		}
		if (s.VisudoReject != "" && strings.Contains(string(f.Data), s.VisudoReject)) || (rs && strings.Contains(string(f.Data), "lecture_file")) {
			return file + ":2:16: syntax error\n", 1, nil
		}
	}
	return "", 0, nil
}

// SudoVersion implements reconcile.System.
func (s *System) SudoVersion(_ context.Context, path string) (string, int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if out, ok := s.SudoVersions[path]; ok {
		return out, 0, nil
	}
	return "Sudo version 1.9.15p5\nSudoers policy plugin version 1.9.15p5\n", 0, nil
}

// EvalSymlinks implements reconcile.System.
func (s *System) EvalSymlinks(path string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if target, ok := s.Links[path]; ok {
		return target, nil
	}
	return path, nil
}

// Gpasswd implements reconcile.System for -d <user> <group> (Members); FailCmd makes it fail.
func (s *System) Gpasswd(_ context.Context, args ...string) (string, int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cmd := "gpasswd " + strings.Join(args, " ")
	s.Calls = append(s.Calls, cmd)
	if cmd == s.FailCmd || len(args) != 3 || args[0] != "-d" {
		return "gpasswd: user is not a member\n", 3, nil
	}
	s.Members[args[2]] = slices.DeleteFunc(s.Members[args[2]], func(m string) bool { return m == args[1] })
	return "", 0, nil
}

// Rename implements reconcile.System.
func (s *System) Rename(oldPath, newPath string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, ok := s.Files[oldPath]
	if !ok {
		return fs.ErrNotExist
	}
	s.Calls = append(s.Calls, "rename "+oldPath+" "+newPath)
	delete(s.Files, oldPath)
	s.Files[newPath] = f
	return nil
}

// ReadDir implements reconcile.System.
func (s *System) ReadDir(path string) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var names []string
	for p := range s.Files {
		if dir, name := filepath.Split(p); filepath.Clean(dir) == filepath.Clean(path) {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names, nil
}

// TakeCalls returns and clears the call log.
func (s *System) TakeCalls() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.Calls
	s.Calls = nil
	return c
}
