// Package fakesys is an in-memory reconcile.System for tests: files, users, systemd units, timedated and
// installed packages, with a log of every state-changing call.
package fakesys

import (
	"context"
	"fmt"
	"io/fs"
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
}

// New returns a fake with root/root, nobody and an empty file system.
func New() *System {
	return &System{
		Files: map[string]*File{}, Units: map[string]*Unit{}, Packages: map[string]bool{},
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
	case "start":
		u.Active = true
	case "stop":
		u.Active = false
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
func (s *System) PackageInstalled(name string) bool { return s.Packages[name] }

// TakeCalls returns and clears the call log.
func (s *System) TakeCalls() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.Calls
	s.Calls = nil
	return c
}
