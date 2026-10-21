// Package encrypttest is a fake encrypt.Host for the tests of the in-place encryption: recorded tool outputs from a
// fixture file plus a handler for the tools whose answer depends on what the code under test did.
package encrypttest

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/agent/internal/encrypt"
)

// Host answers tool runs from Handle first, then from the fixture's recorded commands; an unknown command fails the
// test. Files live below Root. Command lines are recorded with Root cut out, so that they read like on a device.
type Host struct {
	T    *testing.T
	Root string
	// Handle answers a command line (Root cut out); ok false falls through to the fixture.
	Handle func(line string) (stdout string, exit int, ok bool)
	// NotFound reports the tools that are not installed; nil: all are.
	NotFound func(name string) bool
	// PackagesBusy makes LockPackages fail as while apt or dpkg runs.
	PackagesBusy bool
	// Free is what FreeBytes reports for /boot; 0 is 1 GiB. FreeFunc, when set, answers instead.
	Free     int64
	FreeFunc func(dir string) int64
	// Stderr answers the stderr of a command line Handle answered with a non-zero exit; nil: none.
	Stderr func(line string) string

	mu       sync.Mutex
	commands map[string]recorded
	calls    []string
	long     []string
	locked   bool
}

type recorded struct {
	stdout string
	exit   int
}

// New returns a Host without recorded commands and an empty temporary root.
func New(t *testing.T) *Host {
	return &Host{T: t, Root: t.TempDir(), commands: map[string]recorded{}}
}

// Load reads a fixture (the format of agent/internal/encrypt/testdata: "@ <name>" includes another fixture of the same
// directory, "$ <command line>" starts a command whose stdout follows, "? <n>" sets its exit code, "> <path>" starts a
// file below the root, a path ending in / is a directory) into a new Host with a temporary root.
func Load(t *testing.T, fixture string) *Host {
	t.Helper()
	return LoadInto(t, fixture, t.TempDir())
}

// LoadInto is Load with the files below root (an agent's layout root).
func LoadInto(t *testing.T, fixture, root string) *Host {
	t.Helper()
	h := &Host{T: t, Root: root, commands: map[string]recorded{}}
	files := map[string]*strings.Builder{}
	h.load(fixture, files)
	for path, content := range files {
		full := filepath.Join(h.Root, path)
		if strings.HasSuffix(path, "/") {
			h.MkdirAll(path)
			continue
		}
		if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content.String()), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return h
}

func (h *Host) load(fixture string, files map[string]*strings.Builder) {
	raw, err := os.ReadFile(fixture) //nolint:gosec // test fixture
	if err != nil {
		h.T.Fatal(err)
	}
	var out *strings.Builder
	var cmd string
	var exit int
	flush := func() {
		if cmd != "" {
			h.commands[cmd] = recorded{stdout: out.String(), exit: exit}
		}
		cmd, exit = "", 0
	}
	sc := bufio.NewScanner(strings.NewReader(string(raw)))
	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.HasPrefix(line, "@ "):
			flush()
			h.load(filepath.Join(filepath.Dir(fixture), strings.TrimPrefix(line, "@ ")+".txt"), files)
		case strings.HasPrefix(line, "$ "):
			flush()
			cmd, out = strings.TrimPrefix(line, "$ "), &strings.Builder{}
		case strings.HasPrefix(line, "? ") && cmd != "":
			exit, _ = strconv.Atoi(strings.TrimPrefix(line, "? "))
		case strings.HasPrefix(line, "> "):
			flush()
			out = &strings.Builder{}
			files[strings.TrimPrefix(line, "> ")] = out
		default:
			if out != nil {
				out.WriteString(line + "\n")
			}
		}
	}
	flush()
}

// Set records the answer to a command line, replacing the fixture's.
func (h *Host) Set(line, stdout string, exit int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.commands[line] = recorded{stdout: stdout, exit: exit}
}

// Command implements encrypt.System.
func (h *Host) Command(ctx context.Context, name string, args ...string) (string, string, int, error) {
	return h.run(ctx, false, name, args)
}

// CommandWithin implements encrypt.Host; the line is recorded in Long as well.
func (h *Host) CommandWithin(ctx context.Context, _ time.Duration, _ []string, name string, args ...string) (string, string, int, error) {
	return h.run(ctx, true, name, args)
}

// run answers a command line. A tool NotFound names fails like a missing executable; a run whose ctx has ended fails
// like a tool encrypt.OS killed (its line is still recorded).
func (h *Host) run(ctx context.Context, long bool, name string, args []string) (string, string, int, error) {
	line := strings.ReplaceAll(strings.Join(append([]string{name}, args...), " "), h.Root, "")
	h.mu.Lock()
	h.calls = append(h.calls, line)
	if long {
		h.long = append(h.long, line)
	}
	handle := h.Handle
	r, known := h.commands[line]
	notFound := h.NotFound
	h.mu.Unlock()
	if notFound != nil && notFound(name) {
		return "", "", -1, &exec.Error{Name: name, Err: exec.ErrNotFound}
	}
	if err := ctx.Err(); err != nil {
		return "", "", -1, fmt.Errorf("%s: %w", name, err)
	}
	if handle != nil {
		if out, exit, ok := handle(line); ok {
			stderr := ""
			if exit != 0 && h.Stderr != nil {
				stderr = h.Stderr(line)
			}
			return out, stderr, exit, nil
		}
	}
	if !known {
		h.T.Errorf("unrecorded command %s", line)
		return "", "", -1, errors.New("unrecorded command")
	}
	return r.stdout, "", r.exit, nil
}

// LockPackages implements encrypt.Host: busy with PackagesBusy, else held until unlock.
func (h *Host) LockPackages() (func(), error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.PackagesBusy || h.locked {
		return nil, encrypt.ErrPackagesBusy
	}
	h.locked = true
	return func() {
		h.mu.Lock()
		defer h.mu.Unlock()
		h.locked = false
	}, nil
}

// FreeBytes implements encrypt.Host.
func (h *Host) FreeBytes(dir string) (int64, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.FreeFunc != nil {
		return h.FreeFunc(dir), nil
	}
	if h.Free == 0 {
		return 1 << 30, nil
	}
	return h.Free, nil
}

// PackagesLocked reports whether the code under test holds the dpkg locks now.
func (h *Host) PackagesLocked() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.locked
}

// ReadFile implements encrypt.System.
func (h *Host) ReadFile(path string) ([]byte, error) { return os.ReadFile(path) } //nolint:gosec // test root

// Stat implements encrypt.System.
func (h *Host) Stat(path string) (bool, error) {
	_, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return err == nil, err
}

// Calls returns the command lines run so far.
func (h *Host) Calls() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.calls...)
}

// Long returns the command lines run through CommandWithin.
func (h *Host) Long() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.long...)
}

// Count returns how often a command line ran.
func (h *Host) Count(line string) int {
	n := 0
	for _, c := range h.Calls() {
		if c == line {
			n++
		}
	}
	return n
}

// Path is path below the root.
func (h *Host) Path(path string) string { return filepath.Join(h.Root, path) }

// Exists reports whether path below the root exists.
func (h *Host) Exists(path string) bool {
	_, err := os.Stat(h.Path(path))
	return err == nil
}

// Write writes a file below the root.
func (h *Host) Write(path, content string) {
	h.T.Helper()
	if err := os.MkdirAll(filepath.Dir(h.Path(path)), 0o750); err != nil {
		h.T.Fatal(err)
	}
	if err := os.WriteFile(h.Path(path), []byte(content), 0o600); err != nil {
		h.T.Fatal(err)
	}
}

// MkdirAll creates a directory below the root.
func (h *Host) MkdirAll(path string) {
	h.T.Helper()
	if err := os.MkdirAll(h.Path(path), 0o750); err != nil {
		h.T.Fatal(err)
	}
}
