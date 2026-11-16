package integrity

import (
	"bytes"
	"crypto/md5" //nolint:gosec // dpkg's md5sums are a change detector here, not a signature (ADR 0056)
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/phischl/paddock-mdm/agent/internal/fsutil"
	"github.com/phischl/paddock-mdm/agent/internal/paths"
)

// LockWait bounds the wait for integrity.lock; on a timeout the caller skips its work (plan M5a C3).
const LockWait = 10 * time.Second

const lockPoll = 100 * time.Millisecond

// ErrLockTimeout means integrity.lock stayed held for LockWait.
var ErrLockTimeout = errors.New("the integrity lock is held by another process")

// Observed values that are not a content hash (plan M5a C4).
const (
	notSymlink = "!symlink"
	linkAbsent = "!absent"
)

// Staged is the release the agent staged itself, recorded before update.Stage (plan M5a C4).
type Staged struct {
	Version string `json:"version"`
	SHA256  string `json:"sha256"`
}

// Exception is a supervisor file the upgrade helper copied back after a rollback: it is expected while the md5sums
// entry is still MD5 and the file's SHA-256 is still SHA256 (plan M5a C5).
type Exception struct {
	Path   string `json:"path"`
	MD5    string `json:"md5"`
	SHA256 string `json:"sha256"`
}

// Baseline is integrity.json. A path in Expected is initialized; its value is the expected observed value.
// Reported holds the last reported observed value per path (plan M5a C8).
type Baseline struct {
	Expected   map[string]string `json:"expected"`
	Staged     *Staged           `json:"staged,omitempty"`
	Exceptions []Exception       `json:"supervisor_exceptions,omitempty"`
	Reported   map[string]string `json:"reported"`
}

// expect moves the baseline of path; its reported mark goes with it (plan M5a C8).
func (b *Baseline) expect(path, value string) {
	if old, ok := b.Expected[path]; ok && old == value {
		return
	}
	b.Expected[path] = value
	delete(b.Reported, path)
}

// store is the baseline file below a layout with its lock.
type store struct {
	l     paths.Layout
	sleep func(time.Duration)
}

func newStore(l paths.Layout, sleep func(time.Duration)) store {
	if sleep == nil {
		sleep = time.Sleep
	}
	return store{l: l, sleep: sleep}
}

// update runs fn on the baseline under the lock and writes it when fn changed it.
func (s store) update(fn func(b *Baseline)) error {
	release, err := s.lock()
	if err != nil {
		return err
	}
	defer release()
	b := s.load()
	before, err := json.Marshal(b)
	if err != nil {
		return err
	}
	fn(b)
	data, err := json.Marshal(b)
	if err != nil || bytes.Equal(before, data) {
		return err
	}
	return fsutil.WriteFile(s.l.Integrity(), append(data, '\n'), 0o600, 0o700)
}

// lock takes the exclusive flock on integrity.lock, polling for at most LockWait: a blocking flock could hold the
// agent's loop behind `paddockd enroll` (plan M5a C3).
func (s store) lock() (func(), error) {
	path := s.l.IntegrityLock()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("integrity lock: %w", err)
	}
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600) //nolint:gosec // fixed path below the state directory
	if err != nil {
		return nil, fmt.Errorf("integrity lock: %w", err)
	}
	for range LockWait / lockPoll {
		err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) //nolint:gosec // a file descriptor fits an int
		if err == nil {
			return func() { _ = f.Close() }, nil
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) {
			_ = f.Close()
			return nil, fmt.Errorf("integrity lock: %w", err)
		}
		s.sleep(lockPoll)
	}
	_ = f.Close()
	return nil, ErrLockTimeout
}

// load reads the baseline; a missing file is an empty one, and a corrupt one is moved aside and re-initialized by
// trust on first use with one Warn and no event (plan M5a C9).
func (s store) load() *Baseline {
	b := &Baseline{}
	data, err := os.ReadFile(s.l.Integrity())
	switch {
	case err == nil:
		if jerr := json.Unmarshal(data, b); jerr != nil {
			slog.Warn("the integrity baseline is corrupt; it is moved aside and recorded anew", "error", jerr)
			if rerr := os.Rename(s.l.Integrity(), s.l.Integrity()+".corrupt"); rerr != nil {
				slog.Warn("moving the corrupt integrity baseline aside failed", "error", rerr)
			}
			b = &Baseline{}
		}
	case !errors.Is(err, fs.ErrNotExist):
		slog.Warn("reading the integrity baseline failed; it is recorded anew", "error", err)
	}
	if b.Expected == nil {
		b.Expected = map[string]string{}
	}
	if b.Reported == nil {
		b.Reported = map[string]string{}
	}
	return b
}

// SyncFiles sets the baseline of the given agent-written configuration files to their current state. Every Paddock
// writer of such a file calls it after the write (plan M5a C7).
func SyncFiles(l paths.Layout, files ...string) error {
	var h hasher
	return newStore(l, nil).update(func(b *Baseline) {
		for _, full := range files {
			f := devicePath(l, full)
			v, err := h.value(l, f)
			if err != nil {
				slog.Warn("recording an agent-written file in the integrity baseline failed", "file", f, "error", err)
				continue
			}
			b.expect(f, v)
		}
	})
}

// RecordStaged records the release the agent stages, before update.Stage (plan M5a C4).
func RecordStaged(l paths.Layout, version, sum string) error {
	return newStore(l, nil).update(func(b *Baseline) {
		b.Staged = &Staged{Version: version, SHA256: strings.ToLower(sum)}
	})
}

// UpdateResult moves the baseline of the slots and current for the supervisor's update result of version, before
// its event is spooled; one rule covers every outcome (plan M5a C4). A result without a matching staged release
// re-initializes the slots and current from what is observed, with one Warn and no event.
func UpdateResult(l paths.Layout, version string) error {
	var h hasher
	return newStore(l, nil).update(func(b *Baseline) {
		obs, err := h.slots(l)
		if err != nil {
			slog.Warn("reading the agent slots for the update result failed; the next pass compares the old baseline", "error", err)
			return
		}
		staged := b.Staged
		b.Staged = nil
		if staged == nil || staged.Version != version {
			slog.Warn("update result without a release this agent staged; the agent slots are recorded anew", "version", version)
			for p, v := range obs {
				b.expect(p, v)
			}
			return
		}
		for _, slot := range []string{slotA, slotB} {
			if v := obs[slot]; v == staged.SHA256 || v == b.Expected[slot] {
				b.expect(slot, v)
			}
		}
		if v := obs[current]; v == b.Expected[current] || b.Expected[slotPath(v)] == staged.SHA256 {
			b.expect(current, v)
		}
	})
}

// SupervisorRolledBack records the exception for the supervisor binary and unit the upgrade helper copied back: they
// are expected with their SHA-256 of now while dpkg's md5sums entry stays the one of now (plan M5a C5).
func SupervisorRolledBack(l paths.Layout, arch string) error {
	sums, _, err := readMD5Sums(l, supervisorPackage, arch)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var h hasher
	return newStore(l, nil).update(func(b *Baseline) {
		for _, f := range supervisorFiles() {
			sum, ok := sums[f]
			if !ok {
				continue
			}
			sha, _, err := h.file(l, f)
			if err != nil {
				slog.Warn("recording the restored supervisor file failed", "file", f, "error", err)
				continue
			}
			b.Exceptions = append(dropException(b.Exceptions, f), Exception{Path: f, MD5: sum, SHA256: sha})
			delete(b.Reported, f)
		}
	})
}

func dropException(ex []Exception, path string) []Exception {
	out := ex[:0:0]
	for _, e := range ex {
		if e.Path != path {
			out = append(out, e)
		}
	}
	return out
}

// hasher hashes files, cached by their fingerprint when cache is set (plan M5a C5): a file is rehashed only when
// dev, inode, size, mtime or ctime changed.
type hasher struct {
	cache map[string]cached
}

type fingerprint struct {
	dev, ino     uint64
	size         int64
	mtime, ctime int64
}

type cached struct {
	fp       fingerprint
	sha, md5 string
}

// file returns the SHA-256 and MD5 of a regular file, "" for both when it is absent, and a marker of its type for
// anything else, so that a symlink swap with the same content still counts as a change.
func (h *hasher) file(l paths.Layout, path string) (sha, sum string, err error) {
	full := l.Join(path)
	info, err := os.Lstat(full)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return "", "", nil
	case err != nil:
		return "", "", err
	case info.Mode()&fs.ModeSymlink != 0:
		target, err := os.Readlink(full)
		return "symlink:" + target, "", err
	case !info.Mode().IsRegular():
		return "!type:" + info.Mode().Type().String(), "", nil
	}
	fp := fingerprintOf(info)
	if c, ok := h.cache[path]; ok && c.fp == fp {
		return c.sha, c.md5, nil
	}
	f, err := os.Open(full) //nolint:gosec // a fixed device path below the layout
	if err != nil {
		return "", "", err
	}
	defer func() { _ = f.Close() }()
	s, m := sha256.New(), md5.New() //nolint:gosec // see the import
	if _, err := io.Copy(io.MultiWriter(s, m), f); err != nil {
		return "", "", err
	}
	sha, sum = hex.EncodeToString(s.Sum(nil)), hex.EncodeToString(m.Sum(nil))
	if h.cache != nil {
		h.cache[path] = cached{fp: fp, sha: sha, md5: sum}
	}
	return sha, sum, nil
}

func fingerprintOf(info fs.FileInfo) fingerprint {
	fp := fingerprint{size: info.Size(), mtime: info.ModTime().UnixNano()}
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		fp.dev, fp.ino = uint64(st.Dev), st.Ino //nolint:unconvert // Dev is uint32 on some architectures
		fp.ctime = st.Ctim.Sec*int64(time.Second) + st.Ctim.Nsec
	}
	return fp
}

// value is the observed value of a slot binary or an agent-written file: its SHA-256, "" when absent.
func (h *hasher) value(l paths.Layout, path string) (string, error) {
	sha, _, err := h.file(l, path)
	return sha, err
}

// The agent slots (plan M5a C2).
const (
	slotA   = "/opt/paddock/agent/A/paddockd"
	slotB   = "/opt/paddock/agent/B/paddockd"
	current = "/opt/paddock/agent/current"
)

// slotPath is the binary of the slot current points to, "" for any other target.
func slotPath(target string) string {
	switch target {
	case "A":
		return slotA
	case "B":
		return slotB
	}
	return ""
}

// slots observes both slot binaries and current.
func (h *hasher) slots(l paths.Layout) (map[string]string, error) {
	obs := map[string]string{}
	for _, p := range []string{slotA, slotB} {
		v, err := h.value(l, p)
		if err != nil {
			return nil, err
		}
		obs[p] = v
	}
	v, err := linkValue(l, current)
	if err != nil {
		return nil, err
	}
	obs[current] = v
	return obs, nil
}

// linkValue is the observed value of a checked symlink: its target, "!absent" or "!symlink" (plan M5a C4).
func linkValue(l paths.Layout, path string) (string, error) {
	info, err := os.Lstat(l.Join(path))
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return linkAbsent, nil
	case err != nil:
		return "", err
	case info.Mode()&fs.ModeSymlink == 0:
		return notSymlink, nil
	}
	return os.Readlink(l.Join(path))
}

// devicePath is the device path of a path below the layout's root, as the event's file param names it.
func devicePath(l paths.Layout, full string) string {
	rel, err := filepath.Rel(l.Join("/"), full)
	if err != nil {
		return full
	}
	return "/" + rel
}
