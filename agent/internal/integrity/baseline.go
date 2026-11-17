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
	"github.com/phischl/paddock-mdm/agent/internal/update"
	"github.com/phischl/paddock-mdm/pkg/protocol"
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

// SupervisorPre is the SHA-256 of each supervisor file that was expected before the upgrade to Version started (plan
// M5a R10).
type SupervisorPre struct {
	Version string            `json:"version"`
	Files   map[string]string `json:"files"`
}

// Reset is a rebuilt baseline whose report is still due (plan M5a R14); Kind is "corrupt" or "missing".
type Reset struct {
	Kind string    `json:"kind"`
	At   time.Time `json:"at"`
}

// Baseline is integrity.json. A path in Expected is initialized; its value is the expected observed value.
// Reported holds the last reported observed value per path (plan M5a C8). Every save increments Generation (R6).
type Baseline struct {
	Generation    uint64            `json:"generation"`
	CheckedAt     time.Time         `json:"checked_at"`
	Expected      map[string]string `json:"expected"`
	Staged        *Staged           `json:"staged,omitempty"`
	LastStaged    *Staged           `json:"last_staged,omitempty"`
	Exceptions    []Exception       `json:"supervisor_exceptions,omitempty"`
	SupervisorPre *SupervisorPre    `json:"supervisor_pre,omitempty"`
	Reported      map[string]string `json:"reported"`
	Reset         *Reset            `json:"reset,omitempty"`
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

// Errors of update that are causes of plan M5a R3.
var (
	errBaselineRead  = errors.New("reading the integrity baseline failed")
	errBaselineWrite = errors.New("writing the integrity baseline failed")
)

// Size limits of the files the check reads (plan M5a R2).
const (
	maxBaseline = 1 << 20
	maxMD5Sums  = 4 << 20
)

// update runs fn on the baseline under the lock and saves it when fn returns true and changed it, or when load
// rebuilt it: the corrupt file is already moved aside, and its Reset must not be lost (plan M5a R14).
func (s store) update(fn func(b *Baseline) bool) error {
	release, err := s.lock()
	if err != nil {
		return err
	}
	defer release()
	b, rebuilt, err := s.load()
	if err != nil {
		return fmt.Errorf("%w: %w", errBaselineRead, err)
	}
	before, err := json.Marshal(b)
	if err != nil {
		return err
	}
	if !fn(b) && !rebuilt {
		return nil
	}
	data, err := json.Marshal(b)
	if err != nil || bytes.Equal(before, data) && !rebuilt {
		return err
	}
	b.Generation++
	if data, err = json.Marshal(b); err != nil {
		return err
	}
	if err := fsutil.WriteFile(s.l.Integrity(), append(data, '\n'), 0o600, 0o700); err != nil {
		return fmt.Errorf("%w: %w", errBaselineWrite, err)
	}
	return nil
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

// load reads the baseline; a missing file is an empty one. A corrupt one is moved aside and rebuilt with a Reset, so
// that the next pass reports it (plan M5a C9, R14); rebuilt is then true. Any other read error is returned: the
// baseline is never recorded anew from an unreadable file (R11 L2).
func (s store) load() (b *Baseline, rebuilt bool, err error) {
	b = &Baseline{}
	data, err := readRegular(s.l.Integrity(), maxBaseline)
	switch {
	case err == nil:
		if jerr := json.Unmarshal(data, b); jerr != nil {
			slog.Warn("the integrity baseline is corrupt; it is moved aside and recorded anew", "error", jerr)
			if rerr := os.Rename(s.l.Integrity(), s.l.Integrity()+".corrupt"); rerr != nil {
				slog.Warn("moving the corrupt integrity baseline aside failed", "error", rerr)
			}
			b = &Baseline{Reset: &Reset{Kind: "corrupt", At: time.Now().UTC()}}
			rebuilt = true
		}
	case !errors.Is(err, fs.ErrNotExist):
		return nil, false, err
	}
	if b.Expected == nil {
		b.Expected = map[string]string{}
	}
	if b.Reported == nil {
		b.Reported = map[string]string{}
	}
	return b, rebuilt, nil
}

// peekGeneration reads the generation of the baseline without the lock; 0 when it cannot be read or parsed, so that
// a corrupt file is rebuilt and reported, not dropped as raced (plan M5a R1, R15.7).
func peekGeneration(l paths.Layout) uint64 {
	data, err := readRegular(l.Integrity(), maxBaseline)
	var b Baseline
	if err != nil || json.Unmarshal(data, &b) != nil {
		return 0
	}
	return b.Generation
}

// SyncFiles sets the baseline of the given agent-written configuration files to their current state. Every Paddock
// writer of such a file calls it after the write (plan M5a C7). It hashes before it takes the lock (R1), applies every
// file it could hash, and returns an error naming the others, so that the caller defers them (R15.1).
func SyncFiles(l paths.Layout, files ...string) error {
	var h hasher
	values := map[string]string{}
	var failed []error
	for _, full := range files {
		f := devicePath(l, full)
		v, err := h.value(l, f)
		if err != nil {
			failed = append(failed, fmt.Errorf("hashing %s: %w", f, err))
			continue
		}
		values[f] = v
	}
	err := newStore(l, nil).update(func(b *Baseline) bool {
		for f, v := range values {
			b.expect(f, v)
		}
		return true
	})
	return errors.Join(append(failed, err)...)
}

// Fingerprint is the Lstat fingerprint of a file: device, inode, size, mtime, ctime and type (plan M5a R8).
type Fingerprint struct {
	dev, ino     uint64
	size         int64
	mtime, ctime int64
	mode         fs.FileMode
}

// FingerprintOf returns the Lstat fingerprint of a file; an absent file has the zero Fingerprint.
func FingerprintOf(full string) Fingerprint {
	info, err := os.Lstat(full)
	if err != nil {
		return Fingerprint{}
	}
	return fingerprintOf(info)
}

// SyncFileIfChanged is SyncFiles for one file, applied only when its fingerprint differs from before: a Paddock call
// that did not write must not launder an edit made before it (plan M5a R8). changed is false when it did nothing.
func SyncFileIfChanged(l paths.Layout, full string, before Fingerprint) (changed bool, err error) {
	if FingerprintOf(full) == before {
		return false, nil
	}
	return true, SyncFiles(l, full)
}

// RecordStaged records the release the agent stages, before update.Stage (plan M5a C4, R11 L3).
func RecordStaged(l paths.Layout, version, sum string) error {
	return newStore(l, nil).update(func(b *Baseline) bool {
		b.Staged = &Staged{Version: version, SHA256: strings.ToLower(sum)}
		b.LastStaged = nil
		return true
	})
}

// UpdateResultFile is the device path of the update result, the file param of an unstaged result (plan M5a R16).
const UpdateResultFile = "/var/lib/paddock/state/update-result.json"

// UpdateResult moves the baseline for the supervisor's update result of version with outcome, before its event is
// spooled (plan M5a C4, R11 L3, R16). The staged release moves to LastStaged, so that a later result of the same
// version (rolled_back after rollback_failed, or a replay after a crash) finds it. Only the slot holding the staged
// release is taken; current moves only on updated or rollback_failed, and only to that slot. A result without a
// matching staged release keeps the whole baseline and returns unstaged, so that the caller reports it.
func UpdateResult(l paths.Layout, version, outcome string) (unstaged bool, err error) {
	var h hasher
	obs, err := h.slots(l)
	if err != nil {
		return false, fmt.Errorf("reading the agent slots for the update result: %w", err)
	}
	err = newStore(l, nil).update(func(b *Baseline) bool {
		staged := b.Staged
		if staged == nil && b.LastStaged != nil && b.LastStaged.Version == version {
			staged = b.LastStaged
		}
		if b.Staged != nil {
			b.LastStaged = b.Staged
		}
		b.Staged = nil
		if staged == nil || staged.Version != version {
			unstaged = true
			return true
		}
		for _, slot := range []string{slotA, slotB} {
			if obs[slot] == staged.SHA256 {
				b.expect(slot, obs[slot])
			}
		}
		sp := slotPath(obs[current])
		switch {
		case sp == "":
		case outcome == update.OutcomeUpdated || outcome == update.OutcomeRollbackFailed:
			if obs[sp] == staged.SHA256 {
				b.expect(current, obs[current])
			}
		case outcome == update.OutcomeRolledBack:
			// Only the completed rollback after a rollback_failed of this release, which moved current to the staged
			// slot: back to the other slot, unchanged since (plan M5a R11 L3).
			if b.Expected[slotPath(b.Expected[current])] == staged.SHA256 && obs[sp] != staged.SHA256 &&
				obs[sp] == b.Expected[sp] {
				b.expect(current, obs[current])
			}
		}
		return true
	})
	return unstaged, err
}

// supervisorObserved is a supervisor file as observed now with its md5sums entry ("" when it has none).
type supervisorObserved struct {
	sha, md5, entry string
}

// observeSupervisor hashes the supervisor binary and unit with their md5sums entries, before the lock.
func observeSupervisor(l paths.Layout, arch string) (map[string]supervisorObserved, error) {
	sums, _, _, err := readMD5Sums(l, supervisorPackage, arch)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	var h hasher
	out := map[string]supervisorObserved{}
	for _, f := range supervisorFiles() {
		sha, sum, err := h.file(l, f)
		if err != nil {
			return nil, fmt.Errorf("hashing %s: %w", f, err)
		}
		out[f] = supervisorObserved{sha: sha, md5: sum, entry: sums[f]}
	}
	return out, nil
}

// RecordSupervisorPre records, for the supervisor binary and unit, the SHA-256 of each file that is expected now
// (its MD5 equals the md5sums entry, or a valid rollback exception covers it), bound to the version to install (plan
// M5a R10).
func RecordSupervisorPre(l paths.Layout, arch, version string) error {
	obs, err := observeSupervisor(l, arch)
	if err != nil {
		return err
	}
	return newStore(l, nil).update(func(b *Baseline) bool {
		pre := &SupervisorPre{Version: version, Files: map[string]string{}}
		for f, o := range obs {
			if o.entry != "" && (o.md5 == o.entry || excepted(b, f, o.entry, o.sha)) {
				pre.Files[f] = o.sha
			}
		}
		b.SupervisorPre = pre
		return true
	})
}

// SupervisorResult consumes SupervisorPre. For an outcome other than updated it records an exception for a
// supervisor file only when its observed SHA-256 equals SupervisorPre.Files[path] and SupervisorPre.Version equals
// version; the exception holds the current md5sums entry and that SHA-256. Any other file gets no exception and
// a Warn, and the next pass reports it (plan M5a R10).
func SupervisorResult(l paths.Layout, arch, version, outcome string) error {
	obs, err := observeSupervisor(l, arch)
	if err != nil {
		return err
	}
	return newStore(l, nil).update(func(b *Baseline) bool {
		pre := b.SupervisorPre
		b.SupervisorPre = nil
		if outcome == protocol.SupervisorOutcomeUpdated {
			return true
		}
		for f, o := range obs {
			switch {
			case o.entry == "" || o.md5 == o.entry:
			case pre != nil && pre.Version == version && o.sha != "" && pre.Files[f] == o.sha:
				b.Exceptions = append(dropException(b.Exceptions, f), Exception{Path: f, MD5: o.entry, SHA256: o.sha})
				delete(b.Reported, f)
			default:
				slog.Warn("a supervisor file after the upgrade result is not the one recorded before the upgrade", "file", f,
					"version", version, "outcome", outcome)
			}
		}
		return true
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
	// afterLstat is a test hook between the Lstat and the open; nil in production.
	afterLstat func(path string)
}

type cached struct {
	fp       Fingerprint
	sha, md5 string
}

// file returns the SHA-256 and MD5 of a regular file, "" for both when it is absent, and a marker of its type for
// anything else, so that a symlink swap with the same content still counts as a change. The content and the cache's
// fingerprint both come from the opened descriptor, never from the Lstat (plan M5a R2).
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
	if h.afterLstat != nil {
		h.afterLstat(path)
	}
	f, info, err := openRegular(full)
	switch {
	case errors.Is(err, syscall.ELOOP):
		target, err := os.Readlink(full)
		return "symlink:" + target, "", err
	case errors.Is(err, fs.ErrNotExist):
		return "", "", nil
	case err != nil:
		return "", "", err
	case f == nil:
		return "!type:" + info.Mode().Type().String(), "", nil
	}
	defer func() { _ = f.Close() }()
	fp := fingerprintOf(info)
	if c, ok := h.cache[path]; ok && c.fp == fp {
		return c.sha, c.md5, nil
	}
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

// openRegular opens path with O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC and Fstats the descriptor: a FIFO or device
// swapped in never blocks the read (plan M5a R2). It returns (nil, info, nil) when the descriptor is not a regular
// file, so the caller observes its type.
func openRegular(path string) (*os.File, fs.FileInfo, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0) //nolint:gosec // fixed device paths below the layout
	if err != nil {
		return nil, nil, err
	}
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		_ = f.Close()
		return nil, info, err
	}
	return f, info, nil
}

// readRegular reads a regular file of at most maxBytes through openRegular; a non-regular file or a larger one is an
// error.
func readRegular(path string, maxBytes int64) ([]byte, error) {
	f, info, err := openRegular(path)
	if err != nil {
		return nil, err
	}
	if f == nil {
		return nil, fmt.Errorf("%s: not a regular file (%s)", path, info.Mode().Type())
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err == nil && int64(len(data)) > maxBytes {
		err = fmt.Errorf("%s: larger than %d bytes", path, maxBytes)
	}
	return data, err
}

func fingerprintOf(info fs.FileInfo) Fingerprint {
	fp := Fingerprint{size: info.Size(), mtime: info.ModTime().UnixNano(), mode: info.Mode().Type()}
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
