package backuprole

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/phischl/paddock-mdm/server/internal/domain/backupset"
)

// fileInfo is one file of the local repository.
type fileInfo struct {
	size int64
	mod  time.Time
}

// repoIndex lists the local repository (the backup set) by path relative to its root.
type repoIndex map[string]fileInfo

// pgBackRest writes a repository file under a temporary name first.
const pgbackrestTmpSuffix = ".pgbackrest.tmp"

// indexRepo walks the repository. Files still being written are left out; a directory pgBackRest removes during the
// walk is skipped.
func indexRepo(r *os.Root) (repoIndex, error) {
	idx := repoIndex{}
	err := fs.WalkDir(r.FS(), ".", func(p string, e fs.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil
			}
			return err
		}
		if e.IsDir() || strings.HasPrefix(e.Name(), tmpPrefix) || strings.HasSuffix(e.Name(), pgbackrestTmpSuffix) {
			return nil
		}
		info, err := e.Info()
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		if info.Mode().IsRegular() {
			idx[p] = fileInfo{size: info.Size(), mod: info.ModTime()}
		}
		return nil
	})
	return idx, err
}

// under returns the paths of idx below dir (with a trailing slash), sorted.
func (idx repoIndex) under(dir string) []string {
	var out []string
	for p := range idx {
		if strings.HasPrefix(p, dir) {
			out = append(out, p)
		}
	}
	slices.Sort(out)
	return out
}

// bytesUnder sums the sizes below dir.
func (idx repoIndex) bytesUnder(dir string) int64 {
	var n int64
	for _, p := range idx.under(dir) {
		n += idx[p].size
	}
	return n
}

// fileTimePattern matches the time prefix of a snapshot or dump file name (backupset.OpenBaoKey, FleetKey).
var fileTimePattern = regexp.MustCompile(`^(\d{8}T\d{6}Z)\.`)

// fileTime returns the time in a snapshot or dump file name, or the modification time.
func fileTime(p string, fi fileInfo) time.Time {
	if t, ok := nameTime(p); ok {
		return t
	}
	return fi.mod
}

// newestTime returns the newest file time below dir, zero without a file.
func (idx repoIndex) newestTime(dir string) time.Time {
	var newest time.Time
	for _, p := range idx.under(dir) {
		if t := fileTime(p, idx[p]); t.After(newest) {
			newest = t
		}
	}
	return newest
}

// fullLabel matches the label of a pgBackRest full backup: its start time.
var fullLabel = regexp.MustCompile(`^(\d{8}-\d{6})F$`)

// fullManifest is the file pgBackRest writes into a backup's directory once the backup completed; a running or
// aborted backup holds only backup.manifest.copy and its data files, and cannot be restored.
const fullManifest = "backup.manifest"

// hasBackup reports whether the repository path repoPath holds the completed backup label of stanza.
func (idx repoIndex) hasBackup(repoPath, stanza, label string) bool {
	_, ok := idx[repoPath+"/backup/"+stanza+"/"+label+"/"+fullManifest]
	return ok
}

// fulls returns the labels of the completed full backups of stanza in the repository path repoPath, oldest first.
func (idx repoIndex) fulls(repoPath, stanza string) []string {
	dir := repoPath + "/backup/" + stanza + "/"
	var out []string
	for _, p := range idx.under(dir) {
		label, rest, ok := strings.Cut(strings.TrimPrefix(p, dir), "/")
		if ok && rest == fullManifest && fullLabel.MatchString(label) {
			out = append(out, label)
		}
	}
	slices.Sort(out)
	return out
}

// newestFull returns the label and start time of the newest completed full backup of stanza in the repository path
// repoPath.
func (idx repoIndex) newestFull(repoPath, stanza string) (string, time.Time) {
	labels := idx.fulls(repoPath, stanza)
	if len(labels) == 0 {
		return "", time.Time{}
	}
	best := labels[len(labels)-1]
	t, _ := time.Parse("20060102-150405", fullLabel.FindStringSubmatch(best)[1])
	return best, t
}

// expired reports whether pgBackRest's retention has removed the full backup label of stanza in repoPath, or would
// have: the local stanza holds at least retention completed full backups newer than it (plan M15, amendment
// 2026-11-05, A2; repo1-retention-full).
func (idx repoIndex) expired(repoPath, stanza, label string, retention int) bool {
	newer := 0
	for _, l := range idx.fulls(repoPath, stanza) {
		if l > label {
			newer++
		}
	}
	return newer >= max(retention, 1)
}

// holdsPath reports whether the local set holds any file of the repository path repoPath.
func (idx repoIndex) holdsPath(repoPath string) bool {
	dir := repoPath + "/"
	for p := range idx {
		if strings.HasPrefix(p, dir) {
			return true
		}
	}
	return false
}

// walSegment matches a WAL segment file in pgBackRest's archive: the segment name, a dash and the checksum.
var walSegment = regexp.MustCompile(`^([0-9A-F]{24})-[0-9a-f]{40}`)

// walFile matches a WAL segment or a backup history file (<segment>.<offset>.backup) of pgBackRest's archive.
var walFile = regexp.MustCompile(`^([0-9A-F]{24})(-[0-9a-f]{40}|\.[0-9A-F]{8}\.backup)`)

// segments returns the names of the WAL segments of stanza in the repository path repoPath, sorted.
func (idx repoIndex) segments(repoPath, stanza string) []string {
	var out []string
	for _, p := range idx.under(repoPath + "/archive/" + stanza + "/") {
		if m := walSegment.FindStringSubmatch(path.Base(p)); m != nil {
			out = append(out, m[1])
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// lowestWAL returns the lowest WAL segment of stanza in the repository path repoPath, empty without one.
func (idx repoIndex) lowestWAL(repoPath, stanza string) string {
	if s := idx.segments(repoPath, stanza); len(s) > 0 {
		return s[0]
	}
	return ""
}

// contiguousWAL reports whether the archive of stanza in repoPath holds every segment from its lowest to its highest
// one, with run.sh restore's walk (256 segments of 16 MB per log file, per timeline); false without a segment.
func (idx repoIndex) contiguousWAL(repoPath, stanza string) bool {
	segs := idx.segments(repoPath, stanza)
	if len(segs) == 0 {
		return false
	}
	for i := 1; i < len(segs); i++ {
		prev, cur := segs[i-1], segs[i]
		if prev[:8] != cur[:8] {
			// A new timeline starts where the old one ended; run.sh restore stages one timeline.
			continue
		}
		if nextSegment(prev) != cur {
			return false
		}
	}
	return true
}

// nextSegment returns the WAL segment after seg on its timeline.
func nextSegment(seg string) string {
	log, err1 := strconv.ParseUint(seg[8:16], 16, 32)
	n, err2 := strconv.ParseUint(seg[16:24], 16, 32)
	if err1 != nil || err2 != nil {
		return ""
	}
	n++
	if n > 255 {
		n, log = 0, log+1
	}
	return fmt.Sprintf("%s%08X%08X", seg[:8], log, n)
}

// nameTime returns the time in a snapshot or dump file name; ok is false when the name holds none.
func nameTime(p string) (time.Time, bool) {
	m := fileTimePattern.FindStringSubmatch(path.Base(p))
	if m == nil {
		return time.Time{}, false
	}
	t, err := time.Parse("20060102T150405Z", m[1])
	return t, err == nil
}

// newestWAL returns the newest archived WAL segment of stanza and its modification time.
func (idx repoIndex) newestWAL(repoPath, stanza string) (string, time.Time) {
	dir := repoPath + "/archive/" + stanza + "/"
	var name string
	var at time.Time
	for _, p := range idx.under(dir) {
		m := walSegment.FindStringSubmatch(path.Base(p))
		if m == nil {
			continue
		}
		if m[1] > name {
			name = m[1]
		}
		if t := idx[p].mod; t.After(at) {
			at = t
		}
	}
	return name, at
}

// readEpoch reads a file holding Unix seconds (pgBackRest's last-full, a request marker); zero when it is absent.
func readEpoch(r *os.Root, name string) time.Time {
	raw, err := r.ReadFile(name)
	if err != nil {
		return time.Time{}
	}
	n, err := strconv.ParseInt(strings.TrimSpace(string(raw)), 10, 64)
	if err != nil || n <= 0 {
		return time.Time{}
	}
	return time.Unix(n, 0).UTC()
}

// hashEntry caches the SHA-256 of a sealed file between rounds: the files never change once written.
type hashEntry struct {
	size int64
	mod  time.Time
	sum  string
}

// sha256Of returns the hex SHA-256 of p, from the cache while its size and modification time are unchanged.
func sha256Of(r *os.Root, p string, fi fileInfo, cache map[string]hashEntry) (string, error) {
	if h, ok := cache[p]; ok && h.size == fi.size && h.mod.Equal(fi.mod) {
		return h.sum, nil
	}
	f, err := r.Open(p)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	sum := hex.EncodeToString(h.Sum(nil))
	cache[p] = hashEntry{size: fi.size, mod: fi.mod, sum: sum}
	return sum, nil
}

// manifestFiles lists the files below dir for the manifest, oldest first.
func manifestFiles(r *os.Root, idx repoIndex, dir string, hashed bool, cache map[string]hashEntry) ([]backupset.File, error) {
	var out []backupset.File
	for _, p := range idx.under(dir) {
		fi := idx[p]
		f := backupset.File{Path: p, Bytes: fi.size}
		if hashed {
			sum, err := sha256Of(r, p, fi, cache)
			if err != nil {
				return nil, fmt.Errorf("manifest %s: %w", p, err)
			}
			f.SHA256, f.At = sum, fileTime(p, fi)
		}
		out = append(out, f)
	}
	return out, nil
}
