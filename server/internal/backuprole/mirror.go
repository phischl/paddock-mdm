package backuprole

import (
	"bytes"
	"cmp"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/phischl/paddock-mdm/server/internal/domain/backupset"
)

// retention holds the inputs of a round that decide what a target may lose (plan M15, amendment 2026-11-05, A1): a
// target loses only what the local expire would have removed from the target's own copy.
type retention struct {
	// active is the repository path of the active key (A).
	active string
	// retired maps the repository path of every retired key to its retired_at.
	retired map[string]time.Time
	// known holds the repository path of every key the database knows (active, retired, discarded, legacy).
	known map[string]bool
	// full is retention_full; keep is retention_full × full_interval, how long a retired repository stays.
	full int
	keep time.Duration
	// kindKeep is the keep time of the OpenBao snapshots and the Fleet dumps by directory ("openbao/", "fleet/").
	kindKeep map[string]time.Duration
	// walOK holds "<repository path>/<stanza>" when the local archive of that stanza is contiguous and the last
	// whole-stanza verify is newer than its newest completed full backup (A2).
	walOK map[string]bool
	// escrow decides which escrowed header copies may leave the local set and the targets this round.
	escrow escrowRule
	// manifestOK is false when this round's local manifest could not be written: the mirror then deletes nothing.
	manifestOK bool
	now        time.Time
}

// mirrorHooks connect a mirror to its caller's watchdog: tick on every bit of progress, begin before each file is
// copied (with its size) and end once its copy returned, stop once the round's budget is used.
type mirrorHooks struct {
	tick  func()
	begin func(size int64)
	end   func()
	stop  func() bool
}

// guardPlan is what the guard decided for the repository paths the local set lacks entirely (A3 G3).
type guardPlan struct {
	// drop holds the retired repositories (with a trailing slash) the local expire would have removed by now.
	drop map[string]bool
	// hold holds the repositories (with a trailing slash) the target keeps although the local set lacks them.
	hold map[string]bool
	// unknown is true when the target holds a repository path no key names: nothing is deleted on it this round.
	unknown bool
}

// mirrorSet makes dst follow the local set (plan M15, amendment 2026-11-05, A3; the order is binding). It refuses a
// target whose manifest belongs to another installation or does not parse (step 0), lists the target (step 1) and
// runs the guard on that listing before any write (step 2): a target that could lose a restorable state by the
// copy stops with errSetShrunk and receives nothing. It then copies every file the target lacks or holds with
// another size (step 3: WAL, full backups with backup.manifest last, snapshots, dumps and escrowed headers, then
// pgBackRest's info files, which are copied again whenever they changed locally since they were last pushed),
// checks the sizes of what it copied (step 4), writes manifest.json when the target's differs (step 5) and only
// then deletes what the local expire would have removed from the target's own copy (step 6). It returns the number
// of objects the target keeps although the local set lacks them (held). Once hooks.stop reports true after a
// copied file it ends with errBudget before the manifest; it stops as soon as ctx ends.
func mirrorSet(ctx context.Context, repo *os.Root, idx repoIndex, dst Target, pushed map[string]fileInfo,
	ret retention, hooks mirrorHooks) (int, error) {
	local, err := repo.ReadFile(backupset.ManifestPath)
	if err != nil {
		return 0, fmt.Errorf("backup set: %w", err)
	}
	own, err := backupset.Parse(local)
	if err != nil {
		return 0, fmt.Errorf("backup set: %w", err)
	}
	remote, found, err := dst.Read(ctx, backupset.ManifestPath)
	if err != nil {
		return 0, err
	}
	hooks.tick()
	if found {
		theirs, err := backupset.Parse(remote)
		if err != nil {
			return 0, fmt.Errorf("%w: %w", errForeignSet, err)
		}
		if theirs.InstallationID != own.InstallationID {
			return 0, fmt.Errorf("%w: %s", errForeignSet, theirs.InstallationID)
		}
	}
	have, err := listProgress(ctx, dst, hooks.tick)
	if err != nil {
		return 0, err
	}
	hooks.tick()
	facts := newIndexFacts(idx)
	plan, err := guard(ctx, dst, facts, have, ret)
	if err != nil {
		return 0, err
	}
	hooks.tick()

	written := map[string]int64{}
	for _, p := range putOrder(idx) {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		if size, ok := have[p]; ok && size == idx[p].size && (!rewritten(p) || sameFile(pushed[p], idx[p])) {
			continue
		}
		hooks.begin(idx[p].size)
		n, err := putFile(ctx, repo, p, dst, hooks.tick)
		hooks.end()
		if errors.Is(err, fs.ErrNotExist) {
			// pgBackRest expired the file after the index was taken.
			continue
		}
		if err != nil {
			return 0, err
		}
		written[p] = n
		if rewritten(p) {
			pushed[p] = idx[p]
		}
		if hooks.stop() {
			return 0, errBudget
		}
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}

	after, err := listProgress(ctx, dst, hooks.tick)
	if err != nil {
		return 0, err
	}
	hooks.tick()
	for p, n := range written {
		if size, ok := after[p]; !ok || size != n {
			return 0, fmt.Errorf("%w: %s holds %d bytes, want %d", errSizeMismatch, p, size, n)
		}
	}

	held, drop, err := judge(ctx, facts, plan, ret, have, after)
	if err != nil {
		return 0, err
	}
	if !ret.manifestOK {
		if plan.unknown {
			return held, errUnknownPath
		}
		return held, nil
	}
	if !found || sha256.Sum256(remote) != sha256.Sum256(local) {
		// A3: manifest.json follows a verified copy of a mirror still running; one the stall watchdog or the round
		// already gave up writes nothing more.
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		if err := dst.Put(ctx, backupset.ManifestPath, bytes.NewReader(local), int64(len(local))); err != nil {
			return 0, err
		}
		hooks.tick()
		back, ok, err := dst.Read(ctx, backupset.ManifestPath)
		if err != nil {
			return 0, err
		}
		if !ok || sha256.Sum256(back) != sha256.Sum256(local) {
			return 0, errors.New("backup target: manifest.json differs from the written one")
		}
	}

	if plan.unknown {
		return held, errUnknownPath
	}
	for _, p := range drop {
		if err := ctx.Err(); err != nil {
			return held, err
		}
		if err := dst.Delete(ctx, p); err != nil {
			return held, err
		}
		hooks.tick()
	}
	return held, nil
}

// judge applies step 6's verdicts to every object of the step-1 listing (have) that the local set lacks and the
// step-4 listing (after) still holds. It returns the number of held objects and the objects to delete; with an
// unknown path every deletable object counts as held instead. It stops as soon as ctx ends.
func judge(ctx context.Context, facts *indexFacts, plan guardPlan, ret retention,
	have, after map[string]int64) (int, []string, error) {
	newest := newestKindFiles(have)
	held := 0
	var drop []string
	for _, p := range slices.Sorted(maps.Keys(have)) {
		if err := ctx.Err(); err != nil {
			return 0, nil, err
		}
		if _, ok := facts.idx[p]; ok || p == backupset.ManifestPath {
			continue
		}
		if _, still := after[p]; !still {
			continue
		}
		switch verdict(facts, plan, ret, newest, p) {
		case keepUntouched:
		case keepHeld:
			held++
		case drop1:
			if plan.unknown {
				held++
				continue
			}
			drop = append(drop, p)
		}
	}
	return held, drop, nil
}

// rewritten reports whether pgBackRest rewrites the file at p in place (backup.info, archive.info and their copies),
// so an equal size does not mean an equal content.
func rewritten(p string) bool {
	return strings.HasSuffix(p, ".info") || strings.HasSuffix(p, ".info.copy")
}

func sameFile(a, b fileInfo) bool { return a.size == b.size && a.mod.Equal(b.mod) }

// repoFile is a file of a pgBackRest repository in the set: pgbackrest/<key>/<area>/<stanza>/<rest>.
type repoFile struct {
	repoPath string
	key      string
	area     string
	stanza   string
	rest     []string
}

// parseRepo splits a set path below pgbackrest/; ok is false for every other path. A file directly below a
// repository path (no area and stanza) has an empty area.
func parseRepo(p string) (repoFile, bool) {
	rel, ok := strings.CutPrefix(p, backupset.RepoPath(""))
	if !ok {
		return repoFile{}, false
	}
	parts := strings.Split(rel, "/")
	f := repoFile{key: parts[0], repoPath: backupset.RepoPath(parts[0])}
	if len(parts) >= 4 {
		f.area, f.stanza, f.rest = parts[1], parts[2], parts[3:]
	}
	return f, true
}

// info reports whether f is one of pgBackRest's info files of its stanza (backup.info, archive.info, their copies).
func (f repoFile) info() bool {
	if len(f.rest) != 1 {
		return false
	}
	base := strings.TrimSuffix(f.rest[0], ".copy")
	return f.area == "backup" && base == "backup.info" || f.area == "archive" && base == "archive.info"
}

// label returns the full backup label of a file in a backup's directory, empty for every other file.
func (f repoFile) label() string {
	if f.area == "backup" && len(f.rest) >= 2 && fullLabel.MatchString(f.rest[0]) {
		return f.rest[0]
	}
	return ""
}

// segment returns the WAL segment a file of the archive belongs to: a segment or a backup history file
// (<segment>.<offset>.backup), which pgBackRest expires together with its segment; empty for every other file.
func (f repoFile) segment() string {
	if f.area != "archive" || len(f.rest) < 2 {
		return ""
	}
	if m := walFile.FindStringSubmatch(f.rest[len(f.rest)-1]); m != nil {
		return m[1]
	}
	return ""
}

// guard is step 2 of the mirror (A3): it checks the target's listing against the local set before the first write.
// For every repository path the local set holds, a completed full backup the target holds and the local set lacks
// must be one the local expire would have removed (G1), and an info file the target holds must exist locally, or
// its copy (G2); else the set is shrunk. A repository path the local set lacks entirely is the active key's (shrunk),
// a retired key's (removed once the local expire rule holds on the target's own copy, else held), or one no key
// names (held, unknown_path) (G3). OpenBao snapshots, Fleet dumps, escrowed headers and WAL never shrink the set (G4).
// It stops as soon as ctx ends.
func guard(ctx context.Context, dst Target, facts *indexFacts, have map[string]int64,
	ret retention) (guardPlan, error) {
	idx := facts.idx
	plan := guardPlan{drop: map[string]bool{}, hold: map[string]bool{}}
	lacking := map[string]bool{}
	for _, p := range slices.Sorted(maps.Keys(have)) {
		if err := ctx.Err(); err != nil {
			return guardPlan{}, err
		}
		f, ok := parseRepo(p)
		if !ok {
			continue
		}
		if !facts.holdsPath(f.repoPath) {
			lacking[f.repoPath] = true
			continue
		}
		if _, local := idx[p]; local {
			continue
		}
		switch {
		case f.label() != "" && len(f.rest) == 2 && f.rest[1] == fullManifest:
			if !facts.expired(f.repoPath, f.stanza, f.label(), ret.full) {
				return guardPlan{}, errSetShrunk
			}
		case f.info():
			dir := f.repoPath + "/" + f.area + "/" + f.stanza + "/"
			base := strings.TrimSuffix(f.rest[0], ".copy")
			_, a := idx[dir+base]
			_, b := idx[dir+base+".copy"]
			if !a && !b {
				return guardPlan{}, errSetShrunk
			}
		}
	}
	for _, repoPath := range slices.Sorted(maps.Keys(lacking)) {
		dir := repoPath + "/"
		retiredAt, retired := ret.retired[repoPath]
		switch {
		case repoPath == ret.active:
			return guardPlan{}, errSetShrunk
		case retired:
			if !activeComplete(idx, ret.active) {
				plan.hold[dir] = true
				continue
			}
			newest, err := dst.Newest(ctx, dir)
			if err != nil {
				return guardPlan{}, err
			}
			if retiredAt.After(newest) {
				newest = retiredAt
			}
			if ret.now.Sub(newest) > ret.keep {
				plan.drop[dir] = true
			} else {
				plan.hold[dir] = true
			}
		case ret.known[repoPath]:
			plan.hold[dir] = true
		default:
			plan.hold[dir] = true
			plan.unknown = true
		}
	}
	return plan, nil
}

// Verdicts of step 6 on an object the target holds and the local set lacks.
const (
	// keepUntouched: not part of the set (A3 D7); never deleted, not counted.
	keepUntouched = iota
	// keepHeld: kept this round, counted as held.
	keepHeld
	// drop1: the local expire would have removed it from the target's copy; deleted.
	drop1
)

// verdict applies the delete rules D1–D7 of A3 step 6 to the object p the target holds and the local set lacks.
// newest is the time of the newest OpenBao snapshot and Fleet dump on the target's step-1 listing.
func verdict(facts *indexFacts, plan guardPlan, ret retention, newest map[string]time.Time, p string) int {
	if f, ok := parseRepo(p); ok {
		dir := f.repoPath + "/"
		switch {
		case plan.drop[dir]:
			return drop1
		case plan.hold[dir], !facts.holdsPath(f.repoPath), f.info():
			return keepHeld
		case f.label() != "":
			if facts.expired(f.repoPath, f.stanza, f.label(), ret.full) {
				return drop1
			}
		case f.segment() != "":
			low := facts.lowestWAL(f.repoPath, f.stanza)
			if len(facts.fulls(f.repoPath, f.stanza)) >= max(ret.full, 1) && low != "" && f.segment() < low &&
				ret.walOK[f.repoPath+"/"+f.stanza] {
				return drop1
			}
		}
		return keepHeld
	}
	dir, _, _ := strings.Cut(p, "/")
	switch dir += "/"; dir {
	case "openbao/", "fleet/":
		at, ok := nameTime(p)
		if ok && at.Before(newest[dir]) && ret.now.Sub(at) > ret.kindKeep[dir] && facts.hasUnder(dir) {
			return drop1
		}
		return keepHeld
	case "escrow/":
		if ret.escrow.gone(p, ret.now, ret.keep) {
			return drop1
		}
		return keepHeld
	}
	return keepUntouched
}

// newestKindFiles returns the time of the newest OpenBao snapshot and Fleet dump in a target's listing, by the time in
// their names (A1: a kind file's age is never its modification time).
func newestKindFiles(have map[string]int64) map[string]time.Time {
	out := map[string]time.Time{}
	for p := range have {
		for _, dir := range []string{"openbao/", "fleet/"} {
			if !strings.HasPrefix(p, dir) {
				continue
			}
			if at, ok := nameTime(p); ok && at.After(out[dir]) {
				out[dir] = at
			}
		}
	}
	return out
}

// putOrder returns the local files to copy in the order of A3 step 3: WAL, full backups (data files,
// backup.manifest.copy, backup.manifest last; a backup without backup.manifest is still running and skipped),
// snapshots, dumps and escrowed headers, and pgBackRest's info files last. manifest.json is written in step 5.
func putOrder(idx repoIndex) []string {
	type entry struct {
		p     string
		rank  int
		group string
		sub   int
	}
	var out []entry
	for p := range idx {
		if p == backupset.ManifestPath {
			continue
		}
		e := entry{p: p, rank: 3}
		if f, ok := parseRepo(p); ok {
			switch {
			case f.info():
				e.rank = 4
			case f.area == "archive":
				e.rank = 1
			case f.label() != "":
				if !idx.hasBackup(f.repoPath, f.stanza, f.label()) {
					continue
				}
				e.rank, e.group = 2, f.repoPath+"/backup/"+f.stanza+"/"+f.label()
				switch {
				case len(f.rest) == 2 && f.rest[1] == fullManifest:
					e.sub = 2
				case len(f.rest) == 2 && f.rest[1] == fullManifest+".copy":
					e.sub = 1
				}
			default:
				e.rank = 2
			}
		}
		out = append(out, e)
	}
	slices.SortFunc(out, func(a, b entry) int {
		return cmp.Or(cmp.Compare(a.rank, b.rank), cmp.Compare(a.group, b.group), cmp.Compare(a.sub, b.sub),
			cmp.Compare(a.p, b.p))
	})
	paths := make([]string, len(out))
	for i, e := range out {
		paths[i] = e.p
	}
	return paths
}

// activeComplete reports whether the repository path active holds a completed full backup of every stanza.
func activeComplete(idx repoIndex, active string) bool {
	for _, stanza := range Stanzas {
		if len(idx.fulls(active, stanza)) == 0 {
			return false
		}
	}
	return true
}

// putFile copies one file of the repository to dst and returns its size.
func putFile(ctx context.Context, repo *os.Root, p string, dst Target, tick func()) (int64, error) {
	f, err := repo.Open(p)
	if err != nil {
		return 0, err
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return 0, err
	}
	if err := dst.Put(ctx, p, &progressReader{f: f, tick: tick}, info.Size()); err != nil {
		return 0, err
	}
	tick()
	return info.Size(), nil
}

// progressReader reports every read of a file being copied; it stays seekable for an S3 upload's signing and retries.
type progressReader struct {
	f    *os.File
	tick func()
}

func (r *progressReader) Read(b []byte) (int, error) {
	n, err := r.f.Read(b)
	if n > 0 {
		r.tick()
	}
	return n, err
}

func (r *progressReader) Seek(offset int64, whence int) (int64, error) {
	return r.f.Seek(offset, whence)
}

var _ io.ReadSeeker = (*progressReader)(nil)
