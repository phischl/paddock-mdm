package backuprole

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"math/rand/v2"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/phischl/paddock-mdm/server/internal/domain/backupset"
)

// The regression matrix of plan M15, amendment 2026-11-05, A6: one test per loss case of A4, the order of A3 and its
// invariants. Every test drives mirrorSet through runMirror with the retention inputs of rules.

var (
	matrixNow = time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	pathA     = backupset.RepoPath(testKeyID)
	pathOld   = backupset.RepoPath("bk-20261001-0badc0de")
	day       = 24 * time.Hour
)

// Full backup labels, oldest first.
const (
	label1 = "20261101-010000F"
	label2 = "20261102-010000F"
	label3 = "20261103-010000F"
	label4 = "20261104-010000F"
	label9 = "20261105-010000F"
)

// set is a backup set by path with the file contents.
type set map[string]string

func with(sets ...set) set {
	out := set{}
	for _, s := range sets {
		maps.Copy(out, s)
	}
	return out
}

// fullOf is a completed full backup: a data file, backup.manifest.copy and backup.manifest.
func fullOf(repoPath, stanza, label string) set {
	d := repoPath + "/backup/" + stanza + "/" + label + "/"
	return set{d + "pg_data/base/1.zst": "data " + label, d + "backup.manifest.copy": "manifest " + label,
		d + fullManifest: "manifest " + label}
}

// infoOf is pgBackRest's info files of a stanza.
func infoOf(repoPath, stanza, body string) set {
	return set{repoPath + "/backup/" + stanza + "/backup.info": body, repoPath + "/backup/" + stanza + "/backup.info.copy": body,
		repoPath + "/archive/" + stanza + "/archive.info": body, repoPath + "/archive/" + stanza + "/archive.info.copy": body}
}

// segName is WAL segment n of timeline 1, log 0.
func segName(n int) string { return fmt.Sprintf("00000001%08X%08X", 0, n) }

// walPath is the archived file of segment n.
func walPath(repoPath, stanza string, n int) string {
	return repoPath + "/archive/" + stanza + "/18-1/0000000100000000/" + segName(n) + "-" + strings.Repeat("a", 40) + ".zst"
}

// walOf is the archived WAL segments n of a stanza.
func walOf(repoPath, stanza string, n ...int) set {
	out := set{}
	for _, i := range n {
		out[walPath(repoPath, stanza, i)] = "wal " + segName(i)
	}
	return out
}

func span(from, to int) []int {
	var out []int
	for i := from; i <= to; i++ {
		out = append(out, i)
	}
	return out
}

// completeA is a full backup and the info files of both stanzas in the active repository.
func completeA(label string) set {
	return with(fullOf(pathA, "paddock", label), fullOf(pathA, "authentik", label), infoOf(pathA, "paddock", "i"),
		infoOf(pathA, "authentik", "i"))
}

func snapAt(age time.Duration) string { return backupset.OpenBaoKey(matrixNow.Add(-age)) }
func dumpAt(age time.Duration) string { return backupset.FleetKey(matrixNow.Add(-age)) }
func escrowOf(name string) string {
	return backupset.EscrowKey("org/o1/devices/d1/luks-header/" + name + ".bin")
}
func under(s set, dir string) []string { return slices.Sorted(keysWith(s, dir)) }

func keysWith[V any](m map[string]V, dir string) func(func(string) bool) {
	return func(yield func(string) bool) {
		for k := range m {
			if strings.HasPrefix(k, dir) && !yield(k) {
				return
			}
		}
	}
}

// localSet writes s and a manifest of installation 42 into a new repository.
func localSet(t *testing.T, s set) (*os.Root, repoIndex) {
	t.Helper()
	files := with(set{backupset.ManifestPath: string(testManifest(t, InstallationID(42), nil))}, s)
	return openSet(t, files)
}

// targetOf is a target holding s, every file modified at mod, with a manifest of installation 42 unless bare.
func targetOf(t *testing.T, s set, mod time.Time, bare bool) *memTarget {
	t.Helper()
	dst := newMemTarget()
	dst.now = func() time.Time { return matrixNow }
	for p, body := range s {
		dst.files[p], dst.mod[p] = []byte(body), mod
	}
	if !bare {
		dst.files[backupset.ManifestPath] = testManifest(t, InstallationID(42), func(m *backupset.Manifest) {
			m.Contents.PgBackRest.Stanzas = []backupset.Stanza{{Name: "paddock", LastFull: label1}}
		})
	}
	return dst
}

func opsOf(dst *memTarget, verb string) []string {
	var out []string
	for _, op := range dst.ops {
		if p, ok := strings.CutPrefix(op, verb+" "); ok {
			out = append(out, p)
		}
	}
	return out
}

func sameFiles(a, b map[string][]byte) bool { return maps.EqualFunc(a, b, bytes.Equal) }

// assertHeld checks the held count where the code under test reports one.
func assertHeld(t *testing.T, held, want int) {
	t.Helper()
	if heldKnown && held != want {
		t.Errorf("held %d, want %d", held, want)
	}
}

// TestMirrorRepoLostStateKept (L1): the repository volume is lost, the state volume kept: the local set is an empty
// repository and its manifest. The target keeps every byte and the mirror fails with set_shrunk, with and without
// the target's manifest.json.
func TestMirrorRepoLostStateKept(t *testing.T) {
	repo, idx := localSet(t, nil)
	held := with(fullOf(pathA, "paddock", label1), fullOf(pathA, "paddock", label2), infoOf(pathA, "paddock", "i"),
		walOf(pathA, "paddock", span(1, 6)...), set{snapAt(day): "s1", snapAt(2 * day): "s2", snapAt(3 * day): "s3",
			dumpAt(day): "d1", dumpAt(2 * day): "d2", escrowOf("x"): "x"})
	for name, bare := range map[string]bool{"with manifest.json": false, "without manifest.json": true} {
		t.Run(name, func(t *testing.T) {
			dst := targetOf(t, held, matrixNow.Add(-day), bare)
			before := maps.Clone(dst.files)
			_, err := runMirror(repo, idx, dst, defaultRules())
			if !errors.Is(err, errSetShrunk) {
				t.Fatalf("error %v, want set_shrunk", err)
			}
			if len(dst.ops) != 0 || !sameFiles(dst.files, before) {
				t.Errorf("the target changed: %v", dst.ops)
			}
		})
	}
}

// TestMirrorStateLostRepoKept (L2): the state volume is lost, the repository kept; pgBackRest took a new full F3 and
// expired F1 locally (retention_full 2). The mirror copies F3 and the new WAL and deletes F1 on the target; the WAL
// below the oldest local segment leaves the target only while the local archive is contiguous and verified.
func TestMirrorStateLostRepoKept(t *testing.T) {
	local := with(fullOf(pathA, "paddock", label2), fullOf(pathA, "paddock", label3), infoOf(pathA, "paddock", "i"),
		walOf(pathA, "paddock", span(5, 9)...))
	target := with(fullOf(pathA, "paddock", label1), fullOf(pathA, "paddock", label2), infoOf(pathA, "paddock", "i"),
		walOf(pathA, "paddock", span(1, 6)...))
	for name, verified := range map[string]bool{"verified": true, "not verified": false} {
		t.Run(name, func(t *testing.T) {
			repo, idx := localSet(t, local)
			dst := targetOf(t, target, matrixNow.Add(-day), false)
			r := defaultRules()
			if verified {
				r.walOK = []string{pathA + "/paddock"}
			}
			held, err := runMirror(repo, idx, dst, r)
			if err != nil {
				t.Fatal(err)
			}
			puts := opsOf(dst, "put")
			for p := range with(fullOf(pathA, "paddock", label3), walOf(pathA, "paddock", 7, 8, 9)) {
				if !slices.Contains(puts, p) {
					t.Errorf("%s not copied: %v", p, puts)
				}
			}
			want := under(fullOf(pathA, "paddock", label1), "")
			wantHeld := 4
			if verified {
				want = append(want, under(walOf(pathA, "paddock", 1, 2, 3, 4), "")...)
				wantHeld = 0
			}
			slices.Sort(want)
			if got := opsOf(dst, "delete"); !slices.Equal(got, want) {
				t.Errorf("deletes %v, want %v", got, want)
			}
			assertHeld(t, held, wantHeld)
		})
	}
}

// vanishingTarget drops one file between the mirror's first and second listing (another writer on the share).
type vanishingTarget struct {
	*memTarget
	lists  int
	vanish string
}

func (v *vanishingTarget) List(ctx context.Context) (map[string]int64, error) {
	v.lists++
	if v.lists == 2 {
		delete(v.files, v.vanish)
	}
	return v.memTarget.List(ctx)
}

// TestMirrorDeletesOnlyWhatStepFourStillLists (A3 step 6, review 6 F2): an object of the step-1 listing that is gone
// by step 4 is not deleted again; the other allowed deletes run.
func TestMirrorDeletesOnlyWhatStepFourStillLists(t *testing.T) {
	repo, idx := localSet(t, with(fullOf(pathA, "paddock", label2), fullOf(pathA, "paddock", label3),
		infoOf(pathA, "paddock", "i"), walOf(pathA, "paddock", span(5, 9)...)))
	old := under(fullOf(pathA, "paddock", label1), "")
	dst := &vanishingTarget{memTarget: targetOf(t, with(fullOf(pathA, "paddock", label1), fullOf(pathA, "paddock", label2),
		infoOf(pathA, "paddock", "i")), matrixNow.Add(-day), false), vanish: old[0]}
	if _, err := runMirror(repo, idx, dst, defaultRules()); err != nil {
		t.Fatal(err)
	}
	got := opsOf(dst.memTarget, "delete")
	if slices.Contains(got, old[0]) {
		t.Errorf("%s deleted although the step-4 listing no longer held it: %v", old[0], got)
	}
	if !slices.Equal(got, old[1:]) {
		t.Errorf("deletes %v, want %v", got, old[1:])
	}
}

// TestMirrorWalHeldBelowRetentionFull (A3 D2, review 6 F2): WAL below the lowest local segment stays on the target
// while the local stanza holds fewer than retention_full completed fulls, even with wal_ok; the target holds no
// older full, so the guard (G1) does not decide it.
func TestMirrorWalHeldBelowRetentionFull(t *testing.T) {
	repo, idx := localSet(t, with(fullOf(pathA, "paddock", label2), infoOf(pathA, "paddock", "i"),
		walOf(pathA, "paddock", span(5, 9)...)))
	dst := targetOf(t, with(fullOf(pathA, "paddock", label2), infoOf(pathA, "paddock", "i"),
		walOf(pathA, "paddock", span(1, 6)...)), matrixNow.Add(-day), false)
	r := defaultRules()
	r.walOK = []string{pathA + "/paddock"}
	held, err := runMirror(repo, idx, dst, r)
	if err != nil {
		t.Fatal(err)
	}
	if got := opsOf(dst, "delete"); len(got) != 0 {
		t.Errorf("deletes %v with one local full and retention_full 2", got)
	}
	assertHeld(t, held, 4)
}

// TestMirrorBothLostFreshFull (L3): both volumes are lost; pgBackRest created the stanza in the empty repository and
// took a new full F9, and the role took a snapshot. The target holds two fulls the local stanza lacks with fewer than
// retention_full newer ones: set_shrunk, nothing written, nothing deleted, not even F9 or the snapshot.
func TestMirrorBothLostFreshFull(t *testing.T) {
	repo, idx := localSet(t, with(fullOf(pathA, "paddock", label9), infoOf(pathA, "paddock", "new"),
		set{snapAt(time.Hour): "new"}))
	dst := targetOf(t, with(fullOf(pathA, "paddock", label1), fullOf(pathA, "paddock", label2),
		infoOf(pathA, "paddock", "i"), walOf(pathA, "paddock", span(1, 6)...),
		set{snapAt(day): "s1", snapAt(5 * day): "s2", snapAt(40 * day): "s3"}), matrixNow.Add(-day), false)
	before := maps.Clone(dst.files)
	if _, err := runMirror(repo, idx, dst, defaultRules()); !errors.Is(err, errSetShrunk) {
		t.Fatalf("error %v, want set_shrunk", err)
	}
	if len(dst.ops) != 0 || !sameFiles(dst.files, before) {
		t.Errorf("the target changed: %v", dst.ops)
	}
}

// TestMirrorWalOnlyLossHolds (L4): the local WAL archive is lost (a) or has a gap (b) while full backups continue. The
// target keeps every WAL segment the local set lacks (held), the new full is copied.
func TestMirrorWalOnlyLossHolds(t *testing.T) {
	fulls := with(fullOf(pathA, "paddock", label2), fullOf(pathA, "paddock", label3), infoOf(pathA, "paddock", "i"))
	for name, c := range map[string]struct {
		wal  []int
		held int
	}{"a archive lost": {nil, 9}, "b archive with a gap": {[]int{5, 6, 8, 9}, 5}} {
		t.Run(name, func(t *testing.T) {
			repo, idx := localSet(t, with(fulls, fullOf(pathA, "paddock", label4), walOf(pathA, "paddock", c.wal...)))
			dst := targetOf(t, with(fulls, walOf(pathA, "paddock", span(1, 9)...)), matrixNow.Add(-day), false)
			held, err := runMirror(repo, idx, dst, defaultRules())
			if err != nil {
				t.Fatal(err)
			}
			for _, p := range opsOf(dst, "delete") {
				if strings.Contains(p, "/archive/") {
					t.Errorf("deleted %s", p)
				}
			}
			if !slices.Contains(opsOf(dst, "put"), pathA+"/backup/paddock/"+label4+"/"+fullManifest) {
				t.Errorf("the new full was not copied: %v", dst.ops)
			}
			assertHeld(t, held, c.held)
		})
	}
}

// TestMirrorKindPartialLossFollowsKeep (L5): the local set lost older snapshots and took a new one. On the target the
// snapshots past the keep days that are not its newest leave, younger ones are held, the newest is never deleted
// (evaluated on the listing before this round's copies).
func TestMirrorKindPartialLossFollowsKeep(t *testing.T) {
	s1, s2, s3, s4 := snapAt(40*day), snapAt(31*day), snapAt(10*day), snapAt(time.Hour)
	repo, idx := localSet(t, set{s4: "s4"})
	dst := targetOf(t, set{s1: "s1", s2: "s2", s3: "s3"}, matrixNow.Add(-day), false)
	held, err := runMirror(repo, idx, dst, defaultRules())
	if err != nil {
		t.Fatal(err)
	}
	if puts := opsOf(dst, "put"); !slices.Contains(puts, s4) {
		t.Errorf("puts %v lack %s", puts, s4)
	}
	if got, want := opsOf(dst, "delete"), []string{s1, s2}; !slices.Equal(got, want) {
		t.Errorf("deletes %v, want %v", got, want)
	}
	assertHeld(t, held, 1)

	t.Run("second round", func(t *testing.T) {
		dst.ops = nil
		r := defaultRules()
		r.now = matrixNow.Add(25 * day)
		held, err := runMirror(repo, idx, dst, r)
		if err != nil {
			t.Fatal(err)
		}
		if got := opsOf(dst, "delete"); !slices.Equal(got, []string{s3}) {
			t.Errorf("deletes %v, want %s", got, s3)
		}
		assertHeld(t, held, 0)
	})
	t.Run("the target's newest stays", func(t *testing.T) {
		dst := targetOf(t, set{s1: "s1"}, matrixNow.Add(-day), false)
		held, err := runMirror(repo, idx, dst, defaultRules())
		if err != nil {
			t.Fatal(err)
		}
		if got := opsOf(dst, "delete"); len(got) != 0 {
			t.Errorf("deleted %v, the newest snapshot of the target", got)
		}
		assertHeld(t, held, 1)
	})
}

// TestMirrorKindWhollyLostHolds (L6): the local set holds no OpenBao snapshot: every snapshot on the target is held,
// whatever its age, and the rest of the mirror runs without an error.
func TestMirrorKindWhollyLostHolds(t *testing.T) {
	repo, idx := localSet(t, with(completeA(label1), set{dumpAt(time.Hour): "d"}))
	dst := targetOf(t, with(completeA(label1), set{snapAt(40 * day): "s1", snapAt(day): "s2"}), matrixNow.Add(-day), false)
	held, err := runMirror(repo, idx, dst, defaultRules())
	if err != nil {
		t.Fatal(err)
	}
	if got := opsOf(dst, "delete"); len(got) != 0 {
		t.Errorf("deleted %v", got)
	}
	if !slices.Contains(opsOf(dst, "put"), dumpAt(time.Hour)) {
		t.Errorf("the mirror did not run on: %v", dst.ops)
	}
	assertHeld(t, held, 2)
}

// TestMirrorEscrowFollowsBucket (L7, with the A2 notes b and c of decisions-alpha9 items 27, 29 and 31): an escrowed
// header the local set lacks leaves the target only when this round's bucket listing succeeded, was not suspicious
// and lacks it, and its device's Destroy evidence is older than the keep window and covers the copy: the escrow
// object's time the local set's index recorded is at or before the Destroy. Absence alone never deletes.
func TestMirrorEscrowFollowsBucket(t *testing.T) {
	x, y := escrowOf("x"), escrowOf("y")
	repo, idx := localSet(t, set{y: "y"})
	keep := defaultRules().keep
	for name, c := range map[string]struct {
		listed     bool
		bucket     []string
		destroyed  time.Duration
		suspicious bool
		// copied is the age of x's recorded escrow object time; 0 records none.
		copied  time.Duration
		deleted bool
	}{
		"listing failed":                          {false, nil, 0, false, 30 * day, false},
		"bucket has x":                            {true, []string{x, y}, 0, false, 30 * day, false},
		"bucket lacks x without evidence":         {true, []string{y}, 0, false, 30 * day, false},
		"evidence within the keep window":         {true, []string{y}, keep / 2, false, 30 * day, false},
		"evidence older than the keep window":     {true, []string{y}, keep + day, false, 30 * day, true},
		"copy as old as the Destroy":              {true, []string{y}, keep + day, false, keep + day, true},
		"copy newer than the Destroy":             {true, []string{y}, keep + day, false, keep, false},
		"copy without a recorded time":            {true, []string{y}, keep + day, false, 0, false},
		"evidence old but the listing suspicious": {true, []string{y}, keep + day, true, 30 * day, false},
		"empty bucket":                            {true, nil, 0, true, 30 * day, false},
	} {
		t.Run(name, func(t *testing.T) {
			dst := targetOf(t, set{x: "x", y: "y"}, matrixNow.Add(-day), false)
			r := defaultRules()
			r.listed, r.escrow, r.suspicious = c.listed, c.bucket, c.suspicious
			if c.destroyed > 0 {
				r.destroyed = map[string]time.Time{"o1/d1": matrixNow.Add(-c.destroyed)}
			}
			if c.copied > 0 {
				r.copied = map[string]time.Time{x: matrixNow.Add(-c.copied), y: matrixNow.Add(-c.copied)}
			}
			held, err := runMirror(repo, idx, dst, r)
			if err != nil {
				t.Fatal(err)
			}
			if _, kept := dst.files[x]; kept == c.deleted {
				t.Errorf("x kept %v, want deleted %v (%v)", kept, c.deleted, dst.ops)
			}
			if _, kept := dst.files[y]; !kept {
				t.Errorf("y deleted (%v)", dst.ops)
			}
			wantHeld := 1
			if c.deleted {
				wantHeld = 0
			}
			assertHeld(t, held, wantHeld)
		})
	}
}

// oldRepo is the retired key's complete repository.
func oldRepo() set {
	return with(fullOf(pathOld, "paddock", label1), fullOf(pathOld, "authentik", label1), infoOf(pathOld, "paddock", "o"),
		infoOf(pathOld, "authentik", "o"), walOf(pathOld, "paddock", 1, 2, 3))
}

// newRepo is the new active key's repository right after the rotation: stanzas and WAL, no full backup yet.
func newRepo() set {
	return with(infoOf(pathA, "paddock", "n"), infoOf(pathA, "authentik", "n"), walOf(pathA, "paddock", 1, 2))
}

// TestMirrorRotationPutsNewPathHoldsOld (L8): after a rotation the new key's WAL and info files are copied as they
// appear while the local set still holds the old path; nothing of the old path is deleted. Once the local expire
// removed the old path (the new repository complete, the old one past the retention), the target loses it whole.
func TestMirrorRotationPutsNewPathHoldsOld(t *testing.T) {
	r := defaultRules()
	r.retired[pathOld] = matrixNow.Add(-day)
	repo, idx := localSet(t, with(oldRepo(), newRepo()))
	dst := targetOf(t, oldRepo(), matrixNow.Add(-day), false)
	before := maps.Clone(dst.files)
	held, err := runMirror(repo, idx, dst, r)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range opsOf(dst, "put") {
		// A fresh mirror has no record of the info files it pushed, so it copies them again; their content stays.
		if !strings.HasPrefix(p, pathA+"/") && p != backupset.ManifestPath &&
			(!rewritten(p) || !bytes.Equal(dst.files[p], before[p])) {
			t.Errorf("put %s outside the new path", p)
		}
	}
	if got := opsOf(dst, "delete"); len(got) != 0 {
		t.Errorf("deleted %v", got)
	}
	assertHeld(t, held, 0)

	t.Run("A complete, the old path past the retention", func(t *testing.T) {
		r := defaultRules()
		r.keep = 14 * day
		r.retired[pathOld] = matrixNow.Add(-20 * day)
		repo, idx := localSet(t, completeA(label9))
		dst := targetOf(t, oldRepo(), matrixNow.Add(-20*day), false)
		if _, err := runMirror(repo, idx, dst, r); err != nil {
			t.Fatal(err)
		}
		if got, want := opsOf(dst, "delete"), under(oldRepo(), ""); !slices.Equal(got, want) {
			t.Errorf("deletes %v, want the old path %v", got, want)
		}
	})
}

// TestMirrorRotationThenLossKeepsOldPath (L9): a rotation, then the repository is lost: the local set lacks the old
// path entirely. The target keeps the old path byte for byte while the new repository has no full backup (a), and the
// whole target run stops when it also holds full backups of the new path the local set lacks (b).
func TestMirrorRotationThenLossKeepsOldPath(t *testing.T) {
	r := defaultRules()
	r.retired[pathOld] = matrixNow.Add(-20 * day)
	repo, idx := localSet(t, newRepo())
	t.Run("a new path without a full", func(t *testing.T) {
		dst := targetOf(t, oldRepo(), matrixNow.Add(-20*day), false)
		before := maps.Clone(dst.files)
		held, err := runMirror(repo, idx, dst, r)
		if err != nil {
			t.Fatal(err)
		}
		for _, p := range opsOf(dst, "put") {
			if !strings.HasPrefix(p, pathA+"/") && p != backupset.ManifestPath {
				t.Errorf("put %s outside the new path", p)
			}
		}
		if got := opsOf(dst, "delete"); len(got) != 0 {
			t.Errorf("deleted %v", got)
		}
		for p, b := range before {
			if strings.HasPrefix(p, pathOld+"/") && !bytes.Equal(dst.files[p], b) {
				t.Errorf("the old path lost or changed %s", p)
			}
		}
		assertHeld(t, held, len(oldRepo()))
	})
	t.Run("b the target holds fulls of the new path", func(t *testing.T) {
		dst := targetOf(t, with(oldRepo(), fullOf(pathA, "paddock", label1), fullOf(pathA, "paddock", label2)),
			matrixNow.Add(-20*day), false)
		before := maps.Clone(dst.files)
		if _, err := runMirror(repo, idx, dst, r); !errors.Is(err, errSetShrunk) {
			t.Fatalf("error %v, want set_shrunk", err)
		}
		if len(dst.ops) != 0 || !sameFiles(dst.files, before) {
			t.Errorf("the target changed: %v", dst.ops)
		}
	})
}

// TestMirrorRetiredPathAgeFromRetiredAt (L10): a target that missed the retired repository's last files has an older
// newest file than the local set had; the retirement time is the age base, so it never loses the path earlier than
// the local expire would.
func TestMirrorRetiredPathAgeFromRetiredAt(t *testing.T) {
	repo, idx := localSet(t, completeA(label9))
	for name, c := range map[string]struct {
		retired time.Duration
		deleted bool
	}{"retired 2 days ago": {2 * day, false}, "retired 15 days ago": {15 * day, true}} {
		t.Run(name, func(t *testing.T) {
			r := defaultRules()
			r.keep = 14 * day
			r.retired[pathOld] = matrixNow.Add(-c.retired)
			dst := targetOf(t, oldRepo(), matrixNow.Add(-20*day), false)
			held, err := runMirror(repo, idx, dst, r)
			if err != nil {
				t.Fatal(err)
			}
			if deleted := len(opsOf(dst, "delete")) == len(oldRepo()); deleted != c.deleted {
				t.Errorf("old path deleted %v, want %v: %v", deleted, c.deleted, dst.ops)
			}
			if !c.deleted {
				if got := opsOf(dst, "delete"); len(got) != 0 {
					t.Errorf("deleted %v", got)
				}
				assertHeld(t, held, len(oldRepo()))
			}
		})
	}
}

// TestMirrorUnknownPathHeld (L11, decisions-alpha10 A10-25): a repository path of no key the database knows is held
// and the target run fails with unknown_path naming it, but the copies run and every other deletion goes on: the
// expired snapshot and the retired key's repository past its retention leave the target. Before, one unknown path
// stopped every deletion on the target, so an operator could never reclaim its space.
func TestMirrorUnknownPathHeld(t *testing.T) {
	unknown := "pgbackrest/bk-20000101-deadbeef/backup/paddock/backup.info"
	r := defaultRules()
	r.keep = 14 * day
	r.retired[pathOld] = matrixNow.Add(-20 * day)
	repo, idx := localSet(t, with(completeA(label1), set{snapAt(time.Hour): "new"}))
	dst := targetOf(t, with(completeA(label1), oldRepo(), set{unknown: "u", snapAt(40 * day): "old",
		snapAt(35 * day): "older"}), matrixNow.Add(-20*day), false)
	_, err := runMirror(repo, idx, dst, r)
	if ErrorClass(err) != ClassUnknownPath || !strings.Contains(err.Error(), "pgbackrest/bk-20000101-deadbeef/") {
		t.Fatalf("error %v (%s), want %s naming the path", err, ErrorClass(err), ClassUnknownPath)
	}
	if !slices.Contains(opsOf(dst, "put"), snapAt(time.Hour)) {
		t.Errorf("the copies did not run: %v", dst.ops)
	}
	// The 35-day snapshot stays: it is the newest of its kind the target listed (D4).
	want := append(under(oldRepo(), ""), snapAt(40*day))
	slices.Sort(want)
	got := opsOf(dst, "delete")
	slices.Sort(got)
	if !slices.Equal(got, want) {
		t.Errorf("deleted %v, want %v", got, want)
	}
	if _, ok := dst.files[unknown]; !ok {
		t.Error("the unknown path was removed")
	}
}

// TestMirrorRefillsTarget (L12): a target that lost files (a share restored from an older snapshot) gets every file
// back and loses nothing.
func TestMirrorRefillsTarget(t *testing.T) {
	local := with(completeA(label1), walOf(pathA, "paddock", span(1, 6)...),
		set{snapAt(time.Hour): "s", dumpAt(time.Hour): "d", escrowOf("x"): "x"})
	repo, idx := localSet(t, local)
	half := set{}
	for i, p := range under(local, "") {
		if i%2 == 0 {
			half[p] = local[p]
		}
	}
	dst := targetOf(t, half, matrixNow.Add(-day), false)
	if _, err := runMirror(repo, idx, dst, defaultRules()); err != nil {
		t.Fatal(err)
	}
	puts := opsOf(dst, "put")
	for p := range local {
		if _, ok := half[p]; !ok && !slices.Contains(puts, p) {
			t.Errorf("%s not copied", p)
		}
		if string(dst.files[p]) != local[p] {
			t.Errorf("%s differs on the target", p)
		}
	}
	if got := opsOf(dst, "delete"); len(got) != 0 {
		t.Errorf("deleted %v", got)
	}
}

// opsTarget records every call on a target, reads included; failPut fails the put with that number (1-based).
type opsTarget struct {
	*memTarget
	calls   []string
	puts    int
	failPut int
}

func (o *opsTarget) List(ctx context.Context) (map[string]int64, error) {
	o.calls = append(o.calls, "list")
	return o.memTarget.List(ctx)
}

func (o *opsTarget) Newest(ctx context.Context, dir string) (time.Time, error) {
	o.calls = append(o.calls, "newest "+dir)
	return o.memTarget.Newest(ctx, dir)
}

func (o *opsTarget) Read(ctx context.Context, p string) ([]byte, bool, error) {
	o.calls = append(o.calls, "read "+p)
	return o.memTarget.Read(ctx, p)
}

func (o *opsTarget) Put(ctx context.Context, p string, r io.Reader, size int64) error {
	o.calls = append(o.calls, "put "+p)
	o.puts++
	if o.puts == o.failPut {
		return errors.New("disk full")
	}
	return o.memTarget.Put(ctx, p, r, size)
}

func (o *opsTarget) Delete(ctx context.Context, p string) error {
	o.calls = append(o.calls, "delete "+p)
	return o.memTarget.Delete(ctx, p)
}

// putRank is the place of a put in A3 step 3: WAL, full backups, kind files, info files.
func putRank(p string) int {
	switch {
	case p == backupset.ManifestPath:
		return 5
	case strings.HasSuffix(p, ".info") || strings.HasSuffix(p, ".info.copy"):
		return 4
	case strings.Contains(p, "/archive/"):
		return 1
	case strings.HasPrefix(p, "pgbackrest/"):
		return 2
	}
	return 3
}

// TestMirrorOrderGuardPutVerifyManifestDelete: the calls follow A3: read the manifest, list, the copies in the order
// WAL, full backups (backup.manifest of a backup last), kind files, info files; a second list; manifest.json after
// every other copy; every delete after that. A failing copy ends the round: no manifest, no delete.
func TestMirrorOrderGuardPutVerifyManifestDelete(t *testing.T) {
	local := with(fullOf(pathA, "paddock", label1), infoOf(pathA, "paddock", "i"), walOf(pathA, "paddock", 1, 2),
		set{snapAt(time.Hour): "s"})
	repo, idx := localSet(t, local)
	expiring := snapAt(40 * day)
	dst := &opsTarget{memTarget: targetOf(t, set{expiring: "e", snapAt(35 * day): "e2"}, matrixNow.Add(-day), false)}
	if _, err := runMirror(repo, idx, dst, defaultRules()); err != nil {
		t.Fatal(err)
	}
	if len(dst.calls) < 2 || dst.calls[0] != "read "+backupset.ManifestPath || dst.calls[1] != "list" {
		t.Fatalf("calls start %v, want the manifest read and the listing", dst.calls)
	}
	lastRank, lists, manifestAt, firstDelete := 0, 0, -1, -1
	secondList := -1
	for i, c := range dst.calls {
		verb, p, _ := strings.Cut(c, " ")
		switch verb {
		case "list":
			lists++
			if lists == 2 {
				secondList = i
			}
		case "put":
			if secondList >= 0 && p != backupset.ManifestPath {
				t.Errorf("put %s after the verify listing", p)
			}
			if r := putRank(p); r < lastRank {
				t.Errorf("put %s (rank %d) after rank %d: %v", p, r, lastRank, dst.calls)
			} else {
				lastRank = r
			}
			if p == backupset.ManifestPath {
				manifestAt = i
			}
		case "delete":
			if firstDelete < 0 {
				firstDelete = i
			}
		}
	}
	dir := pathA + "/backup/paddock/" + label1 + "/"
	puts := opsOf(dst.memTarget, "put")
	if i, j, k := slices.Index(puts, dir+"pg_data/base/1.zst"), slices.Index(puts, dir+"backup.manifest.copy"),
		slices.Index(puts, dir+fullManifest); i >= j || j >= k {
		t.Errorf("full backup put order %v", puts)
	}
	if secondList < 0 || manifestAt < secondList || firstDelete < manifestAt {
		t.Errorf("second list at %d, manifest at %d, first delete at %d: %v", secondList, manifestAt, firstDelete, dst.calls)
	}
	if got := opsOf(dst.memTarget, "delete"); !slices.Equal(got, []string{expiring}) {
		t.Errorf("deletes %v", got)
	}

	t.Run("a failing copy", func(t *testing.T) {
		dst := &opsTarget{memTarget: targetOf(t, set{expiring: "e", snapAt(35 * day): "e2"}, matrixNow.Add(-day), false),
			failPut: 3}
		if _, err := runMirror(repo, idx, dst, defaultRules()); err == nil {
			t.Fatal("no error")
		}
		for _, c := range dst.calls {
			if c == "put "+backupset.ManifestPath || strings.HasPrefix(c, "delete ") {
				t.Errorf("%s after a failed copy: %v", c, dst.calls)
			}
		}
	})
}

// TestMirrorPartialErrorStopsBeforeDelete: a copy that fails midway ends the round at that copy; the target keeps its
// manifest; the next round copies the rest, writes the manifest and deletes.
func TestMirrorPartialErrorStopsBeforeDelete(t *testing.T) {
	local := with(completeA(label1), set{snapAt(time.Hour): "s"})
	repo, idx := localSet(t, local)
	expiring := snapAt(40 * day)
	dst := &opsTarget{memTarget: targetOf(t, set{expiring: "e", snapAt(35 * day): "e2"}, matrixNow.Add(-day), false),
		failPut: 4}
	manifest := bytes.Clone(dst.files[backupset.ManifestPath])
	if _, err := runMirror(repo, idx, dst, defaultRules()); err == nil {
		t.Fatal("no error")
	}
	if last := dst.calls[len(dst.calls)-1]; !strings.HasPrefix(last, "put ") || dst.puts != 4 {
		t.Errorf("calls end with %q after %d puts, want the failing put", last, dst.puts)
	}
	if !bytes.Equal(dst.files[backupset.ManifestPath], manifest) {
		t.Error("the target's manifest changed")
	}
	dst.failPut, dst.calls = 0, nil
	if _, err := runMirror(repo, idx, dst, defaultRules()); err != nil {
		t.Fatal(err)
	}
	for p, body := range local {
		if string(dst.files[p]) != body {
			t.Errorf("%s missing after the second round", p)
		}
	}
	if got := opsOf(dst.memTarget, "delete"); !slices.Equal(got, []string{expiring}) {
		t.Errorf("deletes %v", got)
	}
}

// randomCase is one random local set and target of TestMirrorInvariants.
type randomCase struct {
	local, target set
	r             rules
	mod           map[string]time.Time
	bare          bool
}

func randomSet(rng *rand.Rand) randomCase {
	c := randomCase{local: set{}, target: set{}, r: defaultRules(), mod: map[string]time.Time{}}
	c.r.full = 1 + rng.IntN(3)
	c.r.keep = time.Duration(5+rng.IntN(20)) * day
	c.r.retired[pathOld] = matrixNow.Add(-time.Duration(rng.IntN(30)) * day)
	c.bare = rng.IntN(2) == 0
	c.r.noManifest = rng.IntN(10) == 0
	pick := func(p, body string, pl, pt int) {
		if rng.IntN(100) < pl {
			c.local[p] = body
		}
		if rng.IntN(100) < pt {
			c.target[p] = body
		}
	}
	labels := []string{"20261020-010000F", "20261022-010000F", "20261024-010000F", "20261026-010000F", "20261028-010000F"}
	oldLocal := rng.IntN(3) > 0
	for _, repoPath := range []string{pathA, pathOld} {
		pl := 70
		if repoPath == pathOld && !oldLocal {
			pl = 0
		}
		for _, stanza := range []string{"paddock", "authentik"} {
			// The local stanza normally holds its newest k fulls (pgBackRest expired the older ones); now and then it
			// lost some of them.
			lost, k := pl > 0 && rng.IntN(8) == 0, 1+rng.IntN(len(labels))
			for i, l := range labels {
				inL := pl > 0 && (lost && rng.IntN(2) == 0 || !lost && i >= len(labels)-k)
				inT := rng.IntN(100) < 60
				for p, b := range fullOf(repoPath, stanza, l) {
					if inL {
						c.local[p] = b
					}
					if inT {
						c.target[p] = b
					}
				}
			}
			infoL := 100
			if pl == 0 {
				infoL = 0
			} else if lost {
				infoL = 50
			}
			for p, b := range infoOf(repoPath, stanza, "i") {
				pick(p, b, infoL, 80)
			}
			lo, gap := 1+rng.IntN(8), 0
			if rng.IntN(4) == 0 {
				gap = lo + 1 + rng.IntN(3)
			}
			for n := 1; n <= 12; n++ {
				if n >= lo && n != gap && pl > 0 {
					c.local[walPath(repoPath, stanza, n)] = "w"
				}
				if rng.IntN(100) < 60 {
					c.target[walPath(repoPath, stanza, n)] = "w"
				}
			}
			if rng.IntN(2) == 0 {
				c.r.walOK = append(c.r.walOK, repoPath+"/"+stanza)
			}
		}
		age := time.Duration(rng.IntN(30)) * day
		for p := range c.target {
			if strings.HasPrefix(p, repoPath+"/") {
				c.mod[p] = matrixNow.Add(-age)
			}
		}
	}
	for _, age := range []time.Duration{day, 10 * day, 29 * day, 31 * day, 40 * day, 60 * day} {
		pick(snapAt(age), "s", 50, 50)
		pick(dumpAt(age), "d", 50, 50)
	}
	for _, n := range []string{"x1", "x2", "x3", "x4"} {
		pick(escrowOf(n), "e", 60, 60)
	}
	if rng.IntN(3) > 0 {
		c.r.listed = true
		for _, n := range []string{"x1", "x2", "x3", "x4"} {
			if rng.IntN(2) == 0 {
				c.r.escrow = append(c.r.escrow, escrowOf(n))
			}
		}
		c.r.suspicious = rng.IntN(4) == 0
		switch rng.IntN(3) {
		case 1:
			c.r.destroyed = map[string]time.Time{"o1/d1": matrixNow.Add(-c.r.keep / 2)}
		case 2:
			c.r.destroyed = map[string]time.Time{"o1/d1": matrixNow.Add(-c.r.keep - day)}
		}
		c.r.copied = map[string]time.Time{}
		for _, n := range []string{"x1", "x2", "x3", "x4"} {
			switch rng.IntN(4) {
			case 1:
				c.r.copied[escrowOf(n)] = matrixNow.Add(-time.Hour)
			case 2, 3:
				c.r.copied[escrowOf(n)] = matrixNow.Add(-c.r.keep - 2*day)
			}
		}
	}
	if rng.IntN(6) == 0 {
		c.target["pgbackrest/bk-20000101-deadbeef/backup/paddock/backup.info"] = "u"
	}
	if rng.IntN(10) == 0 {
		c.target["notes/readme.txt"] = "n"
	}
	return c
}

// expectation is the oracle of the invariants: shrunk, unknown path, and every object the target may lose.
type expectation struct {
	shrunk, unknown bool
	deletable       map[string]bool
}

func countNewer(local set, repoPath, stanza, label string) (newer, all int) {
	for p := range local {
		rest, ok := strings.CutPrefix(p, repoPath+"/backup/"+stanza+"/")
		if !ok {
			continue
		}
		l, file, _ := strings.Cut(rest, "/")
		if file == fullManifest {
			all++
			if l > label {
				newer++
			}
		}
	}
	return newer, all
}

func lowestSeg(local set, repoPath, stanza string) string {
	low := ""
	for p := range local {
		if strings.HasPrefix(p, repoPath+"/archive/"+stanza+"/18-1/") {
			s := filepath.Base(p)[:24]
			if low == "" || s < low {
				low = s
			}
		}
	}
	return low
}

func expect(c randomCase) expectation {
	e := expectation{deletable: map[string]bool{}}
	holds := func(repoPath string) bool {
		for p := range c.local {
			if strings.HasPrefix(p, repoPath+"/") {
				return true
			}
		}
		return false
	}
	full := max(c.r.full, 1)
	aComplete := true
	for _, stanza := range []string{"paddock", "authentik"} {
		if _, all := countNewer(c.local, pathA, stanza, ""); all == 0 {
			aComplete = false
		}
	}
	dropOld := false
	if !holds(pathOld) && aComplete {
		base := c.r.retired[pathOld]
		for p := range c.target {
			if strings.HasPrefix(p, pathOld+"/") && c.mod[p].After(base) {
				base = c.mod[p]
			}
		}
		dropOld = matrixNow.Sub(base) > c.r.keep
	}
	newest := map[string]string{}
	for p := range c.target {
		for _, dir := range []string{"openbao/", "fleet/"} {
			if strings.HasPrefix(p, dir) && p > newest[dir] {
				newest[dir] = p
			}
		}
	}
	for p := range c.target {
		if _, ok := c.local[p]; ok {
			continue
		}
		parts := strings.Split(p, "/")
		switch parts[0] {
		case "pgbackrest":
			repoPath := "pgbackrest/" + parts[1]
			switch {
			case repoPath != pathA && repoPath != pathOld:
				if !holds(repoPath) {
					e.unknown = true
				}
				continue
			case !holds(repoPath):
				if repoPath == pathA {
					e.shrunk = true
				}
				if repoPath == pathOld && dropOld {
					e.deletable[p] = true
				}
				continue
			}
			area, stanza := parts[2], parts[3]
			name := parts[len(parts)-1]
			switch {
			case len(parts) == 5 && strings.Contains(name, ".info"):
				base := strings.TrimSuffix(name, ".copy")
				dir := repoPath + "/" + area + "/" + stanza + "/"
				_, a := c.local[dir+base]
				_, b := c.local[dir+base+".copy"]
				if !a && !b {
					e.shrunk = true
				}
			case area == "backup":
				newer, _ := countNewer(c.local, repoPath, stanza, parts[4])
				if newer >= full {
					e.deletable[p] = true
				} else if name == fullManifest && len(parts) == 6 {
					e.shrunk = true
				}
			case area == "archive":
				_, all := countNewer(c.local, repoPath, stanza, "")
				low := lowestSeg(c.local, repoPath, stanza)
				if all >= full && low != "" && name[:24] < low && slices.Contains(c.r.walOK, repoPath+"/"+stanza) {
					e.deletable[p] = true
				}
			}
		case "openbao", "fleet":
			dir := parts[0] + "/"
			at, _ := time.Parse("20060102T150405Z", parts[1][:16])
			if p != newest[dir] && matrixNow.Sub(at) > c.r.kindKeep && len(under(c.local, dir)) > 0 {
				e.deletable[p] = true
			}
		case "escrow":
			at, destroyed := c.r.destroyed["o1/d1"]
			copied, recorded := c.r.copied[p]
			if c.r.listed && !c.r.suspicious && !slices.Contains(c.r.escrow, p) && destroyed &&
				recorded && !copied.After(at) && matrixNow.Sub(at) > c.r.keep {
				e.deletable[p] = true
			}
		}
	}
	return e
}

// TestMirrorInvariants: 200 random local sets and targets; I1–I7 of A3 hold and every delete satisfies its D rule.
// The oracle (expect) states the rules from the plan, not from the implementation.
func TestMirrorInvariants(t *testing.T) {
	t.Run("G2 an info file the local set lacks", func(t *testing.T) {
		target := with(completeA(label1), walOf(pathA, "paddock", 1))
		for name, c := range map[string]struct {
			drop   []string
			shrunk bool
		}{
			"both lost":     {[]string{"backup.info", "backup.info.copy"}, true},
			"the copy kept": {[]string{"backup.info"}, false},
		} {
			t.Run(name, func(t *testing.T) {
				local := with(target)
				for _, f := range c.drop {
					delete(local, pathA+"/backup/paddock/"+f)
				}
				repo, idx := localSet(t, local)
				dst := targetOf(t, target, matrixNow.Add(-day), false)
				_, err := runMirror(repo, idx, dst, defaultRules())
				if errors.Is(err, errSetShrunk) != c.shrunk {
					t.Errorf("error %v, want shrunk %v", err, c.shrunk)
				}
			})
		}
	})
	rng := rand.New(rand.NewPCG(7, 2026))
	seen := map[string]int{}
	for i := range 200 {
		c := randomSet(rng)
		want := expect(c)
		switch {
		case want.shrunk:
			seen["shrunk"]++
		case want.unknown:
			seen["unknown"]++
		case len(want.deletable) > 0:
			seen["deletes"]++
			for p := range want.deletable {
				seen[strings.SplitN(p, "/", 2)[0]]++
				if strings.Contains(p, "/archive/") {
					seen["wal"]++
				}
				if strings.HasPrefix(p, pathOld+"/") && c.local[pathOld+"/backup/paddock/backup.info"] == "" {
					seen["retired path"]++
				}
			}
		}
		var deletes [2][]string
		for v, bare := range []bool{c.bare, !c.bare} {
			repo, idx := localSet(t, c.local)
			dst := &opsTarget{memTarget: targetOf(t, c.target, matrixNow, bare)}
			maps.Copy(dst.mod, c.mod)
			before := maps.Clone(dst.files)
			_, err := runMirror(repo, idx, dst, c.r)
			fail := func(format string, args ...any) {
				t.Helper()
				t.Errorf("case %d (manifest variant %d): %s\nlocal %v\ntarget %v\ncalls %v", i, v,
					fmt.Sprintf(format, args...), under(c.local, ""), under(c.target, ""), dst.calls)
			}
			for _, call := range dst.calls {
				if p, ok := strings.CutPrefix(call, "read "); ok && p != backupset.ManifestPath {
					fail("I7: read %s", p)
				}
			}
			switch {
			case want.shrunk:
				if !errors.Is(err, errSetShrunk) || len(dst.ops) != 0 || !sameFiles(dst.files, before) {
					fail("I1/I6: want set_shrunk without a change, got %v, ops %v", err, dst.ops)
				}
				continue
			case want.unknown:
				if ErrorClass(err) != ClassUnknownPath {
					fail("want unknown_path, got %v", err)
				}
			case err != nil:
				fail("I5: error %v", err)
			}
			secondList, lists := -1, 0
			for j, call := range dst.calls {
				if call == "list" {
					if lists++; lists == 2 {
						secondList = j
					}
				}
				if strings.HasPrefix(call, "delete ") && (secondList < 0 || j < secondList) {
					fail("I2: %s before the verify listing", call)
				}
			}
			got := opsOf(dst.memTarget, "delete")
			deletes[v] = got
			for _, p := range got {
				if !want.deletable[p] {
					fail("I4: deleted %s against its rule", p)
				}
			}
			if !c.r.noManifest {
				for p := range want.deletable {
					if !slices.Contains(got, p) {
						fail("kept %s although the local expire would have removed it", p)
					}
				}
			} else if len(got) != 0 {
				fail("deleted %v in a round without deletes", got)
			}
			if _, ok := dst.files["notes/readme.txt"]; c.target["notes/readme.txt"] != "" && !ok {
				fail("D7: a path outside the set was touched")
			}
			for p, body := range c.local {
				if string(dst.files[p]) != body {
					fail("the target lacks %s", p)
				}
			}
		}
		if !slices.Equal(deletes[0], deletes[1]) {
			t.Errorf("case %d: I3: the target's manifest changed the deletes: %v vs %v", i, deletes[0], deletes[1])
		}
	}
	// The random cases must reach every rule, else the invariants hold vacuously.
	for _, k := range []string{"shrunk", "unknown", "deletes", "pgbackrest", "wal", "retired path", "openbao", "fleet",
		"escrow"} {
		if seen[k] < 3 {
			t.Errorf("only %d random cases of %q: %v", seen[k], k, seen)
		}
	}
	t.Logf("random cases: %v", seen)
}

// TestRoundRepoLostLeavesEveryTargetIntact: through Engine.Round with two targets, the repository volume is lost
// (L1: pgBackRest reports failed fulls) and then both volumes are lost (L3: a new full in an empty repository). Both
// targets keep every byte, every run records set_shrunk for both, and paddock_backup_target_reachable is 0.
func TestRoundRepoLostLeavesEveryTargetIntact(t *testing.T) {
	f := newFixture(t)
	f.confirmKey()
	writeRepo := func(s set) {
		t.Helper()
		for p, body := range s {
			full := filepath.Join(f.cfg.RepoDir, p)
			if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(full, []byte(body), 0o640); err != nil {
				t.Fatal(err)
			}
		}
	}
	marker := func(stanza, name string, at time.Time) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(f.cfg.StateDir, stanza, name), []byte(strconvUnix(at)), 0o640); err != nil {
			t.Fatal(err)
		}
	}
	writeRepo(with(completeA(label1), completeA(label2), walOf(pathA, "paddock", span(1, 4)...)))
	var dsts []*memTarget
	var recs []TargetRecord
	for range 2 {
		dst := newMemTarget()
		dst.now = func() time.Time { return f.now }
		recs = append(recs, f.addTarget(t, backupset.TypeS3, dst))
		dsts = append(dsts, dst)
	}
	f.round(t)
	var before []map[string][]byte
	for i, dst := range dsts {
		if _, ok := dst.files[pathA+"/backup/paddock/"+label2+"/"+fullManifest]; !ok {
			t.Fatalf("target %d lacks the set before the loss: %v", i, dst.ops)
		}
		before = append(before, maps.Clone(dst.files))
	}
	check := func(when string) {
		t.Helper()
		for i, dst := range dsts {
			if !sameFiles(dst.files, before[i]) {
				t.Errorf("%s: target %d changed", when, i)
			}
			if v := testutil.ToFloat64(f.metrics.reachable.WithLabelValues(recs[i].Name)); v != 0 {
				t.Errorf("%s: paddock_backup_target_reachable of target %d = %v", when, i, v)
			}
		}
		if len(f.store.runs) == 0 {
			t.Fatalf("%s: no run recorded", when)
		}
		for _, r := range f.store.runs {
			if len(r.Targets) != 2 {
				t.Errorf("%s: %s run targets %+v", when, r.Kind, r.Targets)
			}
			for _, rt := range r.Targets {
				if rt.OK || rt.ErrorClass != ClassSetShrunk {
					t.Errorf("%s: %s run target %+v, want set_shrunk", when, r.Kind, rt)
				}
			}
		}
	}

	if err := os.RemoveAll(filepath.Join(f.cfg.RepoDir, "pgbackrest")); err != nil {
		t.Fatal(err)
	}
	f.now = f.now.Add(time.Hour)
	marker("paddock", "last-error", f.now)
	f.store.runs = nil
	f.round(t)
	check("repository lost")

	for _, stanza := range []string{"paddock", "authentik"} {
		for _, name := range []string{"last-error", "last-full", "verify-ok"} {
			_ = os.RemoveAll(filepath.Join(f.cfg.StateDir, stanza, name))
		}
	}
	f.now = f.now.Add(time.Hour)
	writeRepo(completeA(label9))
	marker("paddock", "last-full", f.now)
	f.store.runs = nil
	f.round(t)
	check("both volumes lost")
}
