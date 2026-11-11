package backuprole

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/server/internal/domain/backupset"
)

// devSchedule is the default schedule: 14 fulls, one a day.
var devSchedule = backupset.Schedule{FullIntervalHours: 24, RetentionFull: 14, OpenBaoKeepDays: 30, FleetKeepDays: 30}

// rotatedKeys is the active test key and the retired key of pathOld, retired at retiredAt.
func rotatedKeys(retiredAt time.Time) []KeyRecord {
	return []KeyRecord{{ID: testKeyID, State: "confirmed"},
		{ID: strings.TrimPrefix(pathOld, backupset.RepoPath("")), State: "retired", RetiredAt: retiredAt}}
}

// TestRetiredKeepFollowsEffectiveFullInterval: a retired key's repository is kept retention_full full intervals, and
// the interval is the one pgBackRest runs at: the development override when set, else the schedule's (decisions-alpha10
// A10-25). Before, the keep window ignored the override, so the development stack kept every retired repository 14
// days while it took a full every 20 minutes.
func TestRetiredKeepFollowsEffectiveFullInterval(t *testing.T) {
	f := newFixture(t)
	if got := f.engine.retention(testKeyID, nil, devSchedule, escrowRule{}).keep; got != 14*24*time.Hour {
		t.Errorf("keep %s without an override, want 336h", got)
	}
	f.engine.cfg.FullInterval = 20 * time.Minute
	if got := f.engine.retention(testKeyID, nil, devSchedule, escrowRule{}).keep; got != 14*20*time.Minute {
		t.Errorf("keep %s with a 20-minute full interval, want 4h40m", got)
	}
}

// keyPathTarget is a target kind the retired-path rule must hold on, filled with s whose files are age old.
type keyPathTarget struct {
	name string
	make func(t *testing.T, s set, mod time.Time) (Target, func(p string) bool)
}

func keyPathTargets() []keyPathTarget {
	return []keyPathTarget{
		{"s3", func(t *testing.T, s set, _ time.Time) (Target, func(string) bool) {
			// The fake bucket reports no newest file, so retired_at alone is the age base.
			store := &slowListS3{objects: map[string]string{}}
			for p, body := range s {
				store.objects["site/"+backupset.SetRoot+"/"+p] = body
			}
			return NewS3Target(store, "site"), func(p string) bool {
				store.mu.Lock()
				defer store.mu.Unlock()
				_, ok := store.objects["site/"+backupset.SetRoot+"/"+p]
				return ok
			}
		}},
		{"directory", func(t *testing.T, s set, at time.Time) (Target, func(string) bool) {
			root := filepath.Join(t.TempDir(), "mount", backupset.SetRoot)
			for p, body := range s {
				full := filepath.Join(root, filepath.FromSlash(p))
				if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(full, []byte(body), 0o640); err != nil {
					t.Fatal(err)
				}
				if err := os.Chtimes(full, at, at); err != nil {
					t.Fatal(err)
				}
			}
			return NewDirTarget(root), func(p string) bool {
				_, err := os.Stat(filepath.Join(root, filepath.FromSlash(p)))
				return err == nil
			}
		}},
	}
}

// TestRetiredPathPruning: with the development full interval of 20 minutes (keep 4h40m), the previous key's
// repository leaves an S3 and a directory target only once the active repository holds a completed full of every
// stanza and the retired path is older than the keep window; the active repository is never touched.
func TestRetiredPathPruning(t *testing.T) {
	for _, kind := range keyPathTargets() {
		for name, c := range map[string]struct {
			local   set
			retired time.Duration
			pruned  bool
		}{
			"replacement without a full, past the window": {newRepo(), 5 * time.Hour, false},
			"replacement complete, inside the window":     {completeA(label9), 4 * time.Hour, false},
			"replacement complete, past the window":       {completeA(label9), 5 * time.Hour, true},
		} {
			t.Run(kind.name+"/"+name, func(t *testing.T) {
				f := newFixture(t)
				f.engine.cfg.FullInterval = 20 * time.Minute
				ret := f.engine.retention(testKeyID, rotatedKeys(f.now.Add(-c.retired)), devSchedule, escrowRule{})
				ret.manifestOK = true
				repo, idx := localSet(t, c.local)
				onTarget := with(c.local, oldRepo())
				dst, has := kind.make(t, onTarget, f.now.Add(-c.retired))
				if _, err := mirrorSet(context.Background(), repo, idx, dst, map[string]fileInfo{}, ret,
					noHooks()); err != nil {
					t.Fatal(err)
				}
				for _, p := range under(oldRepo(), "") {
					if has(p) == c.pruned {
						t.Errorf("%s on the target: %v, want pruned %v", p, has(p), c.pruned)
					}
				}
				for _, p := range under(c.local, pathA+"/") {
					if !has(p) {
						t.Errorf("the active repository lost %s", p)
					}
				}
			})
		}
	}
}

// TestLocalExpireKeepsActiveAndIncompleteReplacement: the role's local expire never removes the active repository,
// however old its files, and removes a retired repository past the keep window only once the active repository holds
// a completed full of every stanza.
func TestLocalExpireKeepsActiveAndIncompleteReplacement(t *testing.T) {
	for name, c := range map[string]struct {
		active set
		pruned bool
	}{"replacement without a full": {newRepo(), false}, "replacement complete": {completeA(label9), true}} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			f.engine.cfg.FullInterval = 20 * time.Minute
			ret := f.engine.retention(testKeyID, rotatedKeys(f.now.Add(-5*time.Hour)), devSchedule, escrowRule{})
			repo, idx := localSet(t, with(c.active, oldRepo()))
			old := f.now.Add(-30 * 24 * time.Hour)
			for p := range idx {
				if err := repo.Chtimes(p, old, old); err != nil {
					t.Fatal(err)
				}
				e := idx[p]
				e.mod = old
				idx[p] = e
			}
			f.engine.expire(context.Background(), repo, idx, ret, nil)
			_, err := repo.Stat(pathOld)
			if pruned := os.IsNotExist(err); pruned != c.pruned {
				t.Errorf("retired repository pruned %v, want %v (%v)", pruned, c.pruned, err)
			}
			for _, p := range under(c.active, pathA+"/") {
				if _, err := repo.Stat(p); err != nil {
					t.Errorf("the active repository lost %s: %v", p, err)
				}
			}
		})
	}
}
