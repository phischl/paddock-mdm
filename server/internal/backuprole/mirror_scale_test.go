package backuprole

import (
	"context"
	"errors"
	"fmt"
	"io"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/server/internal/domain/backupset"
)

// largeSet returns a local index of the active repository path with fulls completed full backups of files data files
// per stanza, and a target listing holding that set plus expired completed full backups of the same size and WAL
// below the local archive, which the target holds and the local set lacks: the shape of a set after a day of
// two-minute full backups (PDK-861).
func largeSet(fulls, expired, files int) (repoIndex, map[string]int64, int) {
	repo := backupset.RepoPath(testKeyID)
	idx := repoIndex{backupset.ManifestPath: {size: 1}}
	have := map[string]int64{backupset.ManifestPath: 1}
	targetOnly := 0
	at := time.Date(2026, 11, 6, 0, 0, 0, 0, time.UTC)
	for _, stanza := range []string{"paddock", "authentik"} {
		for i := range expired + fulls {
			label := at.Add(time.Duration(i)*time.Hour).Format("20060102-150405") + "F"
			dir := repo + "/backup/" + stanza + "/" + label + "/"
			paths := []string{dir + fullManifest}
			for j := range files {
				paths = append(paths, fmt.Sprintf("%spg_data/base/%d.gz", dir, j))
			}
			for _, p := range paths {
				have[p] = 1
				if i < expired {
					targetOnly++
				} else {
					idx[p] = fileInfo{size: 1}
				}
			}
		}
		for i := range 64 {
			p := fmt.Sprintf("%s/archive/%s/16-1/0000000100000000/0000000100000000000000%02X-%040d.gz", repo, stanza, i, 0)
			have[p] = 1
			if i < 32 {
				targetOnly++
			} else {
				idx[p] = fileInfo{size: 1}
			}
		}
		info := repo + "/backup/" + stanza + "/backup.info"
		idx[info], have[info] = fileInfo{size: 1}, 1
	}
	return idx, have, targetOnly
}

// TestGuardAndJudgeScaleLinearly: the guard and the delete verdicts of a set with 200 000 local files and 100 000
// objects only the target holds finish in well under the stall deadline. Asking the index per object took hours of
// CPU on such a set, so every mirror stalled and its goroutine kept spinning after the watchdog gave up (PDK-861).
func TestGuardAndJudgeScaleLinearly(t *testing.T) {
	idx, have, targetOnly := largeSet(4, 2, 25_000)
	ret := testRetention(time.Date(2026, 11, 7, 0, 0, 0, 0, time.UTC))
	ret.walOK[backupset.RepoPath(testKeyID)+"/paddock"] = true
	ret.walOK[backupset.RepoPath(testKeyID)+"/authentik"] = true
	start := time.Now()
	facts := newIndexFacts(idx)
	plan, err := guard(context.Background(), newMemTarget(), facts, have, ret)
	if err != nil {
		t.Fatalf("guard: %v", err)
	}
	held, drop, err := judge(context.Background(), facts, plan, ret, have, have)
	if err != nil {
		t.Fatalf("judge: %v", err)
	}
	if took := time.Since(start); took > 10*time.Second {
		t.Errorf("guard and judge took %s", took)
	}
	if held != 0 || len(drop) != targetOnly {
		t.Errorf("held %d, drop %d; want 0 and %d", held, len(drop), targetOnly)
	}
}

// TestGuardAndJudgeStopWithTheirContext: once the mirror's context ended (the stall watchdog gave up), the guard and
// the verdicts return at once instead of finishing their scan while the target stays busy (PDK-861).
func TestGuardAndJudgeStopWithTheirContext(t *testing.T) {
	idx, have, _ := largeSet(4, 2, 1_000)
	ret := testRetention(time.Date(2026, 11, 7, 0, 0, 0, 0, time.UTC))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	facts := newIndexFacts(idx)
	if _, err := guard(ctx, newMemTarget(), facts, have, ret); !errors.Is(err, context.Canceled) {
		t.Errorf("guard: %v, want context.Canceled", err)
	}
	plan := guardPlan{drop: map[string]bool{}, hold: map[string]bool{}}
	if _, drop, err := judge(ctx, facts, plan, ret, have, have); !errors.Is(err, context.Canceled) || drop != nil {
		t.Errorf("judge: %v, drop %d; want context.Canceled and nothing to delete", err, len(drop))
	}
}

// stallingTarget is a target whose Put blocks until its context ends while stall is set, as an S3 endpoint that
// accepts the connection and then sends nothing; it counts the calls of a mirror.
type stallingTarget struct {
	*memTarget
	mu    sync.Mutex
	stall atomic.Bool
	calls map[string]int
}

func (s *stallingTarget) count(op string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls[op]++
}

func (s *stallingTarget) counted(op string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls[op]
}

func (s *stallingTarget) Read(ctx context.Context, p string) ([]byte, bool, error) {
	s.count("read")
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.memTarget.Read(ctx, p)
}

func (s *stallingTarget) List(ctx context.Context) (map[string]int64, error) {
	s.count("list")
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.memTarget.List(ctx)
}

func (s *stallingTarget) Put(ctx context.Context, p string, r io.Reader, size int64) error {
	s.count("put")
	if s.stall.Load() {
		<-ctx.Done()
		return ctx.Err()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.memTarget.Put(ctx, p, r, size)
}

// TestStalledMirrorEndsCleanly: a target that stalls fails the round's mirror with io after the stall deadline; the
// mirror's goroutine returns, the target is no longer busy, no goroutine is left behind, and the stalled mirror made
// exactly one attempt (no retry loop). The next round mirrors the recovered target (PDK-861).
func TestStalledMirrorEndsCleanly(t *testing.T) {
	f := newFixture(t)
	f.confirmKey()
	f.engine.stall = 50 * time.Millisecond
	dst := &stallingTarget{memTarget: newMemTarget(), calls: map[string]int{}}
	dst.stall.Store(true)
	rec := f.addTarget(t, backupset.TypeS3, dst)
	baseline := runtime.NumGoroutine()
	f.round(t)
	r, ok := f.store.run(KindOpenBao)
	if !ok {
		t.Fatal("no run recorded")
	}
	for _, rt := range r.Targets {
		if rt.TargetID == rec.ID.String() && (rt.OK || rt.ErrorClass != ClassIO) {
			t.Errorf("stalled target %+v, want io", rt)
		}
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		f.engine.busyMu.Lock()
		busy := f.engine.busy[rec.ID]
		f.engine.busyMu.Unlock()
		if n := runtime.NumGoroutine(); !busy && n <= baseline {
			break
		} else if time.Now().After(deadline) {
			t.Fatalf("busy %v, goroutines %d, want not busy and at most %d", busy, n, baseline)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if got := [3]int{dst.counted("read"), dst.counted("list"), dst.counted("put")}; got != [3]int{1, 1, 1} {
		t.Errorf("read, list, put calls %v during the stalled mirror, want one each", got)
	}
	dst.stall.Store(false)
	f.round(t)
	dst.mu.Lock()
	_, mirrored := dst.files[backupset.ManifestPath]
	dst.mu.Unlock()
	if !mirrored {
		t.Error("the recovered target got no manifest next round")
	}
}
