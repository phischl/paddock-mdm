package backuprole

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/phischl/paddock-mdm/server/internal/domain/backupset"
)

// hangingTarget is a target whose listing hangs until release is closed or its context ends, as a live S3 endpoint
// whose pages take up to 20 minutes each (RR-132); its connection test answers at once. lists counts the listings.
type hangingTarget struct {
	*memTarget
	entered chan struct{}
	release chan struct{}
	lists   atomic.Int32
}

func newHangingTarget() *hangingTarget {
	return &hangingTarget{memTarget: newMemTarget(), entered: make(chan struct{}, 16), release: make(chan struct{})}
}

func (h *hangingTarget) List(ctx context.Context) (map[string]int64, error) {
	h.lists.Add(1)
	h.entered <- struct{}{}
	select {
	case <-h.release:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return h.memTarget.List(ctx)
}

func (h *hangingTarget) Probe(context.Context) error { return nil }

// statusOf reads a target's status of kind under the fake store's lock: lanes write it while the test runs.
func (s *fakeStore) statusOf(id uuid.UUID, kind string) (KindStatus, bool) {
	s.runsMu.Lock()
	defer s.runsMu.Unlock()
	st, ok := s.status[id.String()+"/"+kind]
	return st, ok
}

// runOf returns the n-th a recorded run under the fake store's lock.
func (s *fakeStore) runOf(kind string, n int) (fakeRun, bool) {
	s.runsMu.Lock()
	defer s.runsMu.Unlock()
	for _, r := range s.runs {
		if r.Kind == kind {
			if n == 0 {
				return r, true
			}
			n--
		}
	}
	return fakeRun{}, false
}

func (s *fakeStore) duplicateWrites() int {
	s.runsMu.Lock()
	defer s.runsMu.Unlock()
	return s.duplicates
}

// roundWithin runs one round and fails the test when it does not return within a minute: a round held by a lane would
// never return while the lane hangs.
func roundWithin(t *testing.T, f *fixture) {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- f.engine.Round(context.Background()) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("round: %v", err)
		}
	case <-time.After(time.Minute):
		t.Fatal("the round waited for a mirror lane")
	}
}

func waitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestHangingLaneDoesNotDelayTheRound: while one target's mirror hangs in its listing, the next round still takes a
// requested OpenBao snapshot, hands a newly confirmed key to pgBackRest, answers the connection test of the hanging
// target with the test's own result, and starts no second mirror to that target (decisions-alpha10 A10-26; before,
// PDK-989: one slow listing held every request and key confirmation for as long as it ran). With every target busy,
// the round settles nothing: the requested run waits for the target's next lane, which copies it and records ok
// (PDK-989 review 1, B1).
func TestHangingLaneDoesNotDelayTheRound(t *testing.T) {
	f := newFixture(t)
	f.confirmKey()
	f.engine.stall = time.Hour
	slow := newHangingTarget()
	released := false
	t.Cleanup(func() {
		if !released {
			close(slow.release)
		}
		f.engine.waitLanes()
	})
	rec := f.addTarget(t, backupset.TypeS3, slow)
	roundWithin(t, f)
	<-slow.entered
	snaps := f.snap.calls

	f.now = f.now.Add(time.Minute)
	req := RequestedRun{ID: uuid.New(), Kind: KindOpenBao, Label: "now", CreatedAt: f.now}
	f.store.requests = []RequestedRun{req}
	const rotated = "bk-20261104-0a1b2c3d"
	f.store.key = &ActiveKey{ID: rotated, Ciphertext: "vault:v1:key", Fingerprint: backupset.Fingerprint(testKey)}
	f.store.targets[0].TestRequested = true
	roundWithin(t, f)

	if f.snap.calls != snaps+1 || f.store.answers(req.ID) != 1 {
		t.Errorf("snapshots %d (want %d), answers of the request %d (want 1)", f.snap.calls, snaps+1,
			f.store.answers(req.ID))
	}
	env, err := os.ReadFile(filepath.Join(f.cfg.RuntimeDir, scheduleFileName))
	if err != nil || !strings.Contains(string(env), backupset.RepoPath(rotated)) {
		t.Errorf("schedule.env after the key change: %q %v", env, err)
	}
	if class, ok := f.store.tests[rec.ID]; !ok || class != "" {
		t.Errorf("connection test of the hanging target: %q (answered %v), want a pass", class, ok)
	}
	if n := slow.lists.Load(); n != 1 {
		t.Errorf("listings of the hanging target %d, want 1: one lane per target", n)
	}
	// The requested run's pass began while the lane mirrored the earlier set: it waits for the target's next lane.
	r, ok := f.store.runOf(KindOpenBao, 1)
	if !ok || r.mirrored {
		t.Errorf("requested run beside the hanging lane: %+v (recorded %v), want recorded and waiting", r, ok)
	}
	// The first round's run waits for its lane: its results are recorded only when the lane ends.
	if r, _ := f.store.runOf(KindOpenBao, 0); r.mirrored {
		t.Errorf("the first run got mirror results before its lane ended: %+v", r)
	}
	if _, ok := f.store.statusOf(rec.ID, KindOpenBao); ok {
		t.Error("the hanging target got a status before its lane ended")
	}

	released = true
	close(slow.release)
	f.engine.waitLanes()
	if r, _ := f.store.runOf(KindOpenBao, 1); r.mirrored {
		t.Errorf("the requested run got the results of a lane whose set lacks it: %+v", r)
	}
	f.now = f.now.Add(time.Minute)
	f.store.requests = nil
	f.store.targets[0].TestRequested = false
	f.round(t)
	for i := range 2 {
		r, _ := f.store.runOf(KindOpenBao, i)
		if !r.mirrored || len(r.Targets) != 1 || !r.Targets[0].OK {
			t.Errorf("run %d after the lanes: %+v, want mirrored ok (no targets_failed)", i, r)
		}
	}
	if n := f.store.duplicateWrites(); n != 0 {
		t.Errorf("%d runs got their mirror results twice", n)
	}
}

// TestSlowTargetDoesNotHoldTheFastOne: with one target hanging and one fast, the fast target is mirrored in every
// round and its status and metrics are current; the slow lane's run gets its results when that lane ends, and a later
// run, recorded while the slow lane ran, waits for the slow target's next lane and then is ok on both, once
// (decisions-alpha10 A10-26; PDK-989 review 1, B1).
func TestSlowTargetDoesNotHoldTheFastOne(t *testing.T) {
	f := newFixture(t)
	f.confirmKey()
	f.engine.stall = time.Hour
	slow := newHangingTarget()
	slowRec := f.addTarget(t, backupset.TypeS3, slow)
	fast := newMemTarget()
	fastRec := f.addTarget(t, backupset.TypeS3, fast)
	roundWithin(t, f)
	<-slow.entered
	waitFor(t, "the fast target's status", func() bool {
		st, ok := f.store.statusOf(fastRec.ID, KindOpenBao)
		return ok && st.Error == "" && !st.LastSuccess.IsZero()
	})
	// The lane writes the status before it publishes the gauges, so the end of the lane is what the gauge waits for
	// (PDK-1006).
	waitFor(t, "the fast target's lane", func() bool {
		f.engine.laneMu.Lock()
		defer f.engine.laneMu.Unlock()
		return f.engine.lanes[fastRec.ID] == nil
	})
	if _, ok := fast.files[backupset.ManifestPath]; !ok {
		t.Fatal("the fast target got no manifest")
	}
	if got := testutil.ToFloat64(f.metrics.reachable.WithLabelValues(fastRec.Name)); got != 1 {
		t.Errorf("fast target reachable %v, want 1", got)
	}

	f.now = f.now.Add(time.Minute)
	req := RequestedRun{ID: uuid.New(), Kind: KindOpenBao, CreatedAt: f.now}
	f.store.requests = []RequestedRun{req}
	roundWithin(t, f)
	f.store.requests = nil
	waitFor(t, "the fast target's second mirror", func() bool {
		f.engine.laneMu.Lock()
		defer f.engine.laneMu.Unlock()
		return f.engine.lanes[fastRec.ID] == nil
	})
	if r, _ := f.store.runOf(KindOpenBao, 1); r.mirrored {
		t.Errorf("second run mirrored before the slow target's next lane: %+v", r)
	}
	if first, _ := f.store.runOf(KindOpenBao, 0); first.mirrored {
		t.Errorf("first run mirrored before the slow lane ended: %+v", first)
	}

	close(slow.release)
	f.engine.waitLanes()
	first, _ := f.store.runOf(KindOpenBao, 0)
	if !first.mirrored || len(first.Targets) != 2 {
		t.Fatalf("first run after the slow lane ended: %+v", first)
	}
	for _, rt := range first.Targets {
		if !rt.OK {
			t.Errorf("first run target %+v, want ok", rt)
		}
	}
	if st, _ := f.store.statusOf(slowRec.ID, KindOpenBao); st.Error != "" || st.LastSuccess.IsZero() {
		t.Errorf("slow target status after its lane %+v", st)
	}
	f.now = f.now.Add(time.Minute)
	f.round(t)
	second, _ := f.store.runOf(KindOpenBao, 1)
	if !second.mirrored || len(second.Targets) != 2 {
		t.Fatalf("second run after the slow target's next lane: %+v", second)
	}
	for _, rt := range second.Targets {
		if !rt.OK {
			t.Errorf("second run target %+v, want ok", rt)
		}
	}
	if n := f.store.duplicateWrites(); n != 0 {
		t.Errorf("%d runs got their mirror results twice", n)
	}
}

// TestShutdownCancelsLanesAndRestartResumes: the end of Run's context cancels a hanging lane, Run returns, and the
// lane records neither a status nor mirror results; a restarted role mirrors the earlier run from the recorded state,
// with one result per run.
func TestShutdownCancelsLanesAndRestartResumes(t *testing.T) {
	f := newFixture(t)
	f.confirmKey()
	f.engine.stall = time.Hour
	slow := newHangingTarget()
	rec := f.addTarget(t, backupset.TypeS3, slow)
	ctx, cancel := context.WithCancel(context.Background())
	ran := make(chan error, 1)
	go func() { ran <- f.engine.Run(ctx) }()
	<-slow.entered
	cancel()
	select {
	case err := <-ran:
		if err != nil {
			t.Fatalf("run: %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("Run did not return after its context ended")
	}
	if r, ok := f.store.run(KindOpenBao); !ok || r.mirrored {
		t.Fatalf("run after the shutdown: %+v (recorded %v), want recorded without mirror results", r, ok)
	}
	if _, ok := f.store.statusOf(rec.ID, KindOpenBao); ok {
		t.Error("the cancelled lane wrote a target status")
	}
	if len(slow.files) != 0 {
		t.Errorf("the cancelled lane wrote %v", slow.files)
	}

	// The restarted role: a new engine on the same repository and database; the target answers now. The stopped
	// process's mirror call ends with it; here it shares the process, so the test waits for it to return.
	close(slow.release)
	stopped := f.engine
	waitFor(t, "the stopped engine's mirror call", func() bool {
		stopped.busyMu.Lock()
		defer stopped.busyMu.Unlock()
		return !stopped.busy[rec.ID]
	})
	f.engine = NewEngine(f.cfg, noLock{}, f.store, fakeKeys{}, f.snap, f.escrow, f.factory, f.metrics,
		func() time.Time { return f.now })
	f.now = f.now.Add(time.Minute)
	f.round(t)
	r, _ := f.store.run(KindOpenBao)
	if !r.mirrored || len(r.Targets) != 1 || !r.Targets[0].OK {
		t.Fatalf("earlier run after the restart: %+v", r)
	}
	if _, ok := slow.files[backupset.ManifestPath]; !ok {
		t.Error("the target got no manifest after the restart")
	}
	if n := f.store.duplicateWrites(); n != 0 {
		t.Errorf("%d runs got their mirror results twice", n)
	}
}

// TestLocalExpireWaitsForLane: the local expire keeps the files of a set a lane still mirrors, both an expired
// snapshot and a retired key's repository past its keep window, and deletes them in the first round after the lane
// ended; the active repository is never touched (decisions-alpha10 A10-26, PDK-972 invariants).
func TestLocalExpireWaitsForLane(t *testing.T) {
	f := newFixture(t)
	f.confirmKey()
	f.engine.stall = time.Hour
	f.store.history[KindOpenBao] = KindHistory{LastAttempt: f.now, LastSuccess: f.now}
	f.store.history[KindFleet] = KindHistory{LastAttempt: f.now, LastSuccess: f.now}
	f.store.history[KindEscrow] = KindHistory{LastAttempt: f.now, LastSuccess: f.now}
	retiredID := strings.TrimPrefix(pathOld, backupset.RepoPath(""))
	f.store.keys = []KeyRecord{{ID: retiredID, State: "retired", RetiredAt: f.now.Add(-60 * 24 * time.Hour)}}
	old := f.now.Add(-60 * 24 * time.Hour)
	expired := backupset.OpenBaoKey(old)
	files := with(completeA(label9), oldRepo())
	files[expired] = "sealed"
	for p, body := range files {
		full := filepath.Join(f.cfg.RepoDir, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o640); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(full, old, old); err != nil {
			t.Fatal(err)
		}
	}
	// In the first round the snapshot is the newest of its kind and the retired repository inside its window, so both
	// stay and go into the lane's index.
	f.store.keys[0].RetiredAt = f.now
	slow := newHangingTarget()
	f.addTarget(t, backupset.TypeS3, slow)
	roundWithin(t, f)
	<-slow.entered

	// Now both are expired, the snapshot by a newer one, but the lane's index holds them.
	f.store.keys[0].RetiredAt = old
	f.now = f.now.Add(time.Minute)
	f.store.requests = []RequestedRun{{ID: uuid.New(), Kind: KindOpenBao, CreatedAt: f.now}}
	roundWithin(t, f)
	f.store.requests = nil
	exists := func(p string) bool {
		_, err := os.Stat(filepath.Join(f.cfg.RepoDir, filepath.FromSlash(p)))
		return err == nil
	}
	if !exists(expired) || !exists(pathOld) {
		t.Fatalf("the expire removed files of a lane in flight: snapshot %v, retired repository %v", exists(expired),
			exists(pathOld))
	}

	close(slow.release)
	f.engine.waitLanes()
	f.now = f.now.Add(time.Minute)
	f.round(t)
	if exists(expired) || exists(pathOld) {
		t.Errorf("after the lane: snapshot %v, retired repository %v, want both expired", exists(expired),
			exists(pathOld))
	}
	for _, p := range under(completeA(label9), pathA+"/") {
		if !exists(p) {
			t.Errorf("the active repository lost %s", p)
		}
	}
}

// TestLanePrunesOnlyByThePDK972Rules: the lane is the round's mirror, so a retired path leaves a target only past
// the keep window with a complete replacement, never the active path, and nothing leaves on a listing that failed
// part of the way (PDK-972 invariants, decisions-alpha10 A10-26).
func TestLanePrunesOnlyByThePDK972Rules(t *testing.T) {
	for name, c := range map[string]struct {
		local   set
		retired time.Duration
		failAt  bool
		pruned  bool
	}{
		"replacement without a full, past the window":         {newRepo(), 5 * time.Hour, false, false},
		"replacement complete, inside the window":             {completeA(label9), 4 * time.Hour, false, false},
		"replacement complete, past the window":               {completeA(label9), 5 * time.Hour, false, true},
		"replacement complete, past the window, partial list": {completeA(label9), 5 * time.Hour, true, false},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			f.engine.cfg.FullInterval = 20 * time.Minute
			ret := f.engine.retention(testKeyID, rotatedKeys(f.now.Add(-c.retired)), devSchedule, escrowRule{})
			ret.manifestOK = true
			repo, idx := localSet(t, c.local)
			f.engine.cfg.RepoDir = repo.Name()
			store := &slowListS3{objects: map[string]string{}}
			for p, body := range with(c.local, oldRepo()) {
				store.objects["site/"+backupset.SetRoot+"/"+p] = body
			}
			var s3 S3Store = store
			if c.failAt {
				s3 = &partialListS3{slowListS3: store}
			}
			rec := TargetRecord{ID: uuid.New(), Name: "t", Type: backupset.TypeS3, Enabled: true}
			f.factory[rec.ID] = NewS3Target(s3, "site")
			_, err := f.engine.mirrorLane(context.Background(), idx, rec, ret)
			if c.failAt != (err != nil) {
				t.Fatalf("lane: %v", err)
			}
			has := func(p string) bool {
				store.mu.Lock()
				defer store.mu.Unlock()
				_, ok := store.objects["site/"+backupset.SetRoot+"/"+p]
				return ok
			}
			for _, p := range under(oldRepo(), "") {
				if has(p) == c.pruned {
					t.Errorf("%s on the target: %v, want pruned %v", p, has(p), c.pruned)
				}
			}
			for _, p := range under(c.local, pathA+"/") {
				if !has(p) && !c.failAt {
					t.Errorf("the active repository lost %s", p)
				}
			}
		})
	}
}

// partialListS3 delivers one page of a listing and then fails, as an endpoint that drops the connection.
type partialListS3 struct{ *slowListS3 }

func (p *partialListS3) ListSizesPaged(_ context.Context, _ string, page func()) (map[string]int64, error) {
	page()
	return nil, errors.New("connection reset by peer")
}

// TestLaneEndingWithTheLeadershipFreesItsSlot: a lane whose mirror returned just before the leadership ended records
// nothing, but gives back its slot and its pin; and the end of a leadership clears every slot, so the next leadership
// starts a lane for the target and the local expire deletes again (PDK-989 review 2, MJ1). Before, the slot stayed:
// the target never got a lane again and the files of the dead lane's index were never expired.
func TestLaneEndingWithTheLeadershipFreesItsSlot(t *testing.T) {
	f := newFixture(t)
	f.confirmKey()
	for _, kind := range []string{KindOpenBao, KindFleet, KindEscrow} {
		f.store.history[kind] = KindHistory{LastAttempt: f.now, LastSuccess: f.now}
	}
	dst := newMemTarget()
	rec := f.addTarget(t, backupset.TypeS3, dst)
	expired, newer := backupset.OpenBaoKey(f.now.Add(-60*24*time.Hour)), backupset.OpenBaoKey(f.now.Add(-time.Hour))
	for _, p := range []string{expired, newer} {
		full := filepath.Join(f.cfg.RepoDir, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte("sealed"), 0o640); err != nil {
			t.Fatal(err)
		}
	}
	pin := repoIndex{expired: {size: 6}}
	exists := func() bool {
		_, err := os.Stat(filepath.Join(f.cfg.RepoDir, filepath.FromSlash(expired)))
		return err == nil
	}

	// settle after the leadership ended: nothing written, slot and pin released.
	l := &lane{idx: pin, ctx: context.Background(), cancel: func() {}}
	f.engine.lanes[rec.ID] = l
	ended, cancel := context.WithCancel(context.Background())
	cancel()
	f.engine.settle(ended, l, l.passes, rec, map[string]kindInfo{}, "", 0)
	if len(f.engine.lanes) != 0 || len(f.engine.pinned()) != 0 {
		t.Fatalf("after settle on an ended leadership: lanes %v, pins %d", f.engine.lanes, len(f.engine.pinned()))
	}
	if _, ok := f.store.statusOf(rec.ID, KindOpenBao); ok {
		t.Error("settle wrote a status after the leadership ended")
	}

	// A slot a dead lane left behind blocks the target and pins its files, until the leadership's end clears it.
	f.engine.lanes[rec.ID] = &lane{idx: pin, ctx: context.Background(), cancel: func() {}}
	f.round(t)
	if !exists() || len(dst.ops) != 0 {
		t.Fatalf("with a stale slot: expired snapshot kept %v, target ops %v", exists(), dst.ops)
	}
	f.engine.forgetPasses()
	f.now = f.now.Add(time.Minute)
	f.round(t)
	if exists() {
		t.Error("the expire still keeps the dead lane's file after the leadership ended")
	}
	if _, ok := dst.files[backupset.ManifestPath]; !ok {
		t.Errorf("the next leadership started no lane for the target: %v", dst.ops)
	}
}

// TestRemovedTargetCancelsItsLane: when a round finds a target disabled or deleted while its lane is in flight, it
// cancels the lane; the lane writes nothing more, frees its slot, pin and started gauge, and its run takes no result
// for that target, while the other target's result stands (amendment 2026-11-11, C3.7 and C3.8).
func TestRemovedTargetCancelsItsLane(t *testing.T) {
	for _, how := range []string{"disabled", "deleted"} {
		t.Run(how, func(t *testing.T) {
			f := newFixture(t)
			f.confirmKey()
			f.engine.stall = time.Hour
			slow := newHangingTarget()
			t.Cleanup(func() { close(slow.release) })
			slowRec := f.addTarget(t, backupset.TypeS3, slow)
			fastRec := f.addTarget(t, backupset.TypeS3, newMemTarget())
			roundWithin(t, f)
			<-slow.entered
			gauge := f.metrics.mirrorStarted.WithLabelValues(slowRec.Name)
			if got := testutil.ToFloat64(gauge); got <= 0 || got > float64(time.Now().Unix()) {
				t.Errorf("mirror started %v while the lane runs, want its start", got)
			}
			waitFor(t, "the other target's lane", func() bool {
				_, ok := f.store.statusOf(fastRec.ID, KindOpenBao)
				return ok
			})
			if how == "disabled" {
				f.store.targets[0].Enabled = false
			} else {
				f.store.targets = f.store.targets[1:]
			}
			f.now = f.now.Add(time.Minute)
			roundWithin(t, f)
			f.engine.waitLanes()

			if _, ok := f.store.statusOf(slowRec.ID, KindOpenBao); ok {
				t.Error("the cancelled lane wrote a target status")
			}
			if len(slow.files) != 0 {
				t.Errorf("the cancelled lane wrote %v", slow.files)
			}
			if len(f.engine.lanes) != 0 || len(f.engine.pinned()) != 0 {
				t.Errorf("after the cancel: lanes %v, pins %d", f.engine.lanes, len(f.engine.pinned()))
			}
			if n := testutil.CollectAndCount(f.metrics.mirrorStarted); n != 0 {
				t.Errorf("%d mirror started series after the cancel, want none", n)
			}
			r, _ := f.store.runOf(KindOpenBao, 0)
			if !r.mirrored || len(r.Targets) != 1 || r.Targets[0].TargetID != fastRec.ID.String() || !r.Targets[0].OK {
				t.Errorf("run after the cancel: %+v, want only the other target's ok", r)
			}
		})
	}
}

// TestTargetGaugesNeverGap: publishing the per-target gauges again never lets a concurrent scrape see fewer series, and
// a removed target's series go away while the remaining target's stay (PDK-1006).
func TestTargetGaugesNeverGap(t *testing.T) {
	f := newFixture(t)
	f.confirmKey()
	f.addTarget(t, backupset.TypeS3, newMemTarget())
	keep := f.addTarget(t, backupset.TypeS3, newMemTarget())
	roundWithin(t, f)
	f.engine.waitLanes()
	reachable, held, last := testutil.CollectAndCount(f.metrics.reachable), testutil.CollectAndCount(f.metrics.held),
		testutil.CollectAndCount(f.metrics.lastSuccess)
	if reachable != 2 || held != 2 || last == 0 {
		t.Fatalf("series after the first round: reachable %d, held %d, last success %d", reachable, held, last)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		for range 2000 {
			f.engine.laneMu.Lock()
			f.engine.publishTargets()
			f.engine.laneMu.Unlock()
		}
	}()
	for running := true; running; {
		select {
		case <-done:
			running = false
		default:
		}
		if n := testutil.CollectAndCount(f.metrics.reachable); n != reachable {
			t.Fatalf("a scrape saw %d reachable series while they were published again, want %d", n, reachable)
		}
		if n := testutil.CollectAndCount(f.metrics.lastSuccess); n != last {
			t.Fatalf("a scrape saw %d last success series while they were published again, want %d", n, last)
		}
	}

	f.store.targets[0].Enabled = false
	f.now = f.now.Add(time.Minute)
	roundWithin(t, f)
	f.engine.waitLanes()
	if n := testutil.CollectAndCount(f.metrics.reachable); n != 1 {
		t.Errorf("%d reachable series after a target was disabled, want 1", n)
	}
	if n := testutil.CollectAndCount(f.metrics.held); n != 1 {
		t.Errorf("%d held series after a target was disabled, want 1", n)
	}
	if n := testutil.CollectAndCount(f.metrics.lastSuccess); n >= last {
		t.Errorf("%d last success series after a target was disabled, want fewer than %d", n, last)
	}
	if got := testutil.ToFloat64(f.metrics.reachable.WithLabelValues(keep.Name)); got != 1 {
		t.Errorf("the remaining target's reachable %v, want 1", got)
	}
}
