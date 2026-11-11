package backuprole

import (
	"context"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/phischl/paddock-mdm/server/internal/domain/backupset"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
)

// fakeLeader is one advisory lock shared by several engines: Lead runs fn while no one else holds it; drop ends the
// holder's leadership as a dead lock connection does and refuses the lock until allow.
type fakeLeader struct {
	mu      sync.Mutex
	held    bool
	refused bool
	cancel  context.CancelCauseFunc
}

func (l *fakeLeader) Lead(ctx context.Context, _ int64, _ time.Duration, fn func(context.Context) error) (bool, error) {
	l.mu.Lock()
	if l.held || l.refused {
		l.mu.Unlock()
		return false, nil
	}
	lctx, cancel := context.WithCancelCause(ctx)
	l.held, l.cancel = true, cancel
	l.mu.Unlock()
	err := fn(lctx)
	lost := errors.Is(context.Cause(lctx), db.ErrLeadershipLost)
	cancel(nil)
	l.mu.Lock()
	l.held = false
	l.mu.Unlock()
	if lost {
		return true, errors.Join(db.ErrLeadershipLost, err)
	}
	return true, err
}

func (l *fakeLeader) drop() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.refused = true
	l.cancel(db.ErrLeadershipLost)
}

func (l *fakeLeader) allow() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.refused = false
}

func (l *fakeLeader) holding() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.held
}

// countingSnap counts its snapshots; another process's engine takes them while the test reads the count.
type countingSnap struct{ calls atomic.Int32 }

func (c *countingSnap) RaftSnapshot(_ context.Context, w io.Writer) error {
	c.calls.Add(1)
	_, err := w.Write([]byte("raft snapshot"))
	return err
}

// writes counts what the fake store holds: target statuses, runs and runs with mirror results.
func (s *fakeStore) writes() (status, runs, mirrored int) {
	s.runsMu.Lock()
	defer s.runsMu.Unlock()
	for _, r := range s.runs {
		if r.mirrored {
			mirrored++
		}
	}
	return len(s.status), len(s.runs), mirrored
}

// runEngine runs e.Run until the test ends.
func runEngine(t *testing.T, e *Engine) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = e.Run(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
}

// TestLostLeadershipStopsLanesAndResumes: when the leader lock's connection dies, Run cancels the hanging lane and
// stops its rounds before any further write, counts the loss, and leads again once the lock is free; the next
// leadership mirrors the earlier run (decisions-alpha10 §50).
func TestLostLeadershipStopsLanesAndResumes(t *testing.T) {
	f := newFixture(t)
	f.confirmKey()
	f.engine.stall = time.Hour
	f.engine.cfg.RoundInterval = 20 * time.Millisecond
	leader := &fakeLeader{}
	f.engine.lock = leader
	slow := newHangingTarget()
	rec := f.addTarget(t, backupset.TypeS3, slow)
	runEngine(t, f.engine)
	<-slow.entered

	leader.drop()
	waitFor(t, "the lost leadership to end", func() bool { return !leader.holding() })
	status, runs, mirrored := f.store.writes()
	close(slow.release)
	time.Sleep(200 * time.Millisecond)
	if s, r, m := f.store.writes(); s != status || r != runs || m != mirrored {
		t.Fatalf("writes after the lost leadership: status %d→%d, runs %d→%d, mirrored %d→%d", status, s, runs, r,
			mirrored, m)
	}
	if _, ok := f.store.statusOf(rec.ID, KindOpenBao); ok {
		t.Error("the cancelled lane wrote a target status")
	}
	if got := testutil.ToFloat64(f.metrics.leaderLost); got != 1 {
		t.Errorf("leader_lost_total %v, want 1", got)
	}
	if got := testutil.ToFloat64(f.metrics.leader); got != 0 {
		t.Errorf("leader %v after the loss, want 0", got)
	}

	leader.allow()
	waitFor(t, "the earlier run's mirror under the new leadership", func() bool {
		r, ok := f.store.runOf(KindOpenBao, 0)
		return ok && r.mirrored
	})
	if r, _ := f.store.runOf(KindOpenBao, 0); len(r.Targets) != 1 || !r.Targets[0].OK {
		t.Errorf("earlier run after the new leadership: %+v", r)
	}
	if got := testutil.ToFloat64(f.metrics.leader); got != 1 {
		t.Errorf("leader %v after leading again, want 1", got)
	}
	if n := f.store.duplicateWrites(); n != 0 {
		t.Errorf("%d runs got their mirror results twice", n)
	}
}

// TestStandbyProcessRunsNothing: a second process runs no round and no lane while the first leads, and leads once the
// first stopped (decisions-alpha10 §50).
func TestStandbyProcessRunsNothing(t *testing.T) {
	f := newFixture(t)
	f.confirmKey()
	f.engine.cfg.RoundInterval = 20 * time.Millisecond
	leader := &fakeLeader{}
	f.engine.lock = leader
	f.addTarget(t, backupset.TypeS3, newMemTarget())
	ctx, cancel := context.WithCancel(context.Background())
	first := make(chan struct{})
	go func() {
		defer close(first)
		_ = f.engine.Run(ctx)
	}()
	waitFor(t, "the first process to lead", leader.holding)

	snap := &countingSnap{}
	metrics := NewMetrics(prometheus.NewRegistry())
	standby := NewEngine(f.engine.cfg, leader, f.store, fakeKeys{}, snap, f.escrow, f.factory, metrics,
		func() time.Time { return f.now })
	runEngine(t, standby)
	time.Sleep(200 * time.Millisecond)
	if n := snap.calls.Load(); n != 0 {
		t.Errorf("the standby took %d snapshots while the first process led", n)
	}
	if got := testutil.ToFloat64(metrics.leader); got != 0 {
		t.Errorf("standby leader %v, want 0", got)
	}
	standby.laneMu.Lock()
	lanes := len(standby.lanes)
	standby.laneMu.Unlock()
	if lanes != 0 {
		t.Errorf("the standby runs %d lanes", lanes)
	}

	cancel()
	<-first
	waitFor(t, "the standby to lead", func() bool { return snap.calls.Load() > 0 })
}
