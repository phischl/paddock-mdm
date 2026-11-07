package backuprole

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/domain/backupset"
)

// gatedTarget is a target whose first Put waits until release is closed (as a mirror of several hours), after telling
// on entered that the mirror runs.
type gatedTarget struct {
	*memTarget
	entered chan struct{}
	release chan struct{}
	once    bool
}

func (g *gatedTarget) Put(ctx context.Context, p string, r io.Reader, size int64) error {
	if !g.once {
		g.once = true
		close(g.entered)
		select {
		case <-g.release:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return g.memTarget.Put(ctx, p, r, size)
}

// TestRunRecordedBeforeTheMirror: a run is recorded as soon as its local step finished, while the round's mirror is
// still running; its mirror results follow once the mirror ended (decisions-alpha9 items 78 and 79). Before, a mirror
// of hours kept a successful backup out of the database for as long, and `backup now --wait` hung.
func TestRunRecordedBeforeTheMirror(t *testing.T) {
	f := newFixture(t)
	f.confirmKey()
	f.engine.stall = time.Hour
	dst := &gatedTarget{memTarget: newMemTarget(), entered: make(chan struct{}), release: make(chan struct{})}
	rec := f.addTarget(t, backupset.TypeS3, dst)
	done := make(chan error, 1)
	go func() { done <- f.engine.Round(context.Background()) }()
	select {
	case <-dst.entered:
	case err := <-done:
		t.Fatalf("the round ended before its mirror: %v", err)
	case <-time.After(30 * time.Second):
		t.Fatal("the mirror did not start")
	}
	r, ok := f.store.run(KindOpenBao)
	if !ok || !r.Succeeded || r.mirrored {
		t.Fatalf("run while the mirror runs: %+v (recorded %v), want recorded and not mirrored yet", r, ok)
	}
	close(dst.release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	r, _ = f.store.run(KindOpenBao)
	if !r.mirrored || len(r.Targets) != 1 || r.Targets[0].TargetID != rec.ID.String() || !r.Targets[0].OK {
		t.Fatalf("run after the mirror: %+v", r)
	}
}

// TestUnmirroredRunGetsTheNextMirror: when phase 2 of a round fails (the role stops between the phases), the next
// round gives the earlier run its mirror results, so that every run gets its one audit event (decisions-alpha9 item 79).
func TestUnmirroredRunGetsTheNextMirror(t *testing.T) {
	f := newFixture(t)
	f.confirmKey()
	rec := f.addTarget(t, backupset.TypeS3, newMemTarget())
	f.store.mirrorErr = errors.New("role stopped")
	if err := f.engine.Round(context.Background()); err == nil {
		t.Fatal("the round hid the failed phase 2")
	}
	r, ok := f.store.run(KindOpenBao)
	if !ok || r.mirrored {
		t.Fatalf("run after a failed phase 2: %+v (recorded %v)", r, ok)
	}
	f.store.mirrorErr = nil
	f.now = f.now.Add(time.Minute)
	f.round(t)
	r, _ = f.store.run(KindOpenBao)
	if !r.mirrored || len(r.Targets) != 1 || r.Targets[0].TargetID != rec.ID.String() || !r.Targets[0].OK {
		t.Fatalf("earlier run after the next round: %+v", r)
	}
}

// TestFleetRunRecordedDuringTheMirror: the Fleet dump a round asked for, which fleet-backup leaves a little later, is
// sealed and its run recorded while the round's mirror still runs, not after it (decisions-alpha9 item 82). Before,
// the fleet run stayed requested for the length of the mirror and `backup now --wait` timed out.
func TestFleetRunRecordedDuringTheMirror(t *testing.T) {
	f := newFixture(t)
	f.confirmKey()
	f.engine.stall = time.Hour
	f.engine.fleetWatch = 10 * time.Millisecond
	dst := &gatedTarget{memTarget: newMemTarget(), entered: make(chan struct{}), release: make(chan struct{})}
	f.addTarget(t, backupset.TypeS3, dst)
	done := make(chan error, 1)
	go func() { done <- f.engine.Round(context.Background()) }()
	select {
	case <-dst.entered:
	case err := <-done:
		t.Fatalf("the round ended before its mirror: %v", err)
	case <-time.After(30 * time.Second):
		t.Fatal("the mirror did not start")
	}
	if _, err := os.Stat(filepath.Join(f.cfg.FleetDumpsDir, fleetRequestFile)); err != nil {
		t.Fatalf("no fleet dump requested: %v", err)
	}
	if _, ok := f.store.run(KindFleet); ok {
		t.Fatal("a fleet run recorded before fleet-backup answered")
	}
	// fleet-backup answers the request while the mirror runs.
	name := f.now.UTC().Format("20060102T150405Z") + ".sql.gz"
	if err := os.WriteFile(filepath.Join(f.cfg.FleetDumpsDir, name), []byte("dump"), 0o600); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(30 * time.Second)
	for {
		if r, ok := f.store.run(KindFleet); ok {
			if !r.Succeeded || r.mirrored {
				t.Fatalf("fleet run during the mirror: %+v", r)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the fleet run was not recorded while the mirror ran")
		}
		time.Sleep(10 * time.Millisecond)
	}
	close(dst.release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	// This round's mirror did not hold the dump: the run's mirror results and event are the next round's.
	if r, _ := f.store.run(KindFleet); r.mirrored {
		t.Fatalf("fleet run took the results of a mirror without its file: %+v", r)
	}
	f.now = f.now.Add(time.Minute)
	f.round(t)
	if r, _ := f.store.run(KindFleet); !r.mirrored {
		t.Fatalf("fleet run after the next round: %+v", r)
	}
}

// TestLateFleetRequestAnsweredOnce: a Fleet request the round answers with a timeout is not answered a second time by
// the dump that arrives while the mirror runs (PDK-885 review 1): the dump becomes a scheduled run of its own.
func TestLateFleetRequestAnsweredOnce(t *testing.T) {
	f := newFixture(t)
	f.confirmKey()
	f.engine.stall = time.Hour
	f.engine.fleetWatch = 10 * time.Millisecond
	req := RequestedRun{ID: uuid.New(), Kind: KindFleet, CreatedAt: f.now.Add(-2 * time.Hour)}
	f.store.requests = []RequestedRun{req}
	dst := &gatedTarget{memTarget: newMemTarget(), entered: make(chan struct{}), release: make(chan struct{})}
	f.addTarget(t, backupset.TypeS3, dst)
	done := make(chan error, 1)
	go func() { done <- f.engine.Round(context.Background()) }()
	select {
	case <-dst.entered:
	case err := <-done:
		t.Fatalf("the round ended before its mirror: %v", err)
	case <-time.After(30 * time.Second):
		t.Fatal("the mirror did not start")
	}
	name := f.now.UTC().Format("20060102T150405Z") + ".sql.gz"
	if err := os.WriteFile(filepath.Join(f.cfg.FleetDumpsDir, name), []byte("dump"), 0o600); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(30 * time.Second)
	for f.store.count(KindFleet) < 2 {
		if time.Now().After(deadline) {
			t.Fatalf("fleet runs %d, want the timeout and the dump", f.store.count(KindFleet))
		}
		time.Sleep(10 * time.Millisecond)
	}
	close(dst.release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if n := f.store.answers(req.ID); n != 1 {
		t.Fatalf("the request was answered %d times, want once", n)
	}
}
