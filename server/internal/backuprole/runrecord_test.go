package backuprole

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

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

// TestRunRecordedBeforeTheMirror: a run is recorded as soon as its local step finished, while the target's lane is
// still mirroring; its mirror results follow once the lane ended (decisions-alpha9 items 78 and 79, decisions-alpha10
// A10-26). Before, a mirror of hours kept a successful backup out of the database for as long.
func TestRunRecordedBeforeTheMirror(t *testing.T) {
	f := newFixture(t)
	f.confirmKey()
	f.engine.stall = time.Hour
	dst := &gatedTarget{memTarget: newMemTarget(), entered: make(chan struct{}), release: make(chan struct{})}
	rec := f.addTarget(t, backupset.TypeS3, dst)
	if err := f.engine.Round(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-dst.entered:
	case <-time.After(30 * time.Second):
		t.Fatal("the mirror did not start")
	}
	r, ok := f.store.run(KindOpenBao)
	if !ok || !r.Succeeded || r.mirrored {
		t.Fatalf("run while the mirror runs: %+v (recorded %v), want recorded and not mirrored yet", r, ok)
	}
	close(dst.release)
	f.engine.waitLanes()
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
	f.round(t)
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

// TestFleetRunRecordedWhileALaneHangs: the Fleet dump a round asked for is sealed and recorded by the next round
// while the target's lane still mirrors the earlier set (decisions-alpha10 A10-26; before, decisions-alpha9 item 82
// watched for it during the round's mirror). That lane's index lacks the dump, so the run's pass records the target as
// continues at once instead of waiting for the lane.
func TestFleetRunRecordedWhileALaneHangs(t *testing.T) {
	f := newFixture(t)
	f.confirmKey()
	f.engine.stall = time.Hour
	dst := &gatedTarget{memTarget: newMemTarget(), entered: make(chan struct{}), release: make(chan struct{})}
	rec := f.addTarget(t, backupset.TypeS3, dst)
	if err := f.engine.Round(context.Background()); err != nil {
		t.Fatal(err)
	}
	<-dst.entered
	if _, err := os.Stat(filepath.Join(f.cfg.FleetDumpsDir, fleetRequestFile)); err != nil {
		t.Fatalf("no fleet dump requested: %v", err)
	}
	name := f.now.UTC().Format("20060102T150405Z") + ".sql.gz"
	if err := os.WriteFile(filepath.Join(f.cfg.FleetDumpsDir, name), []byte("dump"), 0o600); err != nil {
		t.Fatal(err)
	}
	f.now = f.now.Add(time.Minute)
	if err := f.engine.Round(context.Background()); err != nil {
		t.Fatal(err)
	}
	r, ok := f.store.run(KindFleet)
	if !ok || !r.Succeeded || !r.mirrored || len(r.Targets) != 1 || r.Targets[0].TargetID != rec.ID.String() ||
		r.Targets[0].ErrorClass != ClassContinues {
		t.Fatalf("fleet run beside the hanging lane: %+v (recorded %v), want mirrored with the target continuing", r, ok)
	}
	close(dst.release)
	f.engine.waitLanes()
}
