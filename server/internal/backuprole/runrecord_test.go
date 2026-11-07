package backuprole

import (
	"context"
	"errors"
	"io"
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
