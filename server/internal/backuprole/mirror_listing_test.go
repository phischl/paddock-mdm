package backuprole

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/server/internal/domain/backupset"
	"github.com/phischl/paddock-mdm/server/internal/platform/objectstore"
)

// slowListS3 is an S3 endpoint whose bucket listing returns pages pages, each after delay: as RustFS listing a set of
// 300 000 objects at about 1 200 objects a second, the whole listing takes longer than the stall deadline while every
// page arrives well within it.
type slowListS3 struct {
	mu      sync.Mutex
	objects map[string]string
	pages   int
	delay   time.Duration
}

func (s *slowListS3) Ping(context.Context) error { return nil }

func (s *slowListS3) ListSizes(ctx context.Context, prefix string) (map[string]int64, error) {
	return s.ListSizesPaged(ctx, prefix, func() {})
}

func (s *slowListS3) ListSizesPaged(ctx context.Context, prefix string, page func()) (map[string]int64, error) {
	for range s.pages {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(s.delay):
		}
		page()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[string]int64{}
	for k, v := range s.objects {
		if strings.HasPrefix(k, prefix) {
			out[k] = int64(len(v))
		}
	}
	return out, nil
}

func (s *slowListS3) Newest(context.Context, string) (time.Time, bool, error) {
	return time.Time{}, false, nil
}

func (s *slowListS3) Open(_ context.Context, key string) (io.ReadCloser, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.objects[key]
	if !ok {
		return nil, objectstore.ErrNotFound
	}
	return io.NopCloser(strings.NewReader(v)), nil
}

func (s *slowListS3) PutReader(_ context.Context, key string, body io.ReadSeeker, _ int64) error {
	b, err := io.ReadAll(body)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.objects[key] = string(b)
	return err
}

func (s *slowListS3) Delete(_ context.Context, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.objects, key)
	return nil
}

// TestSlowListingIsNoStall: an S3 target whose listing takes longer than the stall deadline but delivers a page well
// within it receives the set; before, the watchdog saw no progress during a listing and failed every mirror to an S3
// target holding a few hundred thousand objects (PDK-865).
func TestSlowListingIsNoStall(t *testing.T) {
	f := newFixture(t)
	f.confirmKey()
	f.engine.stall = 400 * time.Millisecond
	s3 := &slowListS3{objects: map[string]string{}, pages: 12, delay: 50 * time.Millisecond}
	rec := f.addTarget(t, backupset.TypeS3, NewS3Target(s3, "site"))
	f.round(t)
	r, ok := f.store.run(KindOpenBao)
	if !ok {
		t.Fatal("no run recorded")
	}
	for _, rt := range r.Targets {
		if rt.TargetID == rec.ID.String() && !rt.OK {
			t.Errorf("slowly listing target %+v, want ok", rt)
		}
	}
	s3.mu.Lock()
	_, mirrored := s3.objects["site/"+backupset.SetRoot+"/"+backupset.ManifestPath]
	s3.mu.Unlock()
	if !mirrored {
		t.Error("the target got no manifest")
	}
}

// TestDirTargetListingTicks: a mounted target's listing reports progress while it walks a large set, so a slow
// share that is still answering is no stall (PDK-865).
func TestDirTargetListingTicks(t *testing.T) {
	root := filepath.Join(t.TempDir(), "target")
	dir := filepath.Join(root, backupset.SetRoot, "fleet")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	const files = 3 * listTickEvery
	for i := range files {
		if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("%05d.enc", i)), []byte("x"), 0o640); err != nil {
			t.Fatal(err)
		}
	}
	dst := NewDirTarget(root)
	ticks := 0
	got, err := listProgress(context.Background(), dst, func() { ticks++ })
	if err != nil || len(got) != files {
		t.Fatalf("listed %d files, %v; want %d", len(got), err, files)
	}
	if ticks < files/listTickEvery {
		t.Errorf("%d ticks while listing %d files, want at least %d", ticks, files, files/listTickEvery)
	}
}

// TestListingPastBudgetIsNoTrickle: on a target that already holds the set, listings that keep delivering pages past
// the round's budget are not cut off by the hard cap on a trickling copy, and the mirror completes. With two listings
// of a few minutes each on a large S3 target, the cap ended every mirror before step 6 (PDK-865).
func TestListingPastBudgetIsNoTrickle(t *testing.T) {
	f := newFixture(t)
	f.confirmKey()
	f.engine.stall = 400 * time.Millisecond
	s3 := &slowListS3{objects: map[string]string{}}
	rec := f.addTarget(t, backupset.TypeS3, NewS3Target(s3, "site"))
	f.round(t)
	f.engine.budget = 100 * time.Millisecond
	s3.pages, s3.delay = 12, 50*time.Millisecond
	f.round(t)
	if st := f.store.status[rec.ID.String()+"/"+KindOpenBao]; st.Error != "" {
		t.Errorf("target status %+v after listings past the budget, want no error", st)
	}
}
