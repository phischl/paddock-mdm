package backuprole

import (
	"context"
	"errors"
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

// TestSlowListingReachesDeletions: listings that keep delivering pages and, with the copies, take longer than the
// round's budget neither end the copy phase early nor trip the cap on a trickling copy: the mirror copies the set and
// reaches step 6, which deletes the snapshot the local expire would have removed. Charged against the budget, the two
// listings of a large S3 target ended every mirror before step 6 (PDK-865, decisions-alpha9 item 66).
func TestSlowListingReachesDeletions(t *testing.T) {
	f := newFixture(t)
	f.engine.stall = 400 * time.Millisecond
	f.engine.budget = 200 * time.Millisecond
	repo, idx := openSet(t, map[string]string{backupset.ManifestPath: string(testManifest(t, InstallationID(42), nil)),
		"openbao/20261105T060000Z.snap.enc": "a", "openbao/20261105T070000Z.snap.enc": "b"})
	set := "site/" + backupset.SetRoot + "/"
	s3 := &slowListS3{objects: map[string]string{set + "openbao/20200101T000000Z.snap.enc": "old",
		set + "openbao/20200102T000000Z.snap.enc": "old"}, pages: 8, delay: 50 * time.Millisecond}
	rec := f.addTarget(t, backupset.TypeS3, NewS3Target(s3, "site"))
	start := time.Now()
	if _, err := f.engine.mirrorTarget(context.Background(), repo, idx, rec, testRetention(time.Now())); err != nil {
		t.Fatalf("mirror: %v", err)
	}
	if took := time.Since(start); took < 2*f.engine.budget {
		t.Fatalf("the mirror took %s; the listings must outlast the budget for this test to mean anything", took)
	}
	s3.mu.Lock()
	defer s3.mu.Unlock()
	if _, ok := s3.objects[set+"openbao/20200101T000000Z.snap.enc"]; ok {
		t.Error("step 6 did not delete the expired snapshot")
	}
	if _, ok := s3.objects[set+backupset.ManifestPath]; !ok {
		t.Error("the target got no manifest")
	}
}

// hangingListS3 is an S3 endpoint whose listing delivers one page and then never another, until the request is
// cancelled. Its Ping blocks until its request is given up, as an endpoint that went away: an answering endpoint
// would keep the mirror alive until the target's page limit instead.
type hangingListS3 struct{ *slowListS3 }

func (h *hangingListS3) Ping(ctx context.Context) error {
	<-ctx.Done()
	return ctx.Err()
}

func (h *hangingListS3) ListSizesPaged(ctx context.Context, _ string, page func()) (map[string]int64, error) {
	page()
	<-ctx.Done()
	return nil, ctx.Err()
}

// TestHangingListingTripsTheWatchdog: a listing whose next page never arrives while the endpoint answers no probe
// either fails the mirror after the stall deadline, and the error names the listing, not a copy rate (PDK-865,
// decisions-alpha9 item 66; PDK-972).
func TestHangingListingTripsTheWatchdog(t *testing.T) {
	f := newFixture(t)
	f.engine.stall = 200 * time.Millisecond
	repo, idx := openSet(t, map[string]string{backupset.ManifestPath: string(testManifest(t, InstallationID(42), nil)),
		"openbao/20261105T060000Z.snap.enc": "a"})
	s3 := &hangingListS3{&slowListS3{objects: map[string]string{}}}
	dst := NewS3Target(s3, "site").(*s3Target)
	// Probes far below the stall deadline, so the silent endpoint is what the test relies on, not a long default.
	dst.probeEvery, dst.probeTimeout, dst.pageLimit = 20*time.Millisecond, 20*time.Millisecond, time.Minute
	rec := f.addTarget(t, backupset.TypeS3, dst)
	start := time.Now()
	_, err := f.engine.mirrorTarget(context.Background(), repo, idx, rec, testRetention(time.Now()))
	if !errors.Is(err, errStalled) || !strings.Contains(err.Error(), "while "+phaseList) {
		t.Errorf("error %v, want a stall while %s", err, phaseList)
	}
	if took := time.Since(start); took > 5*time.Second {
		t.Errorf("the watchdog took %s", took)
	}
}

// TestDirTargetWalksStopWithTheirContext: a mounted target's listing and its newest-file walk return the context's
// error once it ended, instead of walking a slow share to its end while the target stays busy (PDK-866).
func TestDirTargetWalksStopWithTheirContext(t *testing.T) {
	root := filepath.Join(t.TempDir(), "target")
	dir := filepath.Join(root, "fleet")
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
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ticks := 0
	got, err := listProgress(ctx, dst, func() {
		if ticks++; ticks == 1 {
			cancel()
		}
	})
	if !errors.Is(err, context.Canceled) || got != nil || ticks != 1 {
		t.Errorf("listing after the cancel: %d files, %d ticks, %v; want context.Canceled after the first tick",
			len(got), ticks, err)
	}
	if _, err := dst.Newest(ctx, "fleet/"); !errors.Is(err, context.Canceled) {
		t.Errorf("newest after the cancel: %v, want context.Canceled", err)
	}
}
