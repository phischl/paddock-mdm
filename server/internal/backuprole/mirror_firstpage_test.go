package backuprole

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/server/internal/domain/backupset"
)

// lateFirstPageS3 is an S3 endpoint whose listing returns its first page only after firstPage, as RustFS walking the
// noncurrent versions and delete markers of a large versioned bucket (PDK-972). firstPage < 0 means the page never
// arrives. Ping answers when answering is set, else it blocks until its request is given up, as an endpoint that
// went away.
type lateFirstPageS3 struct {
	*slowListS3
	firstPage time.Duration
	answering bool
}

func (l *lateFirstPageS3) Ping(ctx context.Context) error {
	if l.answering {
		return nil
	}
	<-ctx.Done()
	return ctx.Err()
}

func (l *lateFirstPageS3) ListSizesPaged(ctx context.Context, prefix string, page func()) (map[string]int64, error) {
	wait := make(<-chan time.Time)
	if l.firstPage >= 0 {
		wait = time.After(l.firstPage)
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-wait:
	}
	return l.slowListS3.ListSizesPaged(ctx, prefix, page)
}

// lateTarget returns the S3 target on l with probes every probeEvery, each given up after probeEvery, and a page
// limit of pageLimit.
func lateTarget(l *lateFirstPageS3, probeEvery, pageLimit time.Duration) *s3Target {
	dst := NewS3Target(l, "site").(*s3Target)
	dst.probeEvery, dst.probeTimeout, dst.pageLimit = probeEvery, probeEvery, pageLimit
	return dst
}

// TestSlowFirstPageFromAnsweringEndpointIsNoStall: an S3 target whose first list page arrives well after the stall
// deadline, while the endpoint keeps answering, receives the set. Before, the watchdog counted only pages and failed
// every mirror to the development target holding 55 000 objects (PDK-972).
func TestSlowFirstPageFromAnsweringEndpointIsNoStall(t *testing.T) {
	f := newFixture(t)
	f.engine.stall = 400 * time.Millisecond
	repo, idx := openSet(t, map[string]string{backupset.ManifestPath: string(testManifest(t, InstallationID(42), nil)),
		"openbao/20261105T060000Z.snap.enc": "a"})
	s3 := &lateFirstPageS3{slowListS3: &slowListS3{objects: map[string]string{}, pages: 1},
		firstPage: 4 * f.engine.stall, answering: true}
	rec := f.addTarget(t, backupset.TypeS3, lateTarget(s3, 50*time.Millisecond, time.Minute))
	start := time.Now()
	if _, err := f.engine.mirrorTarget(context.Background(), repo, idx, rec, testRetention(time.Now())); err != nil {
		t.Fatalf("mirror: %v", err)
	}
	if took := time.Since(start); took < 2*f.engine.stall {
		t.Fatalf("the mirror took %s; the first page must outlast the stall deadline for this test to mean anything", took)
	}
	s3.mu.Lock()
	defer s3.mu.Unlock()
	if _, ok := s3.objects["site/"+backupset.SetRoot+"/"+backupset.ManifestPath]; !ok {
		t.Error("the target got no manifest")
	}
}

// TestSlowFirstPageFromSilentEndpointStalls: while the first page is outstanding and the endpoint answers no probe
// either, the watchdog fails the mirror after the stall deadline and names the listing.
func TestSlowFirstPageFromSilentEndpointStalls(t *testing.T) {
	f := newFixture(t)
	f.engine.stall = 400 * time.Millisecond
	repo, idx := openSet(t, map[string]string{backupset.ManifestPath: string(testManifest(t, InstallationID(42), nil)),
		"openbao/20261105T060000Z.snap.enc": "a"})
	s3 := &lateFirstPageS3{slowListS3: &slowListS3{objects: map[string]string{}, pages: 1}, firstPage: -1}
	rec := f.addTarget(t, backupset.TypeS3, lateTarget(s3, 50*time.Millisecond, time.Minute))
	start := time.Now()
	_, err := f.engine.mirrorTarget(context.Background(), repo, idx, rec, testRetention(time.Now()))
	if !errors.Is(err, errStalled) || !strings.Contains(err.Error(), "while "+phaseList) {
		t.Errorf("error %v, want a stall while %s", err, phaseList)
	}
	if took := time.Since(start); took > 10*time.Second {
		t.Errorf("the watchdog took %s", took)
	}
}

// TestListingPageLimit: a page that never arrives ends the listing after the page limit although the endpoint keeps
// answering its probes, so a listing request that hangs on an answering endpoint cannot hold the round for ever.
func TestListingPageLimit(t *testing.T) {
	s3 := &lateFirstPageS3{slowListS3: &slowListS3{objects: map[string]string{}, pages: 1}, firstPage: -1,
		answering: true}
	dst := lateTarget(s3, 20*time.Millisecond, 300*time.Millisecond)
	ticks := 0
	done := make(chan error, 1)
	go func() {
		_, err := dst.ListProgress(context.Background(), func() { ticks++ })
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, errStalled) || !strings.Contains(err.Error(), "no page of the listing") {
			t.Errorf("error %v, want a stall for want of a page", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("the listing did not end at its page limit")
	}
	if ticks == 0 {
		t.Error("the answering endpoint's probes ticked no progress")
	}
}

// TestHungListingOnAnsweringEndpointEndsAtPageLimit: a listing request that hangs on an endpoint that keeps answering
// its probes outlives the stall deadline, ends at the page limit with an error naming the missing page, and does not
// hold the round for the other target (PDK-972).
func TestHungListingOnAnsweringEndpointEndsAtPageLimit(t *testing.T) {
	f := newFixture(t)
	f.confirmKey()
	f.engine.stall = 400 * time.Millisecond
	hung := &lateFirstPageS3{slowListS3: &slowListS3{objects: map[string]string{}, pages: 1}, firstPage: -1,
		answering: true}
	hungRec := f.addTarget(t, backupset.TypeS3, lateTarget(hung, 50*time.Millisecond, time.Second))
	good := newMemTarget()
	f.addTarget(t, backupset.TypeS3, good)

	roundDone := make(chan error, 1)
	go func() { roundDone <- f.engine.Round(context.Background()) }()
	select {
	case err := <-roundDone:
		if err != nil {
			t.Fatalf("round: %v", err)
		}
	case <-time.After(time.Minute):
		t.Fatal("the round stayed blocked by the hung listing")
	}
	if _, ok := good.files[backupset.ManifestPath]; !ok {
		t.Error("the reachable target got no manifest")
	}
	r, ok := f.store.run(KindOpenBao)
	if !ok {
		t.Fatal("no run recorded")
	}
	seen := false
	for _, rt := range r.Targets {
		if rt.TargetID == hungRec.ID.String() {
			seen = true
			if rt.OK || rt.ErrorClass != ClassIO {
				t.Errorf("hung target %+v", rt)
			}
		}
	}
	if !seen {
		t.Error("the run recorded no result for the hung target")
	}

	// The run keeps no error text, so what ended the mirror is read off a direct mirror of the same target.
	repo, idx := openSet(t, map[string]string{backupset.ManifestPath: string(testManifest(t, InstallationID(42), nil)),
		"openbao/20261105T060000Z.snap.enc": "a"})
	rec := f.addTarget(t, backupset.TypeS3, lateTarget(hung, 50*time.Millisecond, time.Second))
	start := time.Now()
	_, err := f.engine.mirrorTarget(context.Background(), repo, idx, rec, testRetention(time.Now()))
	if !errors.Is(err, errStalled) || !strings.Contains(err.Error(), "no page of the listing") {
		t.Errorf("error %v, want the page limit", err)
	}
	if took := time.Since(start); took < 2*f.engine.stall {
		t.Errorf("the mirror ended after %s, within the stall deadline: the probes did not keep it alive", took)
	}
}

// TestListingEndAbandonsProbeInFlight: a probe still waiting on a silent endpoint when the listing's page arrives is
// given up at once; the listing returns without waiting for the probe's timeout.
func TestListingEndAbandonsProbeInFlight(t *testing.T) {
	s3 := &lateFirstPageS3{slowListS3: &slowListS3{objects: map[string]string{}, pages: 1},
		firstPage: 200 * time.Millisecond}
	dst := lateTarget(s3, 20*time.Millisecond, time.Minute)
	dst.probeTimeout = time.Minute
	start := time.Now()
	if _, err := dst.ListProgress(context.Background(), func() {}); err != nil {
		t.Fatal(err)
	}
	if took := time.Since(start); took > 10*time.Second {
		t.Errorf("the listing returned after %s, held by a probe in flight", took)
	}
}

// slowNewestS3 is an S3 endpoint whose listing answers at once but whose walk of a repository for its newest file
// returns its first page only after newest (never when newest < 0), as RustFS on a retired repository of 45 000
// objects among many deleted ones (PDK-972). Ping answers when answering is set, else it blocks until given up.
type slowNewestS3 struct {
	*slowListS3
	newest    time.Duration
	answering bool
}

func (s *slowNewestS3) Ping(ctx context.Context) error {
	if s.answering {
		return nil
	}
	<-ctx.Done()
	return ctx.Err()
}

func (s *slowNewestS3) NewestPaged(ctx context.Context, _ string, page func()) (time.Time, bool, error) {
	wait := make(<-chan time.Time)
	if s.newest >= 0 {
		wait = time.After(s.newest)
	}
	select {
	case <-ctx.Done():
		return time.Time{}, false, ctx.Err()
	case <-wait:
	}
	page()
	return time.Time{}, false, nil
}

// retiredOnSlowNewest mirrors a complete active repository to an S3 target holding a retired repository past its
// retention, through an endpoint whose newest-file walk is slow per s; it returns the mirror's error and whether the
// retired repository is gone.
func retiredOnSlowNewest(t *testing.T, s *slowNewestS3) (error, bool) {
	t.Helper()
	f := newFixture(t)
	f.engine.stall = 400 * time.Millisecond
	set := "site/" + backupset.SetRoot + "/"
	for p, body := range oldRepo() {
		s.objects[set+p] = body
	}
	repo, idx := localSet(t, completeA(label9))
	ret := testRetention(time.Now())
	ret.retired[pathOld], ret.known[pathOld] = time.Now().Add(-20*day), true
	dst := NewS3Target(s, "site").(*s3Target)
	dst.probeEvery, dst.probeTimeout, dst.pageLimit = 50*time.Millisecond, 50*time.Millisecond, time.Minute
	rec := f.addTarget(t, backupset.TypeS3, dst)
	_, err := f.engine.mirrorTarget(context.Background(), repo, idx, rec, ret)
	s.mu.Lock()
	defer s.mu.Unlock()
	for p := range oldRepo() {
		if _, ok := s.objects[set+p]; ok {
			return err, false
		}
	}
	return err, true
}

// TestSlowRetiredNewestFromAnsweringEndpointIsNoStall: the guard's walk of a retired repository for its newest file
// takes longer than the stall deadline while the endpoint answers; the mirror goes on and prunes the repository.
// Before, that walk reported no progress, so a large retired repository stalled every mirror before step 6 (PDK-972).
func TestSlowRetiredNewestFromAnsweringEndpointIsNoStall(t *testing.T) {
	err, pruned := retiredOnSlowNewest(t, &slowNewestS3{slowListS3: &slowListS3{objects: map[string]string{}, pages: 1},
		newest: 1600 * time.Millisecond, answering: true})
	if err != nil {
		t.Fatalf("mirror: %v", err)
	}
	if !pruned {
		t.Error("the retired repository past its retention was not pruned")
	}
}

// TestSlowRetiredNewestFromSilentEndpointStalls: the same walk on an endpoint that answers no probe fails the mirror
// after the stall deadline, and nothing of the retired repository is deleted.
func TestSlowRetiredNewestFromSilentEndpointStalls(t *testing.T) {
	start := time.Now()
	err, pruned := retiredOnSlowNewest(t, &slowNewestS3{slowListS3: &slowListS3{objects: map[string]string{}, pages: 1},
		newest: -1})
	if !errors.Is(err, errStalled) || !strings.Contains(err.Error(), "no progress") {
		t.Errorf("error %v, want a stall", err)
	}
	if pruned {
		t.Error("the stalled mirror deleted the retired repository")
	}
	if took := time.Since(start); took > 10*time.Second {
		t.Errorf("the watchdog took %s", took)
	}
}

// TestDirTargetNewestTicks: a mounted target's walk of a repository for its newest file reports progress like its
// listing, so a slow share that still answers is no stall.
func TestDirTargetNewestTicks(t *testing.T) {
	root := filepath.Join(t.TempDir(), "mount", backupset.SetRoot)
	dir := filepath.Join(root, "pgbackrest", "bk-20261001-0badc0de", "archive")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	const files = 3 * listTickEvery
	for i := range files {
		if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("%05d", i)), []byte("x"), 0o640); err != nil {
			t.Fatal(err)
		}
	}
	ticks := 0
	if _, err := newestProgress(context.Background(), NewDirTarget(root), pathOld+"/", func() { ticks++ }); err != nil {
		t.Fatal(err)
	}
	if ticks < files/listTickEvery {
		t.Errorf("%d ticks while walking %d files, want at least %d", ticks, files, files/listTickEvery)
	}
}
