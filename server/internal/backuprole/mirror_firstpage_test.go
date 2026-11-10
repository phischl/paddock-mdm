package backuprole

import (
	"context"
	"errors"
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
