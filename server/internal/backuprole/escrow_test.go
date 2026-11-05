package backuprole

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/phischl/paddock-mdm/server/internal/domain/backupset"
	"github.com/phischl/paddock-mdm/server/internal/platform/objectstore"
)

// headerKey is the bucket key of header n of device dev in organization o1.
func headerKey(dev string, n int) string {
	return fmt.Sprintf("org/o1/devices/%s/luks-header/%d.bin", dev, n)
}

// escrowFixture is an engine whose bucket, local set and one S3 target hold the same escrowed headers: devices d0…d9
// with two headers each (20 headers), after one round.
type escrowFixture struct {
	*fixture
	dst  *memTarget
	keys []string
}

func newEscrowFixture(t *testing.T) *escrowFixture {
	t.Helper()
	f := &escrowFixture{fixture: newFixture(t)}
	f.confirmKey()
	clear(f.escrow)
	for d := range 10 {
		for n := range 2 {
			k := headerKey(fmt.Sprintf("d%d", d), n)
			f.escrow[k] = "header " + k
			f.keys = append(f.keys, k)
		}
	}
	f.dst = newMemTarget()
	f.dst.now = func() time.Time { return f.now }
	f.addTarget(t, backupset.TypeS3, f.dst)
	f.round(t)
	for _, k := range f.keys {
		if !f.inRepo(t, k) || !f.onTarget(k) {
			t.Fatalf("setup: %s not on the local set and the target", k)
		}
	}
	f.store.runs = nil
	f.now = f.now.Add(2 * time.Hour)
	return f
}

func (f *escrowFixture) inRepo(t *testing.T, key string) bool {
	_, ok := f.repoFiles(t)[backupset.EscrowKey(key)]
	return ok
}

func (f *escrowFixture) onTarget(key string) bool {
	_, ok := f.dst.files[backupset.EscrowKey(key)]
	return ok
}

// assertAllKept checks that every header of the setup is still on the local set and the target.
func (f *escrowFixture) assertAllKept(t *testing.T) {
	t.Helper()
	for _, k := range f.keys {
		if !f.inRepo(t, k) {
			t.Errorf("%s deleted from the local set", k)
		}
		if !f.onTarget(k) {
			t.Errorf("%s deleted from the target", k)
		}
	}
	if d := opsOf(f.dst, "delete"); len(d) != 0 {
		t.Errorf("deletes on the target: %v", d)
	}
}

func (f *escrowFixture) escrowRun(t *testing.T) RunRecord {
	t.Helper()
	r, ok := f.store.run(KindEscrow)
	if !ok {
		t.Fatal("no escrow run recorded")
	}
	return r
}

func (f *escrowFixture) assertSuspicious(t *testing.T, want bool) {
	t.Helper()
	if got := testutil.ToFloat64(f.metrics.escrowSuspicious) == 1; got != want {
		t.Errorf("paddock_backup_escrow_listing_suspicious %v, want %v", got, want)
	}
	if r := f.escrowRun(t); r.Succeeded == want {
		t.Errorf("escrow run succeeded %v with a suspicious listing %v (class %q)", r.Succeeded, want, r.ErrorClass)
	} else if want && r.ErrorClass != runClassEscrow {
		t.Errorf("escrow run class %q, want %q", r.ErrorClass, runClassEscrow)
	}
}

// TestEscrowEmptyBucketHoldsEverything: a lost and re-created escrow bucket lists successfully but empty. No header
// leaves the local set or the target, the listing is suspicious, the escrow run fails (decisions-alpha9 item 27).
func TestEscrowEmptyBucketHoldsEverything(t *testing.T) {
	f := newEscrowFixture(t)
	clear(f.escrow)
	f.round(t)
	f.assertAllKept(t)
	f.assertSuspicious(t, true)
	if got := testutil.ToFloat64(f.metrics.escrowUnevidenced); got != 20 {
		t.Errorf("unevidenced missing %v, want 20", got)
	}
}

// TestEscrowWrongBucketHoldsEverything: a wrong PADDOCK_ESCROW_S3_BUCKET lists another installation's headers. None
// of them is copied into the set, none of the local headers leaves, the listing is suspicious.
func TestEscrowWrongBucketHoldsEverything(t *testing.T) {
	f := newEscrowFixture(t)
	clear(f.escrow)
	foreign := "org/o9/devices/x1/luks-header/1.bin"
	f.escrow[foreign] = "foreign header"
	f.round(t)
	f.assertAllKept(t)
	f.assertSuspicious(t, true)
	if f.inRepo(t, foreign) || f.onTarget(foreign) {
		t.Error("a header of the wrong bucket entered the backup set")
	}
}

// TestEscrowPartialAbsenceWithoutEvidence: headers missing from the bucket without Destroy evidence are held
// everywhere. One of 20 (5 %) is held and counted, the run succeeds; three of 20 (15 %) make the listing suspicious.
func TestEscrowPartialAbsenceWithoutEvidence(t *testing.T) {
	for name, c := range map[string]struct {
		missing    int
		suspicious bool
	}{
		"one of twenty":   {1, false},
		"two of twenty":   {2, false},
		"three of twenty": {3, true},
	} {
		t.Run(name, func(t *testing.T) {
			f := newEscrowFixture(t)
			for _, k := range f.keys[:c.missing] {
				delete(f.escrow, k)
			}
			f.round(t)
			f.assertAllKept(t)
			f.assertSuspicious(t, c.suspicious)
			if got := testutil.ToFloat64(f.metrics.escrowUnevidenced); got != float64(c.missing) {
				t.Errorf("unevidenced missing %v, want %d", got, c.missing)
			}
			if !c.suspicious {
				if got := testutil.ToFloat64(f.metrics.held.WithLabelValues(f.store.targets[0].Name)); got != 0 {
					t.Errorf("held %v: the local set still holds every header", got)
				}
			}
		})
	}
}

// TestEscrowEvidenceKeepWindow: headers of a destroyed device (device.escrow_destroyed) the bucket no longer holds
// leave the local set and the target only after the keep window (retention_full × full_interval, 14 days by default)
// has passed since the Destroy. Evidenced absences never count toward the suspicious share: here half of the local
// headers are missing, all with evidence.
func TestEscrowEvidenceKeepWindow(t *testing.T) {
	for name, c := range map[string]struct {
		age     time.Duration
		deleted bool
	}{
		"evidence within the keep window": {13 * day, false},
		"keep window passed":              {15 * day, true},
	} {
		t.Run(name, func(t *testing.T) {
			f := newEscrowFixture(t)
			f.store.evidence = map[string]time.Time{}
			var gone []string
			for d := range 5 {
				dev := fmt.Sprintf("d%d", d)
				f.store.evidence["o1/"+dev] = f.now.Add(-c.age)
				for n := range 2 {
					delete(f.escrow, headerKey(dev, n))
					gone = append(gone, headerKey(dev, n))
				}
			}
			f.round(t)
			f.assertSuspicious(t, false)
			for _, k := range gone {
				if f.inRepo(t, k) == c.deleted {
					t.Errorf("%s on the local set %v, want deleted %v", k, !c.deleted, c.deleted)
				}
			}
			// The local expire runs before the mirror; the target follows in the same round.
			for _, k := range gone {
				if f.onTarget(k) == c.deleted {
					t.Errorf("%s on the target %v, want deleted %v", k, !c.deleted, c.deleted)
				}
			}
			for _, k := range f.keys[10:] {
				if !f.inRepo(t, k) || !f.onTarget(k) {
					t.Errorf("%s of a device without evidence left the set", k)
				}
			}
			if got := testutil.ToFloat64(f.metrics.escrowUnevidenced); got != 0 {
				t.Errorf("unevidenced missing %v, want 0", got)
			}
		})
	}
}

// TestEscrowEvidenceQueryFailsHoldsEverything: without the evidence the escrow pass fails and nothing leaves.
func TestEscrowEvidenceQueryFailsHoldsEverything(t *testing.T) {
	f := newEscrowFixture(t)
	f.store.evidence = map[string]time.Time{"o1/d0": f.now.Add(-30 * day)}
	f.store.evidenceErr = errors.New("permission denied")
	delete(f.escrow, f.keys[0])
	f.round(t)
	f.assertAllKept(t)
	if r := f.escrowRun(t); r.Succeeded {
		t.Error("the escrow run succeeded without its evidence")
	}
}

// TestEscrowUnevidencedWarnedOncePerChange: a held unevidenced absence below the threshold is warned about when the
// set of such absences changes, not on every round.
func TestEscrowUnevidencedWarnedOncePerChange(t *testing.T) {
	var logs bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })
	warned := func() int {
		return strings.Count(logs.String(), "missing from the bucket without Destroy evidence are held")
	}

	f := newEscrowFixture(t)
	delete(f.escrow, f.keys[0])
	for range 2 {
		f.round(t)
		f.now = f.now.Add(2 * time.Hour)
	}
	if got := warned(); got != 1 {
		t.Errorf("warned %d times for one unchanged absence, want 1", got)
	}
	delete(f.escrow, f.keys[1])
	f.round(t)
	if got := warned(); got != 2 {
		t.Errorf("warned %d times after the absences changed, want 2", got)
	}
}

// timedEscrow is a fakeEscrow whose objects named in at carry that LastModified instead of fakeEscrowAt.
type timedEscrow struct {
	fakeEscrow
	at map[string]time.Time
}

func (e timedEscrow) ListInfo(ctx context.Context, prefix string) (map[string]objectstore.ObjectInfo, error) {
	out, err := e.fakeEscrow.ListInfo(ctx, prefix)
	for k, at := range e.at {
		if o, ok := out[k]; ok {
			o.Modified = at
			out[k] = o
		}
	}
	return out, err
}

// newerGenerationFixture is an escrow fixture with a second S3 target whose device d0 was destroyed 30 days ago
// (keep window 14 days) and, as a device that had not yet executed its Destroy token, escrowed a third header
// generation a day after the Destroy; one round copied it to the local set and both targets.
func newerGenerationFixture(t *testing.T) (*escrowFixture, string, []*memTarget) {
	t.Helper()
	f := newEscrowFixture(t)
	dst2 := newMemTarget()
	dst2.now = func() time.Time { return f.now }
	f.addTarget(t, backupset.TypeS3, dst2)
	destroyed := f.now.Add(-30 * day)
	f.store.evidence = map[string]time.Time{"o1/d0": destroyed}
	newer := headerKey("d0", 2)
	f.escrow[newer] = "header " + newer
	f.engine.escrow = timedEscrow{fakeEscrow: f.escrow, at: map[string]time.Time{newer: destroyed.Add(day)}}
	f.round(t)
	dsts := []*memTarget{f.dst, dst2}
	for _, d := range dsts {
		if _, ok := d.files[backupset.EscrowKey(newer)]; !ok || !f.inRepo(t, newer) {
			t.Fatalf("setup: the newer generation is not on the local set and every target")
		}
	}
	f.store.runs = nil
	f.now = f.now.Add(2 * time.Hour)
	return f, newer, dsts
}

// assertEverywhere checks that key is on the local set and every target (want true) or on none of them.
func (f *escrowFixture) assertEverywhere(t *testing.T, key string, dsts []*memTarget, want bool) {
	t.Helper()
	if got := f.inRepo(t, key); got != want {
		t.Errorf("%s on the local set %v, want %v", key, got, want)
	}
	for i, d := range dsts {
		if _, got := d.files[backupset.EscrowKey(key)]; got != want {
			t.Errorf("%s on target %d %v, want %v", key, i, got, want)
		}
	}
}

// TestEscrowGenerationNewerThanDestroyHeld (review 7 M1, decisions-alpha9 item 31): evidence covers only copies whose
// escrow object existed at or before the Destroy. A header generation escrowed after the Destroy that leaves the
// bucket is unevidenced: held on the local set and every target, and counted, although its device's Destroy is far
// older than the keep window.
func TestEscrowGenerationNewerThanDestroyHeld(t *testing.T) {
	f, newer, dsts := newerGenerationFixture(t)
	delete(f.escrow, newer)
	f.round(t)
	f.assertEverywhere(t, newer, dsts, true)
	if got := testutil.ToFloat64(f.metrics.escrowUnevidenced); got != 1 {
		t.Errorf("unevidenced missing %v, want 1: a copy newer than the Destroy counts", got)
	}
	f.assertSuspicious(t, false)
}

// TestEscrowOlderGenerationWithEvidenceDeleted: the generations escrowed before the Destroy still leave the local set
// and every target once the keep window has passed, although the device escrowed a newer generation after it.
func TestEscrowOlderGenerationWithEvidenceDeleted(t *testing.T) {
	f, newer, dsts := newerGenerationFixture(t)
	for n := range 2 {
		delete(f.escrow, headerKey("d0", n))
	}
	f.round(t)
	for n := range 2 {
		f.assertEverywhere(t, headerKey("d0", n), dsts, false)
	}
	f.assertEverywhere(t, newer, dsts, true)
	if got := testutil.ToFloat64(f.metrics.escrowUnevidenced); got != 0 {
		t.Errorf("unevidenced missing %v, want 0", got)
	}
	f.assertSuspicious(t, false)
}

// TestEscrowIndexRecordsObjectTime: the set's manifest records each escrowed header's escrow object time, never the
// local file's mtime; a copy whose index entry has no time (a manifest written before the time was recorded) is
// unevidenced and held even with old Destroy evidence (A2 note c).
func TestEscrowIndexRecordsObjectTime(t *testing.T) {
	f := newEscrowFixture(t)
	path := filepath.Join(f.cfg.RepoDir, backupset.ManifestPath)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	m, err := backupset.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Contents.Escrow) != len(f.keys) {
		t.Fatalf("manifest lists %d headers, want %d", len(m.Contents.Escrow), len(f.keys))
	}
	for i, e := range m.Contents.Escrow {
		if !e.At.Equal(fakeEscrowAt) {
			t.Errorf("%s recorded at %v, want the object's LastModified %v", e.Path, e.At, fakeEscrowAt)
		}
		m.Contents.Escrow[i].At = time.Time{}
	}
	legacy, err := m.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, legacy, 0o640); err != nil {
		t.Fatal(err)
	}
	f.store.evidence = map[string]time.Time{"o1/d0": f.now.Add(-30 * day)}
	for n := range 2 {
		delete(f.escrow, headerKey("d0", n))
	}
	f.round(t)
	f.assertAllKept(t)
	if got := testutil.ToFloat64(f.metrics.escrowUnevidenced); got != 2 {
		t.Errorf("unevidenced missing %v, want 2", got)
	}
}

// TestEscrowRuleGone pins the rule's conditions one by one.
func TestEscrowRuleGone(t *testing.T) {
	now, keep := matrixNow, 14*day
	p := backupset.EscrowKey(headerKey("d1", 1))
	destroyedAt := now.Add(-keep - time.Hour)
	base := escrowRule{listed: map[string]bool{}, destroyed: map[string]time.Time{"o1/d1": destroyedAt},
		copied: map[string]time.Time{p: destroyedAt}}
	if !base.gone(p, now, keep) {
		t.Fatal("evidence past the keep window does not let the header go")
	}
	for name, mutate := range map[string]func(r *escrowRule){
		"no listing":      func(r *escrowRule) { r.listed = nil },
		"suspicious":      func(r *escrowRule) { r.suspicious = true },
		"still listed":    func(r *escrowRule) { r.listed = map[string]bool{p: true} },
		"no evidence":     func(r *escrowRule) { r.destroyed = nil },
		"other device":    func(r *escrowRule) { r.destroyed = map[string]time.Time{"o1/d2": now.Add(-30 * day)} },
		"other org":       func(r *escrowRule) { r.destroyed = map[string]time.Time{"o2/d1": now.Add(-30 * day)} },
		"within the keep": func(r *escrowRule) { r.destroyed = map[string]time.Time{"o1/d1": now.Add(-keep)} },
		"copy newer":      func(r *escrowRule) { r.copied = map[string]time.Time{p: destroyedAt.Add(time.Second)} },
		"copy unrecorded": func(r *escrowRule) { r.copied = nil },
	} {
		r := base
		r.destroyed = maps.Clone(base.destroyed)
		mutate(&r)
		if r.gone(p, now, keep) {
			t.Errorf("%s: the header may go", name)
		}
	}
	if (escrowRule{}).gone(p, now, keep) {
		t.Error("the zero rule lets a header go")
	}
	for _, c := range []struct {
		missing, total int
		want           bool
	}{{0, 0, false}, {0, 5, false}, {1, 1, true}, {1, 10, false}, {2, 20, false}, {3, 20, true}, {2, 10, true}} {
		if got := suspicious(c.missing, c.total); got != c.want {
			t.Errorf("suspicious(%d, %d) = %v, want %v", c.missing, c.total, got, c.want)
		}
	}
}

// TestHeldGaugeSurvivesAFailedMirror (review 6 F3): a failed mirror keeps the target's last held count, so one
// failure does not restart PaddockBackupTargetHolding's 7-day window; a round whose local manifest could not be
// written still reports the held count of its step-6 verdicts.
func TestHeldGaugeSurvivesAFailedMirror(t *testing.T) {
	f := newEscrowFixture(t)
	f.dst.files[backupset.EscrowKey(headerKey("dz", 1))] = []byte("only on the target")
	name := f.store.targets[0].Name
	f.round(t)
	if got := testutil.ToFloat64(f.metrics.held.WithLabelValues(name)); got != 1 {
		t.Fatalf("held %v after a good mirror, want 1", got)
	}
	f.dst.fail = errors.New("share gone")
	f.now = f.now.Add(2 * time.Hour)
	f.round(t)
	if got := testutil.ToFloat64(f.metrics.reachable.WithLabelValues(name)); got != 0 {
		t.Fatalf("the failing target reachable %v", got)
	}
	if got := testutil.ToFloat64(f.metrics.held.WithLabelValues(name)); got != 1 {
		t.Errorf("held %v after a failed mirror, want the last value 1", got)
	}

	repo, idx := localSet(t, nil)
	x := escrowOf("x")
	r := defaultRules()
	r.noManifest = true
	held, err := runMirror(repo, idx, targetOf(t, set{x: "x"}, matrixNow.Add(-day), false), r)
	if err != nil {
		t.Fatal(err)
	}
	assertHeld(t, held, 1)
}
