package backuprole

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"
)

// fleetRequestFixture is a fixture with a confirmed key whose other kinds are not due, so a round's Fleet runs are the
// only runs it records.
func fleetRequestFixture(t *testing.T) *fixture {
	t.Helper()
	f := newFixture(t)
	f.confirmKey()
	for _, k := range []string{KindOpenBao, KindEscrow, KindFleet} {
		f.store.history[k] = KindHistory{LastAttempt: f.now, LastSuccess: f.now}
	}
	return f
}

func writeDump(t *testing.T, f *fixture, at time.Time) {
	t.Helper()
	name := at.UTC().Format("20060102T150405Z") + ".sql.gz"
	if err := os.WriteFile(filepath.Join(f.cfg.FleetDumpsDir, name), []byte("dump "+name), 0o640); err != nil {
		t.Fatal(err)
	}
}

func fleetRuns(f *fixture) []fakeRun {
	f.store.runsMu.Lock()
	defer f.store.runsMu.Unlock()
	return slices.DeleteFunc(slices.Clone(f.store.runs), func(r fakeRun) bool { return r.Kind != KindFleet })
}

func fleetRequested(t *testing.T, f *fixture) bool {
	t.Helper()
	_, err := os.Stat(filepath.Join(f.cfg.FleetDumpsDir, fleetRequestFile))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	return err == nil
}

// TestFleetDumpOlderThanRequestDoesNotAnswerIt: a dump fleet-backup wrote before `backup now` (it waited a round
// because the rounds no longer wait, A10-26) is sealed, but its run does not answer the request; the role asks for a
// fresh dump, and that dump's run answers it (decisions-alpha10 §64; gate BS3, where the request at 09:02:52 was
// answered by the dump of 09:02:01).
func TestFleetDumpOlderThanRequestDoesNotAnswerIt(t *testing.T) {
	f := fleetRequestFixture(t)
	dumpAt := f.now.Add(-time.Minute)
	writeDump(t, f, dumpAt)
	req := RequestedRun{ID: uuid.New(), Kind: KindFleet, CreatedAt: dumpAt.Add(51 * time.Second)}
	f.store.requests = []RequestedRun{req}

	f.round(t)
	runs := fleetRuns(f)
	if len(runs) != 1 || !runs[0].Succeeded {
		t.Fatalf("fleet runs %+v, want the older dump sealed", runs)
	}
	if n := f.store.answers(req.ID); n != 0 {
		t.Fatalf("the request was answered %d times by a dump older than it, want none", n)
	}
	if _, ok := f.repoFiles(t)["fleet/"+dumpAt.Format("20060102T150405Z")+".sql.gz.enc"]; !ok {
		t.Error("the older dump was not sealed")
	}
	if !fleetRequested(t, f) {
		t.Fatal("no fresh dump requested for the open request")
	}

	if err := os.Remove(filepath.Join(f.cfg.FleetDumpsDir, fleetRequestFile)); err != nil {
		t.Fatal(err)
	}
	f.now = f.now.Add(10 * time.Second)
	fresh := f.now.Truncate(time.Second)
	writeDump(t, f, fresh)
	f.now = f.now.Add(time.Minute)
	f.round(t)
	runs = fleetRuns(f)
	if len(runs) != 2 || !runs[1].Succeeded {
		t.Fatalf("fleet runs %+v, want the fresh dump sealed", runs)
	}
	if !slices.ContainsFunc(runs[1].Requests, func(q RequestedRun) bool { return q.ID == req.ID }) ||
		f.store.answers(req.ID) != 1 {
		t.Errorf("the fresh dump's run %+v does not answer the request once", runs[1])
	}
	if fleetRequested(t, f) {
		t.Error("a dump was requested although the fresh dump answered every request")
	}
}

// TestFleetDumpNewerThanRequestAnswersIt: a dump written after the request (or in the request's second) answers it
// and no further dump is requested.
func TestFleetDumpNewerThanRequestAnswersIt(t *testing.T) {
	for name, offset := range map[string]time.Duration{"dump newer": -time.Minute, "dump at the same instant": 0} {
		t.Run(name, func(t *testing.T) {
			f := fleetRequestFixture(t)
			dumpAt := f.now.Add(-time.Minute)
			writeDump(t, f, dumpAt)
			req := RequestedRun{ID: uuid.New(), Kind: KindFleet, CreatedAt: dumpAt.Add(offset)}
			f.store.requests = []RequestedRun{req}
			f.round(t)
			runs := fleetRuns(f)
			if len(runs) != 1 || !runs[0].Succeeded || f.store.answers(req.ID) != 1 {
				t.Fatalf("fleet runs %+v, want the dump's run to answer the request once", runs)
			}
			if fleetRequested(t, f) {
				t.Error("a dump was requested although the waiting dump answered the request")
			}
		})
	}
}

// TestFleetDumpsAnswerOnlyEarlierRequests: with several waiting dumps each run answers the open requests made at or
// before its dump and after the previous one; a request after the newest dump, even within that dump's second, stays
// open and asks for a fresh dump.
func TestFleetDumpsAnswerOnlyEarlierRequests(t *testing.T) {
	f := fleetRequestFixture(t)
	first, second := f.now.Add(-10*time.Minute), f.now.Add(-5*time.Minute)
	writeDump(t, f, first)
	writeDump(t, f, second)
	beforeFirst := RequestedRun{ID: uuid.New(), Kind: KindFleet, CreatedAt: first.Add(-time.Minute)}
	atFirst := RequestedRun{ID: uuid.New(), Kind: KindFleet, CreatedAt: first}
	between := RequestedRun{ID: uuid.New(), Kind: KindFleet, CreatedAt: first.Add(2 * time.Minute)}
	sameSecondAfter := RequestedRun{ID: uuid.New(), Kind: KindFleet, CreatedAt: second.Add(500 * time.Millisecond)}
	after := RequestedRun{ID: uuid.New(), Kind: KindFleet, CreatedAt: second.Add(time.Minute)}
	f.store.requests = []RequestedRun{beforeFirst, atFirst, between, sameSecondAfter, after}

	f.round(t)
	runs := fleetRuns(f)
	if len(runs) != 2 {
		t.Fatalf("fleet runs %+v, want one per dump", runs)
	}
	ids := func(r fakeRun) []uuid.UUID {
		var out []uuid.UUID
		for _, q := range r.Requests {
			out = append(out, q.ID)
		}
		return out
	}
	if got, want := ids(runs[0]), []uuid.UUID{beforeFirst.ID, atFirst.ID}; !slices.Equal(got, want) {
		t.Errorf("first dump answers %v, want %v", got, want)
	}
	if got, want := ids(runs[1]), []uuid.UUID{between.ID}; !slices.Equal(got, want) {
		t.Errorf("second dump answers %v, want %v", got, want)
	}
	for _, q := range []RequestedRun{sameSecondAfter, after} {
		if n := f.store.answers(q.ID); n != 0 {
			t.Errorf("request at %s answered %d times by an older dump", q.CreatedAt, n)
		}
	}
	if !fleetRequested(t, f) {
		t.Error("no fresh dump requested for the requests newer than every dump")
	}
}

// TestFleetRequestWaitsForARetriedDump: a request older than a dump whose sealing is backing off waits for that dump's
// next attempt instead of asking for another dump.
func TestFleetRequestWaitsForARetriedDump(t *testing.T) {
	f := fleetRequestFixture(t)
	dumpAt := f.now.Add(-time.Minute)
	writeDump(t, f, dumpAt)
	f.engine.fleetFailed[dumpAt.Format("20060102T150405Z")+".sql.gz"] = f.now
	req := RequestedRun{ID: uuid.New(), Kind: KindFleet, CreatedAt: dumpAt.Add(-time.Minute)}
	f.store.requests = []RequestedRun{req}
	f.round(t)
	if runs := fleetRuns(f); len(runs) != 0 {
		t.Fatalf("fleet runs %+v during the back-off, want none", runs)
	}
	if fleetRequested(t, f) {
		t.Error("a dump was requested although a dump newer than the request waits")
	}
}
