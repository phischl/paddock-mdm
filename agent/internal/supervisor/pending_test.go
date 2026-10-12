package supervisor

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// runRecordingPID makes the agent in slot run and record "<slot> <pid>", so a test can see which agent runs.
func (f *fake) runRecordingPID(slot string) {
	f.t.Helper()
	version := map[string]string{"A": "1.0.0", "B": "1.1.0"}[slot]
	f.writeExec(filepath.Join(f.cfg.Slots, slot, "paddockd"),
		script(version, 0, "trap '' HUP; echo "+slot+" $$ > "+filepath.Join(f.dir, "running")+"; exec sleep 300"))
}

// waitAgentRuns waits until the agent of slot that recorded its pid is alive.
func (f *fake) waitAgentRuns(slot string) {
	f.t.Helper()
	f.waitFor("the agent of slot "+slot+" runs", func() bool {
		data, err := os.ReadFile(filepath.Join(f.dir, "running"))
		if err != nil {
			return false
		}
		var got string
		var pid int
		if _, err := fmt.Sscan(string(data), &got, &pid); err != nil || got != slot {
			return false
		}
		return syscall.Kill(pid, 0) == nil
	})
}

// expectPendingLog checks that the probation log is kept and records a pending rollback from B to A.
func (f *fake) expectPendingLog() {
	f.t.Helper()
	var p probation
	data, err := os.ReadFile(f.cfg.ProbationLog)
	if err == nil {
		err = json.Unmarshal(data, &p)
	}
	if err != nil || !p.RollbackPending || p.Outcome != outcomeRollbackFailed || p.FromSlot != "A" || p.ToSlot != "B" {
		f.t.Fatalf("probation log %s, error %v; want a pending rollback from B to A", data, err)
	}
}

// waitTicks waits until n ticks of the Run loop began after the call, so at least n-1 checks ran completely after it.
func (f *fake) waitTicks(n int) {
	f.t.Helper()
	for len(f.notices) > 0 {
		<-f.notices
	}
	deadline := time.After(10 * time.Second)
	for n > 0 {
		select {
		case s := <-f.notices:
			if s == "WATCHDOG=1" {
				n--
			}
		case <-deadline:
			f.t.Fatal("timed out waiting for ticks")
		}
	}
}

// manualClock is a clock that only the test moves, so the supervisor's waits can be checked exactly.
type manualClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *manualClock) get() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *manualClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// retries counts the failed retries of a pending rollback that the supervisor logged at error level.
func retries(log *lockedBuffer) int {
	return strings.Count(log.String(), `level=ERROR msg="retrying the rollback failed`)
}

// waitOutcome waits until the update result has outcome and returns it.
func (f *fake) waitOutcome(outcome string) result {
	f.t.Helper()
	var r result
	f.waitFor("the result "+outcome, func() bool { r = f.waitResult(10 * time.Second); return r.Outcome == outcome })
	return r
}

// TestPendingRollbackIsRetriedWithBackOff (ADR 0024): after the immediate attempts failed, the supervisor retries the
// flip back on its tick, one attempt per retry slot, waiting 10 s and doubling up to 5 minutes, each failure logged at
// error level; once the blocker is gone the retry flips back, restarts the old agent and reports rolled_back anew.
func TestPendingRollbackIsRetriedWithBackOff(t *testing.T) {
	log := captureLog(t)
	f := newFake(t)
	mc := &manualClock{now: time.Date(2026, 10, 12, 0, 0, 0, 0, time.UTC)}
	f.cfg.Now = mc.get
	f.resumeFailingProbation(func(time.Duration) {})
	f.runRecordingPID("A")
	f.blockFlip()
	f.start()
	failed := f.waitResult(10 * time.Second)
	if failed.Outcome != outcomeRollbackFailed {
		t.Fatalf("result %+v", failed)
	}
	for i, wait := range []time.Duration{10 * time.Second, 20 * time.Second, 40 * time.Second, 80 * time.Second,
		160 * time.Second, 300 * time.Second, 300 * time.Second, 300 * time.Second} {
		mc.advance(wait - time.Nanosecond)
		f.waitTicks(3)
		if got := retries(log); got != i {
			t.Fatalf("%d retries before the wait of %s ended, want %d", got, wait, i)
		}
		mc.advance(time.Nanosecond)
		f.waitFor(fmt.Sprintf("retry %d after %s", i+1, wait), func() bool { return retries(log) == i+1 })
		if f.active() != "B" {
			t.Fatalf("current → %s, want B", f.active())
		}
	}
	if !strings.Contains(log.String(), "attempt=8 active_slot=B target_slot=A") {
		t.Fatalf("retry log without attempt and slots:\n%s", log.String())
	}
	f.expectPendingLog()
	f.unblockFlip()
	mc.advance(pendingRetryMax)
	if r := f.waitOutcome(outcomeRolledBack); r.Version != "1.1.0" || r.At.Equal(failed.At) || f.active() != "A" {
		t.Fatalf("result %+v, current %s", r, f.active())
	}
	f.waitNoProbationLog()
	f.waitAgentRuns("A")
}

// writeDecidedLog points current at slot and writes a probation log of 1.1.0 (B) over 1.0.0 (A) that recorded
// outcome, as a pending rollback if pending; it returns the recorded decision time.
func (f *fake) writeDecidedLog(slot, outcome string, pending bool) time.Time {
	f.t.Helper()
	decided := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	if err := flip(f.cfg.Slots, slot, syncDir); err != nil {
		f.t.Fatal(err)
	}
	p := probation{Version: "1.1.0", FromVersion: "1.0.0", FromSlot: "A", ToSlot: "B", Outcome: outcome, DecidedAt: decided,
		RollbackPending: pending}
	if err := writeJSON(f.cfg.ProbationLog, p, syncFile); err != nil {
		f.t.Fatal(err)
	}
	return decided
}

// TestRestartResumesAPendingRollback (ADR 0024 rule 5): a restarted supervisor resumes a pending rollback. With
// current on the new slot it writes the recorded rollback_failed again unchanged and goes on retrying; with current on
// the previous slot it confirms the flip and concludes rolled_back; a recorded rolled_back whose flip back was lost
// (current on the new slot) is retried instead of reported again, and becomes rollback_failed if that retry fails.
func TestRestartResumesAPendingRollback(t *testing.T) {
	t.Run("pending, current on the new slot", func(t *testing.T) {
		log := captureLog(t)
		f := newFake(t)
		f.runRecordingPID("B")
		decided := f.writeDecidedLog("B", outcomeRollbackFailed, true)
		f.blockFlip()
		f.start()
		if r := f.waitResult(10 * time.Second); r.Outcome != outcomeRollbackFailed || !r.At.Equal(decided) {
			t.Fatalf("result %+v, want the recorded rollback_failed at %s", r, decided)
		}
		f.waitFor("the first retry", func() bool { return retries(log) == 1 })
		f.expectPendingLog()
		f.waitAgentRuns("B")
		f.unblockFlip()
		f.clock.set(time.Hour)
		if r := f.waitOutcome(outcomeRolledBack); r.At.Equal(decided) || f.active() != "A" {
			t.Fatalf("result %+v, current %s", r, f.active())
		}
		f.waitNoProbationLog()
	})
	t.Run("pending, current on the previous slot", func(t *testing.T) {
		f := newFake(t)
		f.writeExec(filepath.Join(f.cfg.Slots, "B", "paddockd"), script("1.1.0", 0, f.good()))
		decided := f.writeDecidedLog("A", outcomeRollbackFailed, true)
		f.start()
		if r := f.waitResult(10 * time.Second); r.Outcome != outcomeRolledBack || r.At.Equal(decided) || f.active() != "A" {
			t.Fatalf("result %+v, current %s", r, f.active())
		}
		f.waitNoProbationLog()
	})
	t.Run("rolled back, flip back lost, retry fails", func(t *testing.T) {
		f := newFake(t)
		f.runRecordingPID("B")
		f.writeDecidedLog("B", outcomeRolledBack, false)
		f.blockFlip()
		f.start()
		if r := f.waitResult(10 * time.Second); r.Outcome != outcomeRollbackFailed || f.active() != "B" {
			t.Fatalf("result %+v, current %s", r, f.active())
		}
		f.expectPendingLog()
		f.waitAgentRuns("B")
	})
	t.Run("rolled back, flip back lost, retry succeeds", func(t *testing.T) {
		f := newFake(t)
		f.writeExec(filepath.Join(f.cfg.Slots, "B", "paddockd"), script("1.1.0", 0, f.good()))
		f.runRecordingPID("A")
		decided := f.writeDecidedLog("B", outcomeRolledBack, false)
		f.start()
		if r := f.waitResult(10 * time.Second); r.Outcome != outcomeRolledBack || r.At.Equal(decided) || f.active() != "A" {
			t.Fatalf("result %+v, current %s", r, f.active())
		}
		f.waitNoProbationLog()
		f.waitAgentRuns("A")
	})
}

// TestDowngradeIsRefusedWhileARollbackIsPending (ADR 0024 rules 6 and 7): there is no way back through the update
// channel. A release staged while the rollback is pending, also the previous version, is ignored: it neither switches
// current nor replaces the pending rollback and its result.
func TestDowngradeIsRefusedWhileARollbackIsPending(t *testing.T) {
	log := captureLog(t)
	f := newFake(t)
	f.resumeFailingProbation(func(time.Duration) {})
	f.blockFlip()
	f.start()
	failed := f.waitResult(10 * time.Second)
	if failed.Outcome != outcomeRollbackFailed {
		t.Fatalf("result %+v", failed)
	}
	f.stage("1.0.0", script("1.0.0", 0, f.good()), nil)
	f.waitFor("the update request was ignored", func() bool { return strings.Contains(log.String(), "update request ignored") })
	if r := f.waitResult(time.Second); r != failed || f.active() != "B" {
		t.Fatalf("result %+v, current %s; want the pending rollback's result %+v on B", r, f.active(), failed)
	}
	f.expectPendingLog()
}

// failLogWrites makes every write of the probation log fail at its content sync, before the rename, so the log on
// disk stays as it was, until the returned flag is cleared.
func (f *fake) failLogWrites() *atomic.Bool {
	broken := &atomic.Bool{}
	broken.Store(true)
	f.cfg.SyncFile = func(file *os.File) error {
		if broken.Load() && file.Name() == f.cfg.ProbationLog+".tmp" {
			return errors.New("injected write failure")
		}
		return file.Sync()
	}
	return broken
}

// expectUndecidedLog checks that the probation log on disk is still the switch's log, without a decision.
func (f *fake) expectUndecidedLog() {
	f.t.Helper()
	var p probation
	data, err := os.ReadFile(f.cfg.ProbationLog)
	if err == nil {
		err = json.Unmarshal(data, &p)
	}
	if err != nil || p.Outcome != "" || p.RollbackPending || p.ToSlot != "B" {
		f.t.Fatalf("probation log %s, error %v; want the undecided log of the switch to B", data, err)
	}
}

// pendingOnDisk reports whether the probation log on disk records the pending rollback.
func (f *fake) pendingOnDisk() bool {
	var p probation
	data, err := os.ReadFile(f.cfg.ProbationLog)
	return err == nil && json.Unmarshal(data, &p) == nil && p.RollbackPending && p.Outcome == outcomeRollbackFailed
}

// TestUnrecordedPendingRollbackIsRecordedOnALaterTick (review 1 of PDK-043): if the probation log cannot record
// rollback_failed, the result is reported all the same and the supervisor rewrites the log on a later tick, so the
// log on disk never stays the undecided switch log from which a restart would decide the probation anew.
func TestUnrecordedPendingRollbackIsRecordedOnALaterTick(t *testing.T) {
	f := newFake(t)
	f.resumeFailingProbation(func(time.Duration) {})
	broken := f.failLogWrites()
	f.blockFlip()
	f.start()
	if r := f.waitResult(10 * time.Second); r.Outcome != outcomeRollbackFailed {
		t.Fatalf("result %+v", r)
	}
	f.waitTicks(3)
	f.expectUndecidedLog()
	broken.Store(false)
	f.waitFor("the pending rollback was recorded in the probation log", f.pendingOnDisk)
	f.expectPendingLog()
}

// TestRestartBeforeThePendingRollbackIsRecorded (review 1 of PDK-043): a restart while the log still is the undecided
// switch log does not decide the probation anew, although the new agent now checks in and its probation would pass:
// the result names the release as rollback_failed, so the supervisor resumes the pending rollback (ADR 0024 rule 5),
// writes the same result again, records the decision in the log and goes on retrying.
func TestRestartBeforeThePendingRollbackIsRecorded(t *testing.T) {
	log := captureLog(t)
	f := newFake(t)
	f.resumeFailingProbation(func(time.Duration) {})
	broken := f.failLogWrites()
	f.blockFlip()
	f.start()
	failed := f.waitResult(10 * time.Second)
	if failed.Outcome != outcomeRollbackFailed {
		t.Fatalf("result %+v", failed)
	}
	f.stop()
	f.expectUndecidedLog()
	broken.Store(false)
	if err := os.RemoveAll(f.cfg.LastCheckin); err != nil {
		t.Fatal(err)
	}
	f.writeExec(filepath.Join(f.cfg.Slots, "B", "paddockd"), script("1.1.0", 0, f.good()))
	f.start()
	f.waitFor("a retry of the resumed rollback", func() bool { return retries(log) == 1 })
	f.expectPendingLog()
	f.clock.set(testProbation + time.Minute)
	defer f.clock.set(0)
	f.waitTicks(3)
	if r := f.waitResult(time.Second); r != failed || f.active() != "B" {
		t.Fatalf("result %+v, current %s; want the first result %+v on B", r, f.active(), failed)
	}
}
