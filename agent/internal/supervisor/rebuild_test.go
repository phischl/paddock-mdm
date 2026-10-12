package supervisor

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// corruptSwitch points current at B, which holds an agent that reports version and runs run, next to 1.0.0 in A,
// and leaves an unreadable probation log, as disk corruption after the switch would.
func (f *fake) corruptSwitch(version, run string) {
	f.t.Helper()
	f.writeExec(filepath.Join(f.cfg.Slots, "B", "paddockd"), script(version, 0, run))
	if err := flip(f.cfg.Slots, "B", syncDir); err != nil {
		f.t.Fatal(err)
	}
	if err := os.WriteFile(f.cfg.ProbationLog, []byte(`{"version":"1.1`), 0o600); err != nil {
		f.t.Fatal(err)
	}
}

// writeResult writes an update result for 1.1.0 over 1.0.0 with outcome and returns it.
func (f *fake) writeResult(outcome string) result {
	f.t.Helper()
	r := result{Version: "1.1.0", FromVersion: "1.0.0", Outcome: outcome, At: time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)}
	res := map[string]any{"version": r.Version, "from_version": r.FromVersion, "outcome": r.Outcome, "at": r.At}
	if err := writeJSON(f.cfg.Result, res, syncFile); err != nil {
		f.t.Fatal(err)
	}
	return r
}

// expectRebuiltLog checks that the probation log on disk is the probation rebuilt from the slots.
func (f *fake) expectRebuiltLog() {
	f.t.Helper()
	var p probation
	data, err := os.ReadFile(f.cfg.ProbationLog)
	if err == nil {
		err = json.Unmarshal(data, &p)
	}
	if err != nil || !p.Rebuilt || p.Version != "1.1.0" || p.FromVersion != "1.0.0" || p.FromSlot != "A" || p.ToSlot != "B" ||
		p.Outcome != "" || p.SwitchedAt.IsZero() {
		f.t.Fatalf("probation log %s, error %v; want the rebuilt probation of 1.1.0 (B) over 1.0.0 (A)", data, err)
	}
}

// TestUnreadableLogAfterASwitchIsRebuilt (PDK-062, plan M2b decision 16, amendment 2026-10-12): an unreadable
// probation log while current points at a release newer than the other slot's is rebuilt from the slots, and the
// probation runs again with a fresh window and a cleared check-in mark, so it ends in updated or rolled_back.
func TestUnreadableLogAfterASwitchIsRebuilt(t *testing.T) {
	t.Run("healthy agent", func(t *testing.T) {
		log := captureLog(t)
		f := newFake(t)
		f.corruptSwitch("1.1.0", f.good())
		f.start()
		f.waitReady()
		f.expectRebuiltLog()
		if !strings.Contains(log.String(), `level=ERROR msg="the probation log was unreadable; rebuilt the probation from the slots"`) {
			t.Fatalf("no error about the rebuilt probation:\n%s", log.String())
		}
		f.waitFor("the new agent checked in", f.checkedIn)
		if r := f.endProbation("B"); r.Outcome != outcomeUpdated || r.Version != "1.1.0" || r.FromVersion != "1.0.0" || f.active() != "B" {
			t.Fatalf("result %+v, current %s", r, f.active())
		}
		f.waitNoProbationLog()
	})
	t.Run("agent that never checks in", func(t *testing.T) {
		f := newFake(t)
		f.corruptSwitch("1.1.0", "trap '' HUP; exec sleep 300")
		// A mark from before the restart must not pass the rebuilt probation.
		if err := os.WriteFile(f.cfg.LastCheckin, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		f.start()
		f.waitFor("the supervisor removed the earlier check-in", func() bool { return !f.checkedIn() })
		if r := f.endProbation("B"); r.Outcome != outcomeRolledBack || r.Version != "1.1.0" || f.active() != "A" {
			t.Fatalf("result %+v, current %s", r, f.active())
		}
		f.waitNoProbationLog()
	})
	t.Run("rebuilt log cannot be written", func(t *testing.T) {
		f := newFake(t)
		f.corruptSwitch("1.1.0", f.good())
		f.failLogWrites()
		f.start()
		f.waitReady()
		f.waitFor("the new agent checked in", f.checkedIn)
		if r := f.endProbation("B"); r.Outcome != outcomeUpdated || r.Version != "1.1.0" || f.active() != "B" {
			t.Fatalf("result %+v, current %s", r, f.active())
		}
	})
}

// TestUnreadableLogIsDroppedUnlessTheSlotsDescribeASwitch (PDK-062): each failed precondition of the rebuild drops
// the unreadable log as before (PDK-060), without a result and without touching current, and logs the reason.
func TestUnreadableLogIsDroppedUnlessTheSlotsDescribeASwitch(t *testing.T) {
	for _, tc := range []struct {
		name    string
		prepare func(f *fake)
		current string
		reason  string
	}{
		{name: "current on neither slot", current: "C", reason: "current points at neither slot",
			prepare: func(f *fake) {
				// C holds a newer agent, so only the slot check keeps the log from being rebuilt.
				if err := os.MkdirAll(filepath.Join(f.cfg.Slots, "C"), 0o755); err != nil {
					f.t.Fatal(err)
				}
				f.writeExec(filepath.Join(f.cfg.Slots, "C", "paddockd"), script("1.2.0", 0, f.good()))
				if err := flip(f.cfg.Slots, "C", syncDir); err != nil {
					f.t.Fatal(err)
				}
			}},
		{name: "other slot empty", current: "B", reason: "the other slot holds no agent with a valid version",
			prepare: func(f *fake) {
				if err := os.Remove(filepath.Join(f.cfg.Slots, "A", "paddockd")); err != nil {
					f.t.Fatal(err)
				}
			}},
		{name: "other slot without a valid version", current: "B", reason: "the other slot holds no agent with a valid version",
			prepare: func(f *fake) {
				f.writeExec(filepath.Join(f.cfg.Slots, "A", "paddockd"), script("garbage", 0, f.good()))
			}},
		{name: "active slot without a valid version", current: "B", reason: "the active agent is not newer than the other slot's",
			prepare: func(f *fake) {
				f.writeExec(filepath.Join(f.cfg.Slots, "B", "paddockd"), script("garbage", 0, f.good()))
			}},
		{name: "active version equal", current: "B", reason: "the active agent is not newer than the other slot's",
			prepare: func(f *fake) { f.writeExec(filepath.Join(f.cfg.Slots, "B", "paddockd"), script("1.0.0", 0, f.good())) }},
		{name: "active version older", current: "B", reason: "the active agent is not newer than the other slot's",
			prepare: func(f *fake) {
				f.writeExec(filepath.Join(f.cfg.Slots, "B", "paddockd"), script("1.0.0-rc.1", 0, f.good()))
			}},
		{name: "active version already updated", current: "B", reason: "the update result names the active agent as updated",
			prepare: func(f *fake) { f.writeResult(outcomeUpdated) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			log := captureLog(t)
			f := newFake(t)
			f.corruptSwitch("1.1.0", f.good())
			tc.prepare(f)
			before, _ := os.ReadFile(f.cfg.Result)
			f.start()
			f.waitReady()
			f.expectNoProbationLog()
			if after, _ := os.ReadFile(f.cfg.Result); string(after) != string(before) {
				t.Fatalf("result %s after the drop, want %s", after, before)
			}
			if f.active() != tc.current {
				t.Fatalf("current → %s, want %s", f.active(), tc.current)
			}
			if !strings.Contains(log.String(), `msg="dropping an unreadable probation log"`) || !strings.Contains(log.String(), tc.reason) {
				t.Fatalf("no drop with the reason %q in the log:\n%s", tc.reason, log.String())
			}
		})
	}
}

// TestUnreadableLogWithARollbackResultResumesTheRollback (PDK-062, ADR 0024 rule 5): when the result names the active
// release as rollback_failed or rolled_back, the flip back failed or was lost; the rebuilt log resumes the pending
// rollback instead of a probation, so the release is not decided anew.
func TestUnreadableLogWithARollbackResultResumesTheRollback(t *testing.T) {
	t.Run("rollback_failed, flip still blocked", func(t *testing.T) {
		log := captureLog(t)
		f := newFake(t)
		f.corruptSwitch("1.1.0", f.good())
		failed := f.writeResult(outcomeRollbackFailed)
		f.blockFlip()
		f.start()
		f.waitFor("the first retry", func() bool { return retries(log) == 1 })
		f.expectPendingLog()
		if r := f.waitResult(time.Second); r != failed || f.active() != "B" {
			t.Fatalf("result %+v, current %s; want the recorded %+v on B", r, f.active(), failed)
		}
		f.unblockFlip()
		f.clock.set(time.Hour)
		defer f.clock.set(0)
		if r := f.waitOutcome(outcomeRolledBack); r.At.Equal(failed.At) || f.active() != "A" {
			t.Fatalf("result %+v, current %s", r, f.active())
		}
		f.waitNoProbationLog()
	})
	t.Run("rolled_back, flip back lost", func(t *testing.T) {
		f := newFake(t)
		f.corruptSwitch("1.1.0", f.good())
		lost := f.writeResult(outcomeRolledBack)
		f.runRecordingPID("A")
		f.start()
		f.waitFor("a new rolled_back after the retried flip back", func() bool {
			r := f.waitResult(10 * time.Second)
			return r.Outcome == outcomeRolledBack && !r.At.Equal(lost.At)
		})
		if f.active() != "A" {
			t.Fatalf("current → %s, want A", f.active())
		}
		f.waitNoProbationLog()
		f.waitAgentRuns("A")
	})
}
