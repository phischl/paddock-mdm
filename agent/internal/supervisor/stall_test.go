package supervisor

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/pkg/releasesig"
)

// deferredMsg is the warning of one deferred attempt.
const deferredMsg = `level=WARN msg="update request deferred: the active agent did not report its version in time"`

// stallVersion puts an agent of version into slot whose version calls time out (Config.Version returns
// versionTimedOut, without a real timeout) until the returned release function ran, or while f.versionStalled is set
// again; every other call runs the agent as the supervisor does. The supervisor's clock is the returned manual clock,
// so that only the test ends the wait before a deferred attempt.
func (f *fake) stallVersion(slot, version, run string) (release func(), clock *manualClock) {
	f.t.Helper()
	clock = &manualClock{now: time.Date(2026, 11, 16, 0, 0, 0, 0, time.UTC)}
	f.cfg.Now = clock.get
	f.writeExec(filepath.Join(f.cfg.Slots, slot, "paddockd"), script(version, 0, run))
	stalled, err := filepath.EvalSymlinks(filepath.Join(f.cfg.Slots, slot))
	if err != nil {
		f.t.Fatal(err)
	}
	f.versionStalled.Store(true)
	f.cfg.Version = func(dir string) string {
		if real, _ := filepath.EvalSymlinks(dir); real == stalled && f.versionStalled.Load() {
			f.stalledCalls.Add(1)
			return versionTimedOut
		}
		return runVersion(dir, 10*time.Second)
	}
	return func() { f.versionStalled.Store(false) }, clock
}

// expectDeferred waits until the supervisor has deferred the update request n times, and checks that nothing was
// decided meanwhile: no result, current on A, nothing installed into B, the request still staged.
func (f *fake) expectDeferred(log *lockedBuffer, n int) {
	f.t.Helper()
	f.waitFor(fmt.Sprintf("the request was deferred %d times", n), func() bool { return strings.Count(log.String(), deferredMsg) >= n })
	if _, err := os.Stat(f.cfg.Result); err == nil {
		f.t.Fatal("an update result was written while the active agent's version call timed out")
	}
	if _, err := os.Stat(filepath.Join(f.cfg.Slots, "B", "paddockd")); err == nil || f.active() != "A" {
		f.t.Fatalf("the release was installed (error %v) or switched to (current %s)", err, f.active())
	}
	if _, err := os.Stat(filepath.Join(f.cfg.Staging, "request.json")); err != nil {
		f.t.Fatalf("the update request was not kept: %v", err)
	}
}

// TestStalledVersionDefersTheUpdateRequest (PDK-1118, plan M2b amendment 2026-11-16): an active agent whose version
// call times out has not failed; a release is neither installed nor refused until it reports its version, so a disk
// stall never lets a release that is not newer pass the downgrade refusal.
func TestStalledVersionDefersTheUpdateRequest(t *testing.T) {
	t.Run("older release is refused once the agent answers", func(t *testing.T) {
		log := captureLog(t)
		f := newFake(t)
		release, clock := f.stallVersion("A", "1.0.0", f.good())
		f.start()
		f.waitSent()
		f.stageSigned("0.9.0", script("0.9.0", 0, f.good()), nil, releasesig.Comment("0.9.0", runtime.GOARCH))
		f.expectDeferred(log, 1)
		release()
		clock.advance(pendingRetryStart)
		if r := f.waitResult(10 * time.Second); r.Outcome != outcomeDowngradeRefused || r.Version != "0.9.0" || r.FromVersion != "1.0.0" {
			t.Fatalf("result %+v", r)
		}
		if f.active() != "A" {
			t.Fatalf("switched to %s", f.active())
		}
		f.expectStagingClean()
	})
	t.Run("newer release is installed once the agent answers", func(t *testing.T) {
		log := captureLog(t)
		f := newFake(t)
		release, clock := f.stallVersion("A", "1.0.0", f.good())
		f.start()
		// The agent checks in before Run looks for a request left from before the restart: a request staged in between
		// is deferred twice, by resumeRequest and by the SIGUSR1, and the second wait of 20 s outlasts the advance
		// below (PDK-1132). The first tick comes after that look.
		f.waitSent()
		f.waitFor("the running agent checked in", f.checkedIn)
		if err := os.Remove(f.cfg.LastCheckin); err != nil {
			t.Fatal(err)
		}
		f.stage("1.1.0", script("1.1.0", 0, f.good()), nil)
		f.expectDeferred(log, 1)
		release()
		clock.advance(pendingRetryStart)
		f.waitFor("the new agent checked in", f.checkedIn)
		clock.advance(testProbation + time.Minute)
		if r := f.waitResult(10 * time.Second); r.Outcome != outcomeUpdated || r.Version != "1.1.0" || r.FromVersion != "1.0.0" || f.active() != "B" {
			t.Fatalf("result %+v, current %s", r, f.active())
		}
	})
	t.Run("request left from before the restart", func(t *testing.T) {
		log := captureLog(t)
		f := newFake(t)
		release, clock := f.stallVersion("A", "1.0.0", f.good())
		f.stage("0.9.0", script("0.9.0", 0, f.good()), nil)
		f.start()
		// resumeRequest tries at once, without a wait; the SIGUSR1 that stage left in the channel is a second attempt.
		f.expectDeferred(log, 2)
		release()
		clock.advance(2 * pendingRetryStart)
		if r := f.waitResult(10 * time.Second); r.Outcome != outcomeDowngradeRefused || r.FromVersion != "1.0.0" || f.active() != "A" {
			t.Fatalf("result %+v, current %s", r, f.active())
		}
	})
	t.Run("retries back off and each attempt warns once", func(t *testing.T) {
		log := captureLog(t)
		f := newFake(t)
		_, clock := f.stallVersion("A", "1.0.0", f.good())
		f.start()
		f.waitSent()
		f.stage("1.1.0", script("1.1.0", 0, f.good()), nil)
		f.expectDeferred(log, 1)
		// Each step: the clock just before the attempt is due keeps the request waiting for 10 of the supervisor's
		// ticks; at the due time the next attempt follows.
		for i, wait := range []time.Duration{10 * time.Second, 20 * time.Second, 40 * time.Second} {
			if !strings.Contains(log.String(), fmt.Sprintf("next_attempt_in=%s", wait)) {
				t.Fatalf("attempt %d: no warning with the wait %s:\n%s", i+1, wait, log.String())
			}
			clock.advance(wait - time.Second)
			f.waitTicks(10)
			if n := strings.Count(log.String(), deferredMsg); n != i+1 {
				t.Fatalf("%d deferred attempts before the wait of %s ended, want %d:\n%s", n, wait, i+1, log.String())
			}
			clock.advance(time.Second)
			f.expectDeferred(log, i+2)
		}
		f.waitTicks(1)
		if calls, n := int(f.stalledCalls.Load()), strings.Count(log.String(), deferredMsg); calls != n {
			t.Fatalf("%d version calls of the active agent, %d warnings: want one warning per attempt", calls, n)
		}
	})
	t.Run("the wait starts again after a request ended", func(t *testing.T) {
		log := captureLog(t)
		f := newFake(t)
		release, clock := f.stallVersion("A", "1.0.0", f.good())
		f.start()
		f.waitSent()
		f.stage("0.9.0", script("0.9.0", 0, f.good()), nil)
		f.expectDeferred(log, 1)
		clock.advance(pendingRetryStart)
		f.expectDeferred(log, 2) // the next wait is 20 s
		release()
		clock.advance(2 * pendingRetryStart)
		if r := f.waitResult(10 * time.Second); r.Outcome != outcomeDowngradeRefused {
			t.Fatalf("result %+v", r)
		}
		if err := os.Remove(f.cfg.Result); err != nil {
			t.Fatal(err)
		}
		f.versionStalled.Store(true)
		f.stage("0.9.1", script("0.9.1", 0, f.good()), nil)
		f.expectDeferred(log, 3)
		if last := log.String()[strings.LastIndex(log.String(), deferredMsg):]; !strings.Contains(last, "next_attempt_in=10s") {
			t.Fatalf("the wait after an ended request did not start at 10 s: %s", last)
		}
	})
	// An agent that runs its version command and fails still counts as failed, as before: any signed release may
	// replace it (TestReleaseBinding covers one that exits non-zero).
	t.Run("older release replaces an agent with invalid version output", func(t *testing.T) {
		f := newFake(t)
		f.writeExec(filepath.Join(f.cfg.Slots, "A", "paddockd"), script("not-a-version", 0, f.good()))
		f.start()
		f.stageAfterCheckin("0.9.0", script("0.9.0", 0, f.good()))
		f.waitFor("the new agent checked in", f.checkedIn)
		if r := f.endProbation("B"); r.Outcome != outcomeUpdated || r.Version != "0.9.0" || r.FromVersion != "not-a-version" {
			t.Fatalf("result %+v", r)
		}
	})
}

// keptMsg is the error of a kept unreadable probation log.
const keptMsg = `level=ERROR msg="keeping the unreadable probation log: a slot's version call timed out"`

// expectKept checks that the unreadable log of corruptSwitch stays, that nothing was decided and current is on B.
func (f *fake) expectKept(log *lockedBuffer, n int) {
	f.t.Helper()
	f.waitFor(fmt.Sprintf("the log was kept %d times", n), func() bool { return strings.Count(log.String(), keptMsg) >= n })
	if data, err := os.ReadFile(f.cfg.ProbationLog); err != nil || string(data) != `{"version":"1.1` {
		f.t.Fatalf("probation log %q, error %v; want the unreadable log kept", data, err)
	}
	f.expectNoResult()
	if f.active() != "B" {
		f.t.Fatalf("current → %s, want B", f.active())
	}
}

// TestStalledVersionKeepsTheUnreadableLog (PDK-1118, plan M2b fix batch 2026-11-16, M2): a slot whose version call
// times out while an unreadable probation log is rebuilt only looks version-less; the log stays and is rebuilt again
// on the deferral's back-off, and no update request is processed meanwhile.
func TestStalledVersionKeepsTheUnreadableLog(t *testing.T) {
	for _, slot := range []string{"B", "A"} {
		t.Run("stalled slot "+slot, func(t *testing.T) {
			log := captureLog(t)
			f := newFake(t)
			f.corruptSwitch("1.1.0", f.good())
			version := map[string]string{"A": "1.0.0", "B": "1.1.0"}[slot]
			f.stallVersion(slot, version, f.good())
			// The switch's request stays while the log is kept, also when the active slot answers (resumeRequest
			// would otherwise remove it as a request for the running version).
			request := filepath.Join(f.cfg.Staging, "request.json")
			if err := os.WriteFile(request, []byte(`{"version":"1.1.0"}`), 0o600); err != nil {
				t.Fatal(err)
			}
			f.start()
			f.waitReady()
			f.expectKept(log, 1)
			f.waitTicks(3)
			if _, err := os.Stat(request); err != nil {
				t.Fatalf("the request was not kept: %v", err)
			}
		})
	}
	t.Run("a release that never checks in is rolled back once the stall ends", func(t *testing.T) {
		log := captureLog(t)
		f := newFake(t)
		f.corruptSwitch("1.1.0", "trap '' HUP; exec sleep 300")
		release, clock := f.stallVersion("B", "1.1.0", "trap '' HUP; exec sleep 300")
		f.start()
		f.waitReady()
		f.expectKept(log, 1)
		release()
		clock.advance(pendingRetryStart)
		f.waitFor("the probation was rebuilt", func() bool {
			return strings.Contains(log.String(), "rebuilt the probation from the slots")
		})
		clock.advance(testProbation)
		if r := f.waitResult(10 * time.Second); r.Outcome != outcomeRolledBack || r.Version != "1.1.0" || f.active() != "A" {
			t.Fatalf("result %+v, current %s", r, f.active())
		}
	})
	t.Run("a request left from the switch is not processed for the running release", func(t *testing.T) {
		log := captureLog(t)
		f := newFake(t)
		// The agent checks in again and again, as paddockd does: the rebuilt probation clears the mark of its start.
		checksIn := "trap '' HUP; while :; do : >" + f.cfg.LastCheckin + "; sleep 0.1; done"
		f.corruptSwitch("1.1.0", checksIn)
		release, clock := f.stallVersion("B", "1.1.0", checksIn)
		// The switch's request: its release directory is gone, so processing it would report signature_invalid.
		if err := os.WriteFile(filepath.Join(f.cfg.Staging, "request.json"), []byte(`{"version":"1.1.0"}`), 0o600); err != nil {
			t.Fatal(err)
		}
		f.start()
		f.waitReady()
		f.expectKept(log, 1)
		release()
		f.usr1 <- syscall.SIGUSR1
		f.waitFor("the request was ignored", func() bool { return strings.Contains(log.String(), "update request ignored") })
		f.waitTicks(3)
		f.expectNoResult()
		clock.advance(pendingRetryStart)
		// "resuming probation" follows the removal of the check-in mark, so the mark seen next is a new check-in.
		f.waitFor("the rebuilt probation resumed", func() bool { return strings.Contains(log.String(), `msg="resuming probation"`) })
		f.waitFor("the agent checked in again", f.checkedIn)
		clock.advance(testProbation)
		if r := f.waitResult(10 * time.Second); r.Outcome != outcomeUpdated || r.Version != "1.1.0" || f.active() != "B" {
			t.Fatalf("result %+v, current %s", r, f.active())
		}
	})
	t.Run("retries back off while the stall lasts", func(t *testing.T) {
		log := captureLog(t)
		f := newFake(t)
		f.corruptSwitch("1.1.0", f.good())
		_, clock := f.stallVersion("B", "1.1.0", f.good())
		if err := os.WriteFile(filepath.Join(f.cfg.Staging, "request.json"), []byte(`{"version":"1.1.0"}`), 0o600); err != nil {
			t.Fatal(err)
		}
		f.start()
		f.waitReady()
		f.expectKept(log, 1)
		for i, wait := range []time.Duration{10 * time.Second, 20 * time.Second, 40 * time.Second, 80 * time.Second,
			160 * time.Second, 300 * time.Second, 300 * time.Second} {
			if last := log.String()[strings.LastIndex(log.String(), keptMsg):]; !strings.Contains(last, fmt.Sprintf("next_attempt_in=%s", wait)) {
				t.Fatalf("attempt %d: no wait of %s: %s", i+1, wait, last)
			}
			clock.advance(wait - time.Second)
			f.waitTicks(3)
			if n := strings.Count(log.String(), keptMsg); n != i+1 {
				t.Fatalf("%d attempts before the wait of %s ended, want %d", n, wait, i+1)
			}
			clock.advance(time.Second)
			f.expectKept(log, i+2)
		}
		if _, err := os.Stat(filepath.Join(f.cfg.Staging, "request.json")); err != nil {
			t.Fatalf("the request was not kept: %v", err)
		}
	})
	t.Run("a pending rollback continues once the stall ends", func(t *testing.T) {
		log := captureLog(t)
		f := newFake(t)
		f.corruptSwitch("1.1.0", f.good())
		release, clock := f.stallVersion("B", "1.1.0", f.good())
		if err := writeJSON(filepath.Join(filepath.Dir(f.cfg.ProbationLog), "rollback-pending"), "1.1.0", syncFile); err != nil {
			t.Fatal(err)
		}
		f.start()
		f.waitReady()
		f.expectKept(log, 1)
		release()
		clock.advance(pendingRetryStart)
		if r := f.waitOutcome(outcomeRolledBack); r.Version != "1.1.0" || f.active() != "A" {
			t.Fatalf("result %+v, current %s", r, f.active())
		}
	})
}

// TestStalledSelfTestKeepsTheCheckedVersion (PDK-1118, plan M2b fix batch 2026-11-16, m3): the version of the active
// agent that onRequest checked is the switch's from_version; a version call that times out after that check never
// reaches the probation log or the result.
func TestStalledSelfTestKeepsTheCheckedVersion(t *testing.T) {
	f := newFake(t)
	active, err := filepath.EvalSymlinks(filepath.Join(f.cfg.Slots, "A"))
	if err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	f.cfg.Version = func(dir string) string {
		if real, _ := filepath.EvalSymlinks(dir); real == active && calls.Add(1) > 1 {
			return versionTimedOut
		}
		return runVersion(dir, 10*time.Second)
	}
	f.start()
	// Staged before Run looked for a request left from before the restart, the request would take the first version
	// call there and onRequest's call would time out (PDK-1132). The first tick comes after that look.
	f.waitSent()
	f.stageAfterCheckin("1.1.0", script("1.1.0", 0, f.good()))
	f.waitFor("the new agent checked in", f.checkedIn)
	if r := f.endProbation("B"); r.Outcome != outcomeUpdated || r.FromVersion != "1.0.0" {
		t.Fatalf("result %+v", r)
	}
}

// TestRunVersionTimesOut: the one real timeout of these tests; an agent that never answers is reported as timed out,
// one that fails as unknown.
func TestRunVersionTimesOut(t *testing.T) {
	dir := t.TempDir()
	write := func(body string) {
		if err := os.WriteFile(filepath.Join(dir, "paddockd"), []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil { //nolint:gosec // test script
			t.Fatal(err)
		}
	}
	write("exec sleep 300")
	if got := runVersion(dir, 500*time.Millisecond); got != versionTimedOut {
		t.Fatalf("hung agent: %q, want the timeout", got)
	}
	write("exit 1")
	if got := runVersion(dir, 10*time.Second); got != "unknown" {
		t.Fatalf("failing agent: %q, want unknown", got)
	}
}
