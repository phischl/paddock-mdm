package supervisor

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/pkg/releasesig"
)

// stalledScript is script whose `version` appends a line to calls and answers only once gate exists, as an agent
// whose binary or disk stalls does: until then every version call hits the supervisor's VersionTimeout, whatever the
// host's load.
func stalledScript(gate, calls, version, run string) []byte {
	return []byte("#!/bin/sh\ncase \"$1\" in\nversion) echo >>" + calls + "; while [ ! -e " + gate +
		" ]; do sleep 0.05; done; echo " + version + " ;;\nself-test) exit 0 ;;\nrun) " + run + " ;;\nesac\n")
}

// deferredMsg is the warning of one deferred attempt.
const deferredMsg = `level=WARN msg="update request deferred: the active agent did not report its version in time"`

// stallVersion makes slot's agent report version only after the returned release function ran; version calls time
// out after 100 ms meanwhile. The supervisor's clock is the returned manual clock, so that only the test ends the
// wait before a deferred request's next attempt.
func (f *fake) stallVersion(slot, version, run string) (release func(), clock *manualClock) {
	f.t.Helper()
	gate := filepath.Join(f.dir, "gate-"+slot)
	clock = &manualClock{now: time.Date(2026, 11, 16, 0, 0, 0, 0, time.UTC)}
	f.cfg.VersionTimeout, f.cfg.Now = 100*time.Millisecond, clock.get
	f.writeExec(filepath.Join(f.cfg.Slots, slot, "paddockd"), stalledScript(gate, filepath.Join(f.dir, "calls-"+slot), version, run))
	return func() {
		if err := os.WriteFile(gate, nil, 0o600); err != nil {
			f.t.Fatal(err)
		}
	}, clock
}

// versionCalls counts the version calls of slot's stalled agent (stallVersion).
func (f *fake) versionCalls(slot string) int {
	data, _ := os.ReadFile(filepath.Join(f.dir, "calls-"+slot))
	return len(data)
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
		if calls, n := f.versionCalls("A"), strings.Count(log.String(), deferredMsg); calls != n {
			t.Fatalf("%d version calls of the active agent, %d warnings: want one warning per attempt", calls, n)
		}
	})
	// An agent that runs its version command and fails still counts as failed, as before: any signed release may
	// replace it (TestReleaseBinding covers one that exits non-zero).
	t.Run("older release replaces an agent with invalid version output", func(t *testing.T) {
		f := newFake(t)
		f.cfg.VersionTimeout = 100 * time.Millisecond
		f.writeExec(filepath.Join(f.cfg.Slots, "A", "paddockd"), script("not-a-version", 0, f.good()))
		f.start()
		f.stageAfterCheckin("0.9.0", script("0.9.0", 0, f.good()))
		f.waitFor("the new agent checked in", f.checkedIn)
		if r := f.endProbation("B"); r.Outcome != outcomeUpdated || r.Version != "0.9.0" || r.FromVersion != "not-a-version" {
			t.Fatalf("result %+v", r)
		}
	})
}

// TestStalledVersionKeepsTheUnreadableLog (PDK-1118, plan M2b amendment 2026-11-16): a slot whose version call times
// out while an unreadable probation log is rebuilt only looks version-less; the log stays for the next start instead
// of being dropped, and nothing is decided.
func TestStalledVersionKeepsTheUnreadableLog(t *testing.T) {
	for _, slot := range []string{"B", "A"} {
		t.Run("stalled slot "+slot, func(t *testing.T) {
			log := captureLog(t)
			f := newFake(t)
			f.corruptSwitch("1.1.0", f.good())
			version := map[string]string{"A": "1.0.0", "B": "1.1.0"}[slot]
			f.stallVersion(slot, version, f.good())
			f.start()
			f.waitReady()
			f.waitTicks(3)
			if !strings.Contains(log.String(), `level=ERROR msg="keeping the unreadable probation log until the next start: a slot's version call timed out"`) {
				t.Fatalf("no error about the kept probation log:\n%s", log.String())
			}
			if data, err := os.ReadFile(f.cfg.ProbationLog); err != nil || string(data) != `{"version":"1.1` {
				t.Fatalf("probation log %q, error %v; want the unreadable log kept", data, err)
			}
			f.expectNoResult()
			if f.active() != "B" {
				t.Fatalf("current → %s, want B", f.active())
			}
		})
	}
}
