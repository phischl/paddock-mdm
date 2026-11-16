package supervisor

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// expiredProbation leaves a probation of 1.1.0 in slot B, whose agent never checks in, switched at switchedAt in the
// boot bootID, and makes mc the supervisor's clock.
func (f *fake) expiredProbation(mc *manualClock, switchedAt time.Time, bootID string) {
	f.t.Helper()
	f.cfg.Now = mc.get
	f.writeExec(filepath.Join(f.cfg.Slots, "B", "paddockd"), script("1.1.0", 0, "trap '' HUP; exec sleep 300"))
	if err := flip(f.cfg.Slots, "B", syncDir); err != nil {
		f.t.Fatal(err)
	}
	p := probation{Version: "1.1.0", FromVersion: "1.0.0", FromSlot: "A", ToSlot: "B", SwitchedAt: switchedAt, BootID: bootID}
	if err := writeJSON(f.cfg.ProbationLog, p, syncFile); err != nil {
		f.t.Fatal(err)
	}
}

// expectRollbackAfter checks that the resumed probation rolls back exactly when the clock has advanced by window:
// not within the supervisor's next ticks before, and at once after.
func (f *fake) expectRollbackAfter(mc *manualClock, window time.Duration) {
	f.t.Helper()
	mc.advance(window - time.Nanosecond)
	f.waitTicks(3)
	if _, err := os.Stat(f.cfg.Result); err == nil || f.active() != "B" {
		f.t.Fatalf("rolled back before the window of %s ended (current %s)", window, f.active())
	}
	mc.advance(time.Nanosecond)
	if r := f.waitResult(10 * time.Second); r.Outcome != outcomeRolledBack || f.active() != "A" {
		f.t.Fatalf("result %+v, current %s", r, f.active())
	}
}

// TestResumedProbationKeepsItsWindow (PDK-1118, plan M2b amendment 2026-11-16): within one boot a resumed probation
// ends at its switch time plus the probation, at the earliest after the floor of a fifth of it; after a reboot, or
// with a log that names no boot, it runs a full window; a clock set back never stretches it past one window.
func TestResumedProbationKeepsItsWindow(t *testing.T) {
	start := time.Date(2026, 11, 16, 0, 0, 0, 0, time.UTC)
	tests := []struct {
		name       string
		switchedAt time.Time
		bootID     string
		window     time.Duration
	}{
		{"same boot, window already over: the floor", start.Add(-2 * testProbation), "boot-1", testProbation / 5},
		{"same boot, half the window left", start.Add(-testProbation / 2), "boot-1", testProbation / 2},
		{"other boot: a full window", start.Add(-2 * testProbation), "boot-0", testProbation},
		{"log without a boot: a full window", start.Add(-2 * testProbation), "", testProbation},
		{"clock set back: at most one window", start.Add(10 * testProbation), "boot-1", testProbation},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFake(t)
			mc := &manualClock{now: start}
			f.expiredProbation(mc, tt.switchedAt, tt.bootID)
			f.start()
			f.waitReady()
			f.expectRollbackAfter(mc, tt.window)
		})
	}
}

// startKillable starts a supervisor like start, but one whose seams may end its goroutine with runtime.Goexit, as a
// watchdog kill ends the process at that point; it returns the supervisor, whose child the test then kills
// (KillMode=mixed), and a channel closed when its Run goroutine has ended.
func (f *fake) startKillable() (*Supervisor, <-chan struct{}) {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	f.cancel, f.done = cancel, done
	cfg, notify := f.cfg, f.cfg.Notify
	cfg.Notify = func(s string) {
		if s == "WATCHDOG=1" {
			f.ticks.Add(1)
		}
		notify(s)
	}
	s := New(cfg)
	go func() { defer close(done); s.Run(ctx, f.usr1) }()
	return s, done
}

// killed waits until a seam ended the supervisor (kills reached n), then kills its agent as systemd would.
func (f *fake) killed(s *Supervisor, done <-chan struct{}, kills *atomic.Int32, n int32) {
	f.t.Helper()
	f.waitFor("the supervisor was killed in its rollback pass", func() bool { return kills.Load() == n })
	<-done
	if s.child != nil {
		_ = s.child.Process.Kill()
	}
	f.cancel = nil
}

// waitTicksOrEnd is waitTicks that also returns once the supervisor's goroutine has ended, which ticks no more.
func (f *fake) waitTicksOrEnd(n int, done <-chan struct{}) {
	for len(f.notices) > 0 {
		<-f.notices
	}
	for n > 0 {
		select {
		case notice := <-f.notices:
			if notice == "WATCHDOG=1" {
				n--
			}
		case <-done:
			return
		}
	}
}

// probationOnDisk reads the probation log.
func (f *fake) probationOnDisk() probation {
	f.t.Helper()
	var p probation
	data, err := os.ReadFile(f.cfg.ProbationLog)
	if err == nil {
		err = json.Unmarshal(data, &p)
	}
	if err != nil {
		f.t.Fatalf("probation log %s: %v", data, err)
	}
	return p
}

// TestResumeAfterARebootRecordsTheNewWindow (PDK-1118, plan M2b fix batch 2026-11-16, M1): a resume in another boot,
// or of a log without a boot, starts a full window and records it, so a later restart in this boot gets only the rest
// of that window; if the record cannot be written, the window holds in memory; without a boot ID every resume runs a
// full window, and New says so once.
func TestResumeAfterARebootRecordsTheNewWindow(t *testing.T) {
	start := time.Date(2026, 11, 16, 0, 0, 0, 0, time.UTC)
	t.Run("restart later in the new boot", func(t *testing.T) {
		f := newFake(t)
		mc := &manualClock{now: start}
		f.expiredProbation(mc, start.Add(-2*testProbation), "boot-0")
		f.start()
		f.waitReady()
		if p := f.probationOnDisk(); p.BootID != "boot-1" || !p.SwitchedAt.Equal(start) {
			t.Fatalf("log names boot %q, switched at %s; want boot-1 at the resume %s", p.BootID, p.SwitchedAt, start)
		}
		mc.advance(testProbation - time.Second)
		f.waitTicks(3)
		f.expectNoResult()
		f.stop()
		f.start()
		f.waitReady()
		f.expectRollbackAfter(mc, testProbation/5)
	})
	t.Run("the record fails", func(t *testing.T) {
		log := captureLog(t)
		f := newFake(t)
		mc := &manualClock{now: start}
		f.expiredProbation(mc, start.Add(-2*testProbation), "boot-0")
		f.cfg.SyncFile = func(file *os.File) error {
			if file.Name() == f.cfg.ProbationLog+".tmp" {
				return errors.New("injected")
			}
			return file.Sync()
		}
		f.start()
		f.waitReady()
		if !strings.Contains(log.String(), `level=ERROR msg="recording the resumed probation's boot in the probation log failed"`) {
			t.Fatalf("no error about the failed record:\n%s", log.String())
		}
		f.expectRollbackAfter(mc, testProbation)
	})
	t.Run("no boot ID", func(t *testing.T) {
		log := captureLog(t)
		f := newFake(t)
		mc := &manualClock{now: start}
		f.cfg.BootID, f.cfg.BootIDFile = "", filepath.Join(f.dir, "missing")
		f.expiredProbation(mc, start.Add(-testProbation/2), "")
		f.start()
		f.waitReady()
		if n := strings.Count(log.String(), `level=WARN msg="reading the boot ID failed; every resumed probation runs a full window"`); n != 1 {
			t.Fatalf("%d warnings about the boot ID, want 1:\n%s", n, log.String())
		}
		f.expectRollbackAfter(mc, testProbation)
	})
}

// killPass starts a supervisor on an expired probation of B, kills it where seam calls kill, kills its agent, and
// returns the clock; the seams are reset for the restart.
func (f *fake) killPass(seam func(kill func())) *manualClock {
	f.t.Helper()
	mc := &manualClock{now: time.Date(2026, 11, 16, 0, 0, 0, 0, time.UTC)}
	f.expiredProbation(mc, mc.now.Add(-2*testProbation), "boot-1")
	f.runRecordingPID("A")
	var kills atomic.Int32
	seam(func() { kills.Add(1); runtime.Goexit() })
	s, done := f.startKillable()
	f.waitReady()
	mc.advance(testProbation / 5)
	f.killed(s, done, &kills, 1)
	f.cfg.SyncDir, f.cfg.SyncFile, f.cfg.Sleep = nil, nil, nil
	return mc
}

// syncOf kills at the SyncFile of name.
func (f *fake) syncOf(name string) func(kill func()) {
	return func(kill func()) {
		f.cfg.SyncFile = func(file *os.File) error {
			if file.Name() == name {
				kill()
			}
			return file.Sync()
		}
	}
}

// TestRollbackKillMatrix (PDK-1118b, plan M2b): a watchdog kill at any point of a rollback pass ends in rolled_back
// after the restart, and never reports it while current points at the failed release.
func TestRollbackKillMatrix(t *testing.T) {
	t.Run("1-2 before the intent is in place", func(t *testing.T) {
		f := newFake(t)
		mc := &manualClock{now: time.Date(2026, 11, 16, 0, 0, 0, 0, time.UTC)}
		f.expiredProbation(mc, mc.now.Add(-2*testProbation), "boot-1")
		// The intent's temporary file was written, its rename did not happen: the switch's log stands.
		if err := os.WriteFile(f.cfg.ProbationLog+".tmp", []byte(`{"version":"1.1.0","rolling_back":true}`), 0o600); err != nil {
			t.Fatal(err)
		}
		f.start()
		f.waitReady()
		f.expectRollbackAfter(mc, testProbation/5)
	})
	t.Run("3 after the intent, before the flip back", func(t *testing.T) {
		f := newFake(t)
		f.killPass(func(kill func()) { f.blockFlip(); f.cfg.Sleep = func(time.Duration) { kill() } })
		if p := f.probationOnDisk(); !p.RollingBack || f.active() != "B" {
			t.Fatalf("log %+v, current %s; want the recorded intent on B", p, f.active())
		}
		f.unblockFlip()
		f.start()
		f.waitReady()
		if r := f.waitOutcome(outcomeRolledBack); r.Version != "1.1.0" || f.active() != "A" {
			t.Fatalf("result %+v, current %s", r, f.active())
		}
		f.waitAgentRuns("A")
		f.waitNoProbationLog()
	})
	t.Run("3 with a flip back that keeps failing", func(t *testing.T) {
		f := newFake(t)
		mc := f.killPass(func(kill func()) { f.blockFlip(); f.cfg.Sleep = func(time.Duration) { kill() } })
		f.start()
		f.waitReady()
		if r := f.waitResult(10 * time.Second); r.Outcome != outcomeRollbackFailed || f.active() != "B" {
			t.Fatalf("result %+v, current %s", r, f.active())
		}
		f.unblockFlip()
		mc.advance(pendingRetryStart)
		if r := f.waitOutcome(outcomeRolledBack); f.active() != "A" {
			t.Fatalf("result %+v, current %s", r, f.active())
		}
	})
	t.Run("4 in the sync of the flip back", func(t *testing.T) {
		f := newFake(t)
		f.killPass(func(kill func()) {
			f.cfg.SyncDir = func(dir string) error {
				if dir == f.cfg.Slots && f.active() == "A" {
					kill()
				}
				return syncDir(dir)
			}
		})
		f.expectRolledBackAfterRestart(false)
	})
	t.Run("4 in the sync of the recorded outcome", func(t *testing.T) {
		f := newFake(t)
		f.killPass(f.syncOf(f.cfg.ProbationLog + ".tmp"))
		f.expectRolledBackAfterRestart(false)
	})
	t.Run("5 in the sync of the result", func(t *testing.T) {
		f := newFake(t)
		// The log records rolled_back; the result's rename did not happen, so the restart writes it again.
		f.killPass(f.syncOf(f.cfg.Result + ".tmp"))
		if p := f.probationOnDisk(); p.Outcome != outcomeRolledBack {
			t.Fatalf("log %+v, want the recorded rolled_back", p)
		}
		f.expectRolledBackAfterRestart(false)
	})
}

// expectRolledBackAfterRestart restarts the supervisor after killPass and expects rolled_back with the previous agent
// running; written says whether the killed pass had already written the result.
func (f *fake) expectRolledBackAfterRestart(written bool) {
	f.t.Helper()
	if _, err := os.Stat(f.cfg.Result); (err == nil) != written {
		f.t.Fatalf("result before the restart: %v, want written %v", err, written)
	}
	if f.active() != "A" {
		f.t.Fatalf("current → %s after the kill, want A", f.active())
	}
	f.start()
	f.waitReady()
	if r := f.waitOutcome(outcomeRolledBack); r.Version != "1.1.0" || f.active() != "A" {
		f.t.Fatalf("result %+v, current %s", r, f.active())
	}
	f.waitAgentRuns("A")
	f.waitNoProbationLog()
}

// stalledRestarts restarts the supervisor n times on a disk whose every sync stalls past the watchdog, so that each
// restart is killed at its first sync, and expects current on the previous slot and no result after each.
func (f *fake) stalledRestarts(n int) {
	f.t.Helper()
	for i := range n {
		var kills atomic.Int32
		kill := func() { kills.Add(1); runtime.Goexit() }
		f.cfg.SyncDir = func(string) error { kill(); return nil }
		f.cfg.SyncFile = func(*os.File) error { kill(); return nil }
		s, done := f.startKillable()
		f.killed(s, done, &kills, 1)
		if f.active() != "A" {
			f.t.Fatalf("restart %d: current → %s, want A: the flip back did not land before the first sync", i+1, f.active())
		}
	}
	f.cfg.SyncDir, f.cfg.SyncFile = nil, nil
}

// TestRollbackUnderStalledSyncsConverges (PDK-1118b correction and fix round 2, plan M2b): on a disk where every sync
// stalls past the watchdog, each pass is killed at its first sync; the flip back's rename comes before any sync, in a
// fresh rollback pass as in a resumed one, so the failed release never runs again, and a restart once the disk answers
// reports rolled_back.
func TestRollbackUnderStalledSyncsConverges(t *testing.T) {
	t.Run("rollback pass", func(t *testing.T) {
		f := newFake(t)
		f.killPass(func(kill func()) {
			f.cfg.SyncDir = func(string) error { kill(); return nil }
			f.cfg.SyncFile = func(*os.File) error { kill(); return nil }
		})
		if f.active() != "A" {
			t.Fatalf("current → %s after the first killed pass, want A", f.active())
		}
		f.stalledRestarts(2)
		f.expectNoResult()
		f.expectRolledBackAfterRestart(false)
	})
	t.Run("resumed intent whose flip back did not land", func(t *testing.T) {
		f := newFake(t)
		f.killPass(func(kill func()) { f.blockFlip(); f.cfg.Sleep = func(time.Duration) { kill() } })
		if p := f.probationOnDisk(); !p.RollingBack || f.active() != "B" {
			t.Fatalf("log %+v, current %s; want the recorded intent on B", p, f.active())
		}
		f.unblockFlip()
		f.stalledRestarts(3)
		f.expectNoResult()
		f.expectRolledBackAfterRestart(false)
	})
	t.Run("resumed rollback_failed log", func(t *testing.T) {
		f := newFake(t)
		f.runRecordingPID("A")
		f.pendingRollback()
		f.stop()
		f.unblockFlip()
		f.stalledRestarts(3)
		f.expectRolledBackAfterRestart(true)
	})
}

// syncsBeforeReady counts the syncs a supervisor makes before its READY notice; ready.Store(false) before each start.
func (f *fake) syncsBeforeReady() (early *atomic.Int32, ready *atomic.Bool) {
	early, ready = &atomic.Int32{}, &atomic.Bool{}
	notify := f.cfg.Notify
	f.cfg.Notify = func(state string) {
		if state == "READY=1" {
			ready.Store(true)
		}
		notify(state)
	}
	f.cfg.SyncFile = func(file *os.File) error {
		if !ready.Load() {
			early.Add(1)
		}
		return file.Sync()
	}
	f.cfg.SyncDir = func(dir string) error {
		if !ready.Load() {
			early.Add(1)
		}
		return syncDir(dir)
	}
	return early, ready
}

// TestResumedRollbackFailedReportsOnce (PDK-1118 fix round 2, ADR 0024): a resumed rollback_failed log whose flip back
// keeps failing writes nothing before READY; it writes its result again exactly once, with the recorded at, after the
// first failed retry of each start, and never rolled_back.
func TestResumedRollbackFailedReportsOnce(t *testing.T) {
	log := captureLog(t)
	f := newFake(t)
	mc := &manualClock{now: time.Date(2026, 11, 16, 0, 0, 0, 0, time.UTC)}
	f.cfg.Now = mc.get
	failed := f.pendingRollback()
	f.stop()
	early, ready := f.syncsBeforeReady()
	for i := range 3 {
		// The agent delivered and deleted the result.
		if err := os.Remove(f.cfg.Result); err != nil && !errors.Is(err, os.ErrNotExist) {
			t.Fatal(err)
		}
		base := retries(log)
		ready.Store(false)
		f.start()
		f.waitReady()
		if r := f.waitResult(10 * time.Second); r != failed || f.active() != "B" || retries(log) != base+1 {
			t.Fatalf("restart %d: result %+v after %d retries, current %s; want %+v after the first retry on B",
				i+1, r, retries(log)-base, f.active(), failed)
		}
		if err := os.Remove(f.cfg.Result); err != nil {
			t.Fatal(err)
		}
		mc.advance(pendingRetryMax)
		f.waitFor("a second failed retry", func() bool { return retries(log) == base+2 })
		f.waitTicks(3)
		f.expectNoResult()
		if n := early.Load(); n != 0 {
			t.Fatalf("restart %d: %d syncs before READY", i+1, n)
		}
		f.stop()
	}
}

// TestResultTakeoverWritesNothingBeforeReady (PDK-1118 fix round 2): an undecided log whose rollback_failed the result
// names is taken over without a write at the resume; the log records it after the first failed retry.
func TestResultTakeoverWritesNothingBeforeReady(t *testing.T) {
	f := newFake(t)
	mc := &manualClock{now: time.Date(2026, 11, 16, 0, 0, 0, 0, time.UTC)}
	f.expiredProbation(mc, mc.now, "boot-1")
	at := time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)
	res := map[string]any{"version": "1.1.0", "from_version": "1.0.0", "outcome": outcomeRollbackFailed, "at": at}
	if err := writeJSON(f.cfg.Result, res, syncFile); err != nil {
		t.Fatal(err)
	}
	f.blockFlip()
	early, _ := f.syncsBeforeReady()
	f.start()
	f.waitReady()
	f.waitFor("the log records the taken-over decision", func() bool {
		data, err := os.ReadFile(f.cfg.ProbationLog)
		return err == nil && strings.Contains(string(data), `"outcome":"rollback_failed"`)
	})
	if p := f.probationOnDisk(); !p.DecidedAt.Equal(at) || f.active() != "B" {
		t.Fatalf("log %+v, current %s; want the result's decision on B", p, f.active())
	}
	if n := early.Load(); n != 0 {
		t.Fatalf("%d syncs before READY", n)
	}
}

// TestPendingMarkerIsWrittenWhileTheRetryWaits (PDK-1118 fix round 2): a marker that the failed flip back could not
// write is written on the next tick whose retry is not due, without another flip attempt.
func TestPendingMarkerIsWrittenWhileTheRetryWaits(t *testing.T) {
	log := captureLog(t)
	f := newFake(t)
	f.cfg.Now = (&manualClock{now: time.Date(2026, 11, 16, 0, 0, 0, 0, time.UTC)}).get
	var failedOnce atomic.Bool
	f.cfg.SyncFile = func(file *os.File) error {
		if file.Name() == f.marker()+".tmp" && failedOnce.CompareAndSwap(false, true) {
			return errors.New("injected")
		}
		return file.Sync()
	}
	f.pendingRollback()
	f.waitFor("the marker on a waiting tick", f.marked)
	if !failedOnce.Load() || retries(log) != 0 {
		t.Fatalf("marker write failed once: %v, retries %d; want the marker from a tick without a retry", failedOnce.Load(), retries(log))
	}
}

// TestSwitchKilledInItsLogWriteReportsNothing (PDK-1118b regression): a supervisor killed while the switch's own log
// is written leaves an undecided log without rolling_back and current on the previous slot; the restart drops the log
// and reports nothing, as for a switch whose flip never landed.
func TestSwitchKilledInItsLogWriteReportsNothing(t *testing.T) {
	f := newFake(t)
	var kills atomic.Int32
	kill := func() { kills.Add(1); runtime.Goexit() }
	f.cfg.SyncFile = func(file *os.File) error {
		if _, err := os.Stat(f.cfg.ProbationLog); err == nil && file.Name() == filepath.Dir(f.cfg.ProbationLog) && f.active() == "A" {
			kill()
		}
		return file.Sync()
	}
	s, done := f.startKillable()
	f.waitReady()
	f.stage("1.1.0", script("1.1.0", 0, f.good()), nil)
	f.killed(s, done, &kills, 1)
	if p := f.probationOnDisk(); p.RollingBack || f.active() != "A" {
		t.Fatalf("log %+v, current %s; want the switch's log on A", p, f.active())
	}
	f.cfg.SyncFile = nil
	f.start()
	f.waitReady()
	f.waitNoProbationLog()
	f.waitTicks(3)
	f.expectNoResult()
	if f.active() != "A" {
		t.Fatalf("current → %s, want A", f.active())
	}
}

// TestSwitchRecordsTheBoot (PDK-1118): the switch and the rebuild record the boot in the probation log, so that a
// restart in the same boot keeps the window; New reads the boot ID from the kernel unless it is injected.
func TestSwitchRecordsTheBoot(t *testing.T) {
	t.Run("switch", func(t *testing.T) {
		f := newFake(t)
		mc := &manualClock{now: time.Date(2026, 11, 16, 0, 0, 0, 0, time.UTC)}
		f.cfg.Now = mc.get
		f.writeExec(filepath.Join(f.cfg.Slots, "A", "paddockd"), script("1.0.0", 0, f.good()))
		f.start()
		f.waitSent()
		f.stage("1.1.0", script("1.1.0", 0, "trap '' HUP; exec sleep 300"), nil)
		f.waitFor("current → B", func() bool { return f.active() == "B" })
		f.stop()
		mc.advance(2 * testProbation)
		f.start()
		f.waitReady()
		f.expectRollbackAfter(mc, testProbation/5)
	})
	t.Run("rebuild", func(t *testing.T) {
		f := newFake(t)
		f.corruptSwitch("1.1.0", f.good())
		f.start()
		f.waitReady()
		f.expectRebuiltLog()
		var p probation
		data, _ := os.ReadFile(f.cfg.ProbationLog)
		if err := json.Unmarshal(data, &p); err != nil || p.BootID != "boot-1" {
			t.Fatalf("rebuilt log %s without the boot (error %v)", data, err)
		}
	})
	t.Run("kernel boot ID", func(t *testing.T) {
		want, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
		if err != nil {
			t.Skip("no boot ID on this host:", err)
		}
		if got := New(Config{}).cfg.BootID; got == "" || got != strings.TrimSpace(string(want)) {
			t.Fatalf("boot ID %q, want %q", got, strings.TrimSpace(string(want)))
		}
	})
}
