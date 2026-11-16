package supervisor

import (
	"context"
	"encoding/json"
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

// TestWatchdogKillsBeforeTheFlipBackConverge (PDK-1118): a supervisor killed in every rollback pass before the flip
// back lands (here between the attempts of a blocked flip; a rename that stalls leaves the same state on disk)
// tries again after each restart once the floor of a fifth of the probation has passed, not after a fresh window, so
// k kills postpone the rollback by k floors, and it rolls back at the first pass whose flip lands.
func TestWatchdogKillsBeforeTheFlipBackConverge(t *testing.T) {
	f := newFake(t)
	mc := &manualClock{now: time.Date(2026, 11, 16, 0, 0, 0, 0, time.UTC)}
	f.expiredProbation(mc, mc.now.Add(-2*testProbation), "boot-1")
	f.blockFlip()
	var kills atomic.Int32
	f.cfg.Sleep = func(time.Duration) { kills.Add(1); runtime.Goexit() }
	for i := range int32(3) {
		s, done := f.startKillable()
		f.waitReady()
		mc.advance(testProbation/5 - time.Nanosecond)
		f.waitTicksOrEnd(3, done)
		if kills.Load() != i {
			t.Fatalf("restart %d: the rollback pass started before the floor", i+1)
		}
		mc.advance(time.Nanosecond)
		f.killed(s, done, &kills, i+1)
		if f.active() != "B" {
			t.Fatalf("restart %d: current → %s, want B", i+1, f.active())
		}
	}
	f.unblockFlip()
	f.cfg.Sleep = nil
	f.start()
	f.waitReady()
	f.expectRollbackAfter(mc, testProbation/5)
}

// TestWatchdogKillAfterTheFlipBackConverges (PDK-1118): a supervisor killed after the rollback's rename has landed
// leaves current on the previous slot; the restart runs the previous agent and never the failed release again. It
// documents the behaviour the window change relies on; it passes without the change too.
func TestWatchdogKillAfterTheFlipBackConverges(t *testing.T) {
	tests := []struct {
		name    string
		seam    func(f *fake, kill func())
		outcome string // the result after the restart, "" for none
	}{
		{"in the sync of the flip back", func(f *fake, kill func()) {
			f.cfg.SyncDir = func(dir string) error {
				if dir == f.cfg.Slots && f.active() == "A" {
					kill()
				}
				return syncDir(dir)
			}
		}, ""},
		{"in the sync of the recorded outcome", func(f *fake, kill func()) {
			f.cfg.SyncFile = func(file *os.File) error {
				if file.Name() == f.cfg.ProbationLog+".tmp" {
					kill()
				}
				return file.Sync()
			}
		}, ""},
		{"in the sync of the result", func(f *fake, kill func()) {
			f.cfg.SyncFile = func(file *os.File) error {
				if file.Name() == f.cfg.Result+".tmp" {
					kill()
				}
				return file.Sync()
			}
		}, outcomeRolledBack},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFake(t)
			mc := &manualClock{now: time.Date(2026, 11, 16, 0, 0, 0, 0, time.UTC)}
			f.expiredProbation(mc, mc.now.Add(-2*testProbation), "boot-1")
			f.runRecordingPID("A")
			var kills atomic.Int32
			tt.seam(f, func() { kills.Add(1); runtime.Goexit() })
			s, done := f.startKillable()
			f.waitReady()
			mc.advance(testProbation / 5)
			f.killed(s, done, &kills, 1)
			f.cfg.SyncDir, f.cfg.SyncFile = nil, nil
			f.start()
			f.waitReady()
			f.waitAgentRuns("A")
			f.waitNoProbationLog()
			if f.active() != "A" {
				t.Fatalf("current → %s, want A", f.active())
			}
			if tt.outcome == "" {
				f.expectNoResult()
			} else if r := f.waitResult(10 * time.Second); r.Outcome != tt.outcome {
				t.Fatalf("result %+v", r)
			}
		})
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
