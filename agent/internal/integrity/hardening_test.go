package integrity

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// TestGuardedSync (plan M5a R8, T2): a Paddock call that did not write leaves a prior hand edit reported; one that
// wrote moves the baseline.
func TestGuardedSync(t *testing.T) {
	d := newDevice(t)
	full := d.l.DiskSetupConfig()
	d.write("/etc/paddock/disk-setup.json", "prepared")
	d.quiet(1, Pass{})
	d.write("/etc/paddock/disk-setup.json", "hand edit")
	before := FingerprintOf(full)
	if changed, err := SyncFileIfChanged(d.l, full, before); changed || err != nil {
		t.Fatalf("changed %v, %v", changed, err)
	}
	d.changedOnce("/etc/paddock/disk-setup.json", Pass{})
	before = FingerprintOf(full)
	d.write("/etc/paddock/disk-setup.json", "written by Paddock")
	if changed, err := SyncFileIfChanged(d.l, full, before); !changed || err != nil {
		t.Fatalf("changed %v, %v", changed, err)
	}
	d.quiet(3, Pass{})
	if FingerprintOf(d.l.Join("/nowhere")) != (Fingerprint{}) {
		t.Fatal("an absent file has a fingerprint")
	}
}

// mkfifo replaces a device path by a FIFO.
func (d *device) mkfifo(path string) {
	d.t.Helper()
	_ = os.Remove(d.l.Join(path))
	if err := syscall.Mkfifo(d.l.Join(path), 0o600); err != nil {
		d.t.Fatal(err)
	}
}

// passWithin runs a pass that must return within limit.
func (d *device) passWithin(limit time.Duration, p Pass) []string {
	d.t.Helper()
	done := make(chan []string, 1)
	go func() {
		var ev []string
		d.c.Emit = func(f, reason string) {
			if reason != "" {
				f += "#" + reason
			}
			ev = append(ev, f)
		}
		d.c.Check(context.Background(), p)
		done <- ev
	}()
	select {
	case ev := <-done:
		return ev
	case <-time.After(limit):
		d.t.Fatalf("the pass blocked for %v", limit)
		return nil
	}
}

// TestFIFOsNeverBlock (plan M5a R2, T3): a FIFO at a checked file is observed by its type and reported; a FIFO at
// an md5sums file suspends its package; neither blocks the pass.
func TestFIFOsNeverBlock(t *testing.T) {
	d := newDevice(t)
	d.quiet(1, Pass{})
	d.mkfifo("/etc/paddock/trust.json")
	d.mkfifo("/var/lib/dpkg/info/paddock-revoke.md5sums")
	if ev := d.passWithin(5*time.Second, Pass{}); !slices.Equal(ev, []string{"/etc/paddock/trust.json"}) {
		t.Fatalf("reported %v", ev)
	}
	if b := d.baseline(); b.Reported["/etc/paddock/trust.json"] != "!type:p---------" {
		t.Fatalf("observed %q", b.Reported["/etc/paddock/trust.json"])
	}
	if s, ok := d.c.suspended["package:paddock-revoke"]; !ok || s.File != "/var/lib/dpkg/info/paddock-revoke.md5sums" {
		t.Fatalf("suspended %v", d.c.suspended)
	}
	if ev := d.passWithin(5*time.Second, Pass{}); len(ev) != 0 {
		t.Fatalf("reported %v again", ev)
	}
}

// TestSwapAfterLstat (plan M5a R2, T4): a file swapped between the Lstat and the open is cached under the
// fingerprint of the file that was read, so the malicious file is hashed and reported when it is back.
func TestSwapAfterLstat(t *testing.T) {
	d := newDevice(t)
	const path = "/etc/paddock/agent.yml"
	d.quiet(1, Pass{})
	genuine, err := os.ReadFile(d.l.Join(path))
	if err != nil {
		t.Fatal(err)
	}
	d.write(path, "malicious")
	if err := os.WriteFile(d.l.Join(path)+".genuine", genuine, 0o600); err != nil {
		t.Fatal(err)
	}
	d.c.hash.afterLstat = func(p string) {
		if p == path {
			d.c.hash.afterLstat = nil
			if err := os.Rename(d.l.Join(path)+".genuine", d.l.Join(path)); err != nil {
				t.Error(err)
			}
		}
	}
	d.quiet(1, Pass{})
	if got, want := d.c.hash.cache[path].fp, FingerprintOf(d.l.Join(path)); got != want {
		t.Fatalf("cached fingerprint %+v, want the one of the file read %+v", got, want)
	}
	d.write(path, "malicious")
	d.changedOnce(path, Pass{})
}

// blockingSys blocks the first systemctl call until release closes.
type blockingSys struct {
	*fakeSys
	once             sync.Once
	entered, release chan struct{}
}

func (b *blockingSys) Systemctl(ctx context.Context, args ...string) (string, int, error) {
	b.once.Do(func() {
		close(b.entered)
		<-b.release
	})
	return b.fakeSys.Systemctl(ctx, args...)
}

// TestObserveOutsideTheLock (plan M5a R1, T5): while a pass waits for systemd, a Paddock write syncs at once; the
// pass, whose observation predates the sync, is dropped as raced and reports nothing.
func TestObserveOutsideTheLock(t *testing.T) {
	d := newDevice(t)
	d.quiet(1, Pass{})
	sys := &blockingSys{fakeSys: d.sys, entered: make(chan struct{}), release: make(chan struct{})}
	d.c.Sys = sys
	var ev []string
	d.c.Emit = func(f, _ string) { ev = append(ev, f) }
	done := make(chan struct{})
	go func() {
		defer close(done)
		d.c.Check(context.Background(), Pass{})
	}()
	<-sys.entered
	d.write("/etc/paddock/agent.yml", "written by Paddock")
	start := time.Now()
	if err := SyncFiles(d.l, d.l.AgentConfig()); err != nil || time.Since(start) >= LockWait {
		t.Fatalf("sync during the pass: %v after %v", err, time.Since(start))
	}
	close(sys.release)
	<-done
	if len(ev) != 0 {
		t.Fatalf("the raced pass reported %v", ev)
	}
	if _, ok := d.c.suspended[objBaseline]; !ok {
		t.Fatalf("suspended %v", d.c.suspended)
	}
	d.restart()
	d.quiet(3, Pass{})
}

// TestDeferredSync (plan M5a R7.1, T7): a file whose sync failed is taken as the baseline by the next pass and leaves
// the deferred set after the save.
func TestDeferredSync(t *testing.T) {
	d := newDevice(t)
	d.quiet(1, Pass{})
	d.write("/etc/paddock/agent.yml", "written by Paddock")
	d.c.Defer(d.l.AgentConfig())
	d.quiet(3, Pass{})
	if len(d.c.deferred) != 0 {
		t.Fatalf("deferred %v", d.c.deferred)
	}
	d.write("/etc/paddock/agent.yml", "hand edit")
	d.changedOnce("/etc/paddock/agent.yml", Pass{})
}

// TestSupervisorExceptionNeedsCapture (plan M5a R10, T8): a planted stale marker with a replaced binary gets no
// exception; a chain of rollbacks keeps the genuine files expected.
func TestSupervisorExceptionNeedsCapture(t *testing.T) {
	at := time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)
	p := Pass{ReportedSupervisorAt: &at}
	t.Run("planted marker", func(t *testing.T) {
		d := newDevice(t)
		d.quiet(1, Pass{})
		d.write("/var/lib/paddock/state/supervisor-upgrade.json", `{"version":"9.9.9"}`)
		d.write("/usr/sbin/paddock-supervisor", "malicious")
		d.remove("/var/lib/paddock/state/supervisor-upgrade.json")
		writeSupervisorResult(t, d, "install_failed", at)
		d.logs.reset()
		if err := SupervisorResult(d.l, d.c.Arch, "9.9.9", "install_failed"); err != nil {
			t.Fatal(err)
		}
		if b := d.baseline(); len(b.Exceptions) != 0 {
			t.Fatalf("exceptions %v", b.Exceptions)
		}
		d.changedOnce("/usr/sbin/paddock-supervisor", p)
	})
	t.Run("chain of rollbacks", func(t *testing.T) {
		d := newDevice(t)
		d.quiet(1, Pass{})
		old, _ := os.ReadFile(d.l.Join("/usr/sbin/paddock-supervisor"))
		oldUnit, _ := os.ReadFile(d.l.Join("/usr/lib/systemd/system/paddock-supervisor.service"))
		for i, version := range []string{"2.0.0", "3.0.0"} {
			if err := RecordSupervisorPre(d.l, d.c.Arch, version); err != nil {
				t.Fatal(err)
			}
			upgradeSupervisor(d, version)
			d.write("/usr/sbin/paddock-supervisor", string(old))
			d.write("/usr/lib/systemd/system/paddock-supervisor.service", string(oldUnit))
			result := at.Add(time.Duration(i) * time.Hour)
			writeSupervisorResult(t, d, "rolled_back", result)
			if err := SupervisorResult(d.l, d.c.Arch, version, "rolled_back"); err != nil {
				t.Fatal(err)
			}
			d.quiet(3, Pass{ReportedSupervisorAt: &result})
		}
		if b := d.baseline(); b.SupervisorPre != nil || len(b.Exceptions) != 2 {
			t.Fatalf("pre %v, exceptions %v", b.SupervisorPre, b.Exceptions)
		}
	})
}

// TestRepeatedUpdateResult (plan M5a R11 L3, T13): rolled_back after rollback_failed of the same release, and a result
// processed twice, move the baseline without a Warn or a report.
func TestRepeatedUpdateResult(t *testing.T) {
	d := newDevice(t)
	d.quiet(1, Pass{})
	at := stagedUpdate(t, d)
	d.remove("/var/lib/paddock/state/probation.json")
	writeResult(t, d, "2.0.0", "rollback_failed", at)
	d.logs.reset()
	if _, err := UpdateResult(d.l, "2.0.0", "rollback_failed"); err != nil {
		t.Fatal(err)
	}
	d.quiet(2, Pass{ReportedUpdateAt: &at})
	d.link("A", current)
	later := at.Add(time.Hour)
	writeResult(t, d, "2.0.0", "rolled_back", later)
	for range 2 {
		if _, err := UpdateResult(d.l, "2.0.0", "rolled_back"); err != nil {
			t.Fatal(err)
		}
	}
	d.quiet(3, Pass{ReportedUpdateAt: &later})
	if n := d.logs.count(slog.LevelWarn); n != 0 {
		t.Fatalf("%d warnings: %v", n, d.logs.lines)
	}
	if b := d.baseline(); b.Expected[current] != "A" {
		t.Fatalf("current %q", b.Expected[current])
	}
}

// TestRolledBackNeedsFailedRollback (plan M5a R16): only a rolled_back that follows a rollback_failed of the staged
// release moves current back, and only to an unchanged slot; a replay changes nothing.
func TestRolledBackNeedsFailedRollback(t *testing.T) {
	setup := func(t *testing.T, outcome string) (*device, time.Time) {
		d := newDevice(t)
		d.quiet(1, Pass{})
		at := stagedUpdate(t, d)
		d.remove("/var/lib/paddock/state/probation.json")
		writeResult(t, d, "2.0.0", outcome, at)
		if _, err := UpdateResult(d.l, "2.0.0", outcome); err != nil {
			t.Fatal(err)
		}
		d.quiet(1, Pass{ReportedUpdateAt: &at})
		return d, at.Add(time.Hour)
	}
	rolledBack := func(t *testing.T, d *device, at time.Time) {
		writeResult(t, d, "2.0.0", "rolled_back", at)
		if _, err := UpdateResult(d.l, "2.0.0", "rolled_back"); err != nil {
			t.Fatal(err)
		}
	}
	t.Run("after updated", func(t *testing.T) {
		d, later := setup(t, "updated")
		d.link("A", current)
		rolledBack(t, d, later)
		d.changedOnce(current, Pass{ReportedUpdateAt: &later})
	})
	t.Run("after rollback_failed", func(t *testing.T) {
		d, later := setup(t, "rollback_failed")
		if !d.baseline().RollbackPending {
			t.Fatal("rollback_failed left no pending rollback")
		}
		d.link("A", current)
		rolledBack(t, d, later)
		rolledBack(t, d, later)
		d.quiet(3, Pass{ReportedUpdateAt: &later})
		if b := d.baseline(); b.Expected[current] != "A" || b.RollbackPending {
			t.Fatalf("current %q, pending %v", b.Expected[current], b.RollbackPending)
		}
	})
	t.Run("changed slot", func(t *testing.T) {
		d, later := setup(t, "rollback_failed")
		d.write(slotA, "agent other")
		d.link("A", current)
		rolledBack(t, d, later)
		if ev := d.pass(Pass{ReportedUpdateAt: &later}); !slices.Equal(ev, []string{slotA, current}) {
			t.Fatalf("reported %v", ev)
		}
		if b := d.baseline(); b.Expected[current] != "B" {
			t.Fatalf("current %q", b.Expected[current])
		}
	})
}

// TestBaselineReadableByOlderAgent (plan M5a R16): an agent without RollbackPending reads a baseline that holds it, as
// after a downgrade.
func TestBaselineReadableByOlderAgent(t *testing.T) {
	d := newDevice(t)
	d.quiet(1, Pass{})
	at := stagedUpdate(t, d)
	d.remove("/var/lib/paddock/state/probation.json")
	writeResult(t, d, "2.0.0", "rollback_failed", at)
	if _, err := UpdateResult(d.l, "2.0.0", "rollback_failed"); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(d.l.Integrity())
	if err != nil || !strings.Contains(string(raw), `"rollback_pending":true`) {
		t.Fatalf("baseline %s: %v", raw, err)
	}
	// The fields of Baseline as of e024d60c that this check uses; Go's decoder skips the others.
	var older struct {
		Generation uint64            `json:"generation"`
		Expected   map[string]string `json:"expected"`
		Staged     *Staged           `json:"staged"`
		LastStaged *Staged           `json:"last_staged"`
	}
	if err := json.Unmarshal(raw, &older); err != nil || older.Expected[current] != "B" || older.LastStaged == nil {
		t.Fatalf("an older agent could not read the baseline: %v, %+v", err, older)
	}
}

// TestSplitQuoted (plan M5a R9, T14).
func TestSplitQuoted(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want []string
		err  bool
	}{
		{in: "", want: nil},
		{in: "/a.conf", want: []string{"/a.conf"}},
		{in: `"/d/a b.conf"`, want: []string{"/d/a b.conf"}},
		{in: `"/d/a\"b.conf"`, want: []string{`/d/a"b.conf`}},
		{in: `/x.conf "/d/a b.conf"`, want: []string{"/x.conf", "/d/a b.conf"}},
		{in: `/d/a\ b.conf`, want: []string{"/d/a b.conf"}},
		{in: `"/d/a`, err: true},
	} {
		got, err := splitQuoted(tc.in)
		if (err != nil) != tc.err || !slices.Equal(got, tc.want) {
			t.Errorf("splitQuoted(%q) = %q, %v", tc.in, got, err)
		}
	}
}

// TestQuotedDropIn (T14): a drop-in with a space is reported with its whole path.
func TestQuotedDropIn(t *testing.T) {
	d := newDevice(t)
	d.quiet(1, Pass{})
	const dropIn = "/etc/systemd/system/orbit.service.d/a b.conf"
	d.write(dropIn, "[Service]\n")
	d.sys.units["orbit.service"] = show("/usr/lib/systemd/system/orbit.service",
		"/etc/systemd/system/orbit.service.d/90-paddock.conf", `"`+dropIn+`"`)
	d.changedOnce(dropIn, Pass{})
}

// TestBaselineReset (plan M5a R14, T15): a corrupt or deleted baseline is reported once per episode.
func TestBaselineReset(t *testing.T) {
	est := Pass{Established: true}
	corrupt := func(d *device) { d.write("/var/lib/paddock/state/integrity.json", "{not json") }
	t.Run("corrupt", func(t *testing.T) {
		d := newDevice(t)
		d.quiet(1, Pass{})
		corrupt(d)
		if ev := d.pass(est); !slices.Equal(ev, []string{reset}) {
			t.Fatalf("reported %v", ev)
		}
		d.quiet(5, est)
		corrupt(d)
		if ev := d.pass(est); !slices.Equal(ev, []string{reset}) {
			t.Fatalf("the second episode reported %v", ev)
		}
	})
	t.Run("a writer before the pass", func(t *testing.T) {
		d := newDevice(t)
		d.quiet(1, Pass{})
		corrupt(d)
		if err := SyncFiles(d.l, d.l.AgentConfig()); err != nil {
			t.Fatal(err)
		}
		d.changedOnce(reset, est)
	})
	t.Run("unwritable", func(t *testing.T) {
		d := newDevice(t)
		d.quiet(1, Pass{})
		corrupt(d)
		readOnlyState(t, d)
		if ev := d.pass(est); !slices.Equal(ev, []string{reset}) {
			t.Fatalf("reported %v", ev)
		}
		d.quiet(5, est)
	})
	t.Run("deleted", func(t *testing.T) {
		d := newDevice(t)
		d.quiet(1, Pass{})
		d.remove(integrityFile)
		d.changedOnce(reset, est)
	})
	t.Run("recreated without the slots", func(t *testing.T) {
		d := newDevice(t)
		d.quiet(1, Pass{})
		d.remove(integrityFile)
		if err := SyncFiles(d.l, d.l.AgentConfig()); err != nil {
			t.Fatal(err)
		}
		d.changedOnce(reset, est)
	})
	t.Run("fresh device", func(t *testing.T) {
		d := newDevice(t)
		if !d.c.Check(context.Background(), Pass{}).Established {
			t.Fatal("not established after the first pass")
		}
		if len(d.events) != 0 {
			t.Fatal(d.events)
		}
		d.quiet(3, est)
	})
	t.Run("established only with the slots", func(t *testing.T) {
		d := newDevice(t)
		d.write("/var/lib/paddock/staging/request.json", "{}")
		if d.c.Check(context.Background(), Pass{}).Established {
			t.Fatal("established without the slots")
		}
	})
}
