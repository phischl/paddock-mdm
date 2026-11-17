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
	if _, err := UpdateResult(d.l, "2.0.0", "rollback_failed", at); err != nil {
		t.Fatal(err)
	}
	d.quiet(2, Pass{ReportedUpdateAt: &at})
	d.link("A", current)
	later := at.Add(time.Hour)
	writeResult(t, d, "2.0.0", "rolled_back", later)
	for range 2 {
		if _, err := UpdateResult(d.l, "2.0.0", "rolled_back", later); err != nil {
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

// settle writes the update result of 2.0.0 and processes it as the agent does; it returns unstaged.
func settle(t *testing.T, d *device, outcome string, at time.Time) bool {
	t.Helper()
	writeResult(t, d, "2.0.0", outcome, at)
	unstaged, err := UpdateResult(d.l, "2.0.0", outcome, at)
	if err != nil {
		t.Fatal(err)
	}
	return unstaged
}

// settled stages 2.0.0 into slot B, leaves current on slot and settles the release with outcome.
func settled(t *testing.T, d *device, slot, outcome string) time.Time {
	t.Helper()
	d.quiet(1, Pass{})
	at := stagedUpdate(t, d)
	d.link(slot, current)
	d.remove("/var/lib/paddock/state/probation.json")
	if settle(t, d, outcome, at) {
		t.Fatalf("%s of the staged release is unstaged", outcome)
	}
	d.quiet(1, Pass{ReportedUpdateAt: &at})
	return at
}

// TestSettledReleaseMovesNothing (plan M5a R16): a later result of a release that already settled is unstaged and
// moves nothing, so a switch of current made with it is reported.
func TestSettledReleaseMovesNothing(t *testing.T) {
	for _, tc := range []struct {
		first, slot string
		forged      []string
		to          string
	}{
		{"updated", "B", []string{"rollback_failed", "rolled_back"}, "A"},
		{"rolled_back", "A", []string{"updated"}, "B"},
		{"self_test_failed", "A", []string{"rollback_failed"}, "B"},
	} {
		t.Run(tc.first+" then "+strings.Join(tc.forged, ", "), func(t *testing.T) {
			d := newDevice(t)
			at := settled(t, d, tc.slot, tc.first)
			for i, outcome := range tc.forged {
				if i == len(tc.forged)-1 {
					d.link(tc.to, current)
				}
				at = at.Add(time.Hour)
				if !settle(t, d, outcome, at) {
					t.Fatalf("%s after %s is not unstaged", outcome, tc.first)
				}
			}
			d.changedOnce(current, Pass{ReportedUpdateAt: &at})
		})
	}
}

// TestUpdateResultToggle (plan M5a R16): rollback_failed, rolled_back and updated of one release repeated with
// switches of current report every round after the first; the baseline never moves silently.
func TestUpdateResultToggle(t *testing.T) {
	d := newDevice(t)
	d.quiet(1, Pass{})
	at := stagedUpdate(t, d)
	d.remove("/var/lib/paddock/state/probation.json")
	for round := range 3 {
		var unstaged []bool
		step := func(slot, outcome string) {
			d.link(slot, current)
			at = at.Add(time.Minute)
			unstaged = append(unstaged, settle(t, d, outcome, at))
		}
		step("B", "rollback_failed")
		step("A", "rolled_back")
		if ev := d.pass(Pass{ReportedUpdateAt: &at}); len(ev) != 0 {
			t.Fatalf("round %d: reported %v on the expected slot", round, ev)
		}
		step("B", "updated")
		want := []bool{round > 0, round > 0, true}
		if !slices.Equal(unstaged, want) {
			t.Fatalf("round %d: unstaged %v, want %v", round, unstaged, want)
		}
		if ev := d.pass(Pass{ReportedUpdateAt: &at}); !slices.Equal(ev, []string{current}) {
			t.Fatalf("round %d: reported %v", round, ev)
		}
		if b := d.baseline(); b.Expected[current] != "A" {
			t.Fatalf("round %d: current %q", round, b.Expected[current])
		}
	}
}

// TestRolledBackChangedSlot (plan M5a R16): the completed rollback does not move current to a changed slot.
func TestRolledBackChangedSlot(t *testing.T) {
	d := newDevice(t)
	at := settled(t, d, "B", "rollback_failed")
	d.write(slotA, "agent other")
	d.link("A", current)
	later := at.Add(time.Hour)
	if settle(t, d, "rolled_back", later) {
		t.Fatal("the completed rollback is unstaged")
	}
	if ev := d.pass(Pass{ReportedUpdateAt: &later}); !slices.Equal(ev, []string{slotA, current}) {
		t.Fatalf("reported %v", ev)
	}
	if b := d.baseline(); b.Expected[current] != "B" || b.LastResult.RollbackPending {
		t.Fatalf("current %q, last result %+v", b.Expected[current], b.LastResult)
	}
}

// TestUpdateResultReplay (plan M5a R16): the same result again, as after a crash before the agent state was saved,
// changes nothing; the same result with another at is unstaged.
func TestUpdateResultReplay(t *testing.T) {
	d := newDevice(t)
	at := settled(t, d, "B", "updated")
	if settle(t, d, "updated", at) {
		t.Fatal("the replay is unstaged")
	}
	later := at.Add(time.Hour)
	if !settle(t, d, "updated", later) {
		t.Fatal("a result with another at is not unstaged")
	}
	d.quiet(3, Pass{ReportedUpdateAt: &later})
}

// TestFirstResultWithoutRecord (plan M5a R16): the first update result on a device without a record of the slots, as
// after an update from a release without the check, raises nothing.
func TestFirstResultWithoutRecord(t *testing.T) {
	d := newDevice(t)
	d.write(slotB, "agent v2")
	d.link("B", current)
	at := time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)
	if settle(t, d, "updated", at) {
		t.Fatal("unstaged without a record")
	}
	d.quiet(3, Pass{ReportedUpdateAt: &at})
}

// TestBaselineCompatibility (plan M5a R16): an agent of PDK-1122a reads a baseline with LastResult, and this agent reads
// one of PDK-1122a with LastStaged and the flag of a40549bd, which it ignores.
func TestBaselineCompatibility(t *testing.T) {
	t.Run("older agent", func(t *testing.T) {
		d := newDevice(t)
		settled(t, d, "B", "rollback_failed")
		raw, err := os.ReadFile(d.l.Integrity())
		if err != nil || !strings.Contains(string(raw), `"last_result":{`) {
			t.Fatalf("baseline %s: %v", raw, err)
		}
		// The fields of Baseline as of PDK-1122a; Go's decoder skips the others.
		var older struct {
			Generation uint64            `json:"generation"`
			Expected   map[string]string `json:"expected"`
			Staged     *Staged           `json:"staged"`
			LastStaged *Staged           `json:"last_staged"`
			Reported   map[string]string `json:"reported"`
		}
		if err := json.Unmarshal(raw, &older); err != nil || older.Expected[current] != "B" || older.LastStaged != nil {
			t.Fatalf("an older agent could not read the baseline: %v, %+v", err, older)
		}
	})
	t.Run("older baseline", func(t *testing.T) {
		d := newDevice(t)
		d.quiet(1, Pass{})
		raw, err := os.ReadFile(d.l.Integrity())
		if err != nil {
			t.Fatal(err)
		}
		var b map[string]any
		if err := json.Unmarshal(raw, &b); err != nil {
			t.Fatal(err)
		}
		b["last_staged"] = map[string]string{"version": "2.0.0", "sha256": sha("agent v2")}
		b["rollback_pending"] = true
		raw, _ = json.Marshal(b)
		if err := os.WriteFile(d.l.Integrity(), raw, 0o600); err != nil {
			t.Fatal(err)
		}
		d.quiet(2, Pass{})
		if !settle(t, d, "rolled_back", time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)) {
			t.Fatal("a result for the old LastStaged is not unstaged")
		}
	})
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
