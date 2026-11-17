package integrity

import (
	"errors"
	"io/fs"
	"os"
	"slices"
	"testing"
	"time"
)

// alternating holds two blockers of one object in turns of five hours for three days, one interval apart, and
// returns the check_suspended reports with the hour they came at.
func (d *device) alternating(first, second func(on bool), p Pass) map[string][]time.Duration {
	d.t.Helper()
	p.Interval = interval
	start := d.clock
	reports := map[string][]time.Duration{}
	for at := time.Duration(0); at <= 72*time.Hour; at += interval {
		turn := int(at/(5*time.Hour)) % 2
		first(turn == 0)
		second(turn == 1)
		for _, s := range suspensions(d.tick(p)) {
			reports[s] = append(reports[s], d.clock.Sub(start))
		}
	}
	return reports
}

// exactlyOnceAt asserts one report in total, of file, at the first pass at or past FlowBound.
func exactlyOnceAt(t *testing.T, reports map[string][]time.Duration, file string) {
	t.Helper()
	got := reports[suspended(file)]
	if len(reports) != 1 || len(got) != 1 || got[0] < FlowBound || got[0] > FlowBound+interval {
		t.Fatalf("reported %v, want %s once after %v", reports, suspended(file), FlowBound)
	}
}

// TestSuspensionPerObject (plan M5a R15.2, T16): blockers of one object that take turns never restart its bound.
func TestSuspensionPerObject(t *testing.T) {
	t.Run("slots", func(t *testing.T) {
		d := clockedDevice(t)
		d.write(slotB, "trojan")
		reports := d.alternating(func(on bool) { d.toggle(on, "/var/lib/paddock/state/probation.json", "{}") },
			func(on bool) { d.toggle(on, "/var/lib/paddock/staging/request.json", "{}") }, Pass{})
		// At six hours the second blocker holds the slots.
		exactlyOnceAt(t, reports, "/var/lib/paddock/staging/request.json")
	})
	t.Run("package", func(t *testing.T) {
		d := clockedDevice(t)
		const sums = "/var/lib/dpkg/info/paddock-agent.md5sums"
		genuine := d.read(sums)
		reports := d.alternating(func(on bool) { d.busy = on }, func(on bool) {
			if on {
				d.mkfifo(sums)
			} else {
				d.removeIfPresent(sums)
				d.write(sums, genuine)
			}
		}, Pass{})
		exactlyOnceAt(t, reports, sums)
	})
	t.Run("supervisor package", func(t *testing.T) {
		d := clockedDevice(t)
		reports := d.alternating(func(on bool) { d.toggle(on, "/var/lib/paddock/state/supervisor-upgrade.json", "{}") },
			func(on bool) { d.toggle(on, "/var/lib/paddock/state/supervisor-upgrade-result.json", "{not json") }, Pass{})
		exactlyOnceAt(t, reports, "/var/lib/paddock/state/supervisor-upgrade-result.json")
	})
}

// toggle writes or removes a device file.
func (d *device) toggle(on bool, path, content string) {
	d.t.Helper()
	if on {
		d.write(path, content)
	} else {
		d.removeIfPresent(path)
	}
}

func (d *device) removeIfPresent(path string) {
	if err := os.Remove(d.l.Join(path)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		d.t.Fatal(err)
	}
}

func (d *device) read(path string) string {
	d.t.Helper()
	data, err := os.ReadFile(d.l.Join(path))
	if err != nil {
		d.t.Fatal(err)
	}
	return string(data)
}

// TestSuspensionAcrossRestartsAndALockedBaseline (plan M5a R15.3, R15.4, T17): with integrity.lock held and the agent
// restarted every ten minutes, seeded from the state the previous one returned, the baseline reports after
// StateBound and the slots, blocked before the lock was taken, after FlowBound.
func TestSuspensionAcrossRestartsAndALockedBaseline(t *testing.T) {
	t.Run("probation", func(t *testing.T) {
		d := clockedDevice(t)
		d.write("/var/lib/paddock/state/probation.json", "{}")
		d.lockedRestarts("/var/lib/paddock/state/probation.json")
	})
	// The staged guard runs only in a classified pass: its episode survives the passes the lock skips (R15.4).
	t.Run("staged", func(t *testing.T) {
		d := clockedDevice(t)
		if err := RecordStaged(d.l, "2.0.0", sha("agent v2")); err != nil {
			t.Fatal(err)
		}
		d.write(slotB, "agent v2")
		d.lockedRestarts(slotB)
	})
}

// lockedRestarts starts the slots' episode in one pass, then holds integrity.lock and restarts the checker every ten
// minutes: the baseline reports after StateBound and the slots with file after FlowBound. A blocker that appears
// while the lock is held starts no episode.
func (d *device) lockedRestarts(file string) {
	t := d.t
	t.Helper()
	const step = 10 * time.Minute
	p := Pass{Interval: step}
	d.quiet(1, p)
	holdLock(t, d)
	d.write("/var/lib/paddock/state/supervisor-upgrade.json", "{}")
	start := d.clock
	reports := map[string][]time.Duration{}
	for d.clock.Sub(start) < FlowBound+step {
		d.restart()
		d.clock = d.clock.Add(step)
		for _, s := range suspensions(d.pass(p)) {
			reports[s] = append(reports[s], d.clock.Sub(start))
		}
	}
	if _, ok := d.state["package:"+supervisorPackage]; ok {
		t.Fatalf("a pass the lock skipped started %v", d.state)
	}
	lock := reports[suspended("/var/lib/paddock/state/integrity.lock")]
	slots := reports[suspended(file)]
	// The first pass with the lock held starts the baseline's episode one step after start.
	if len(reports) != 2 || len(lock) != 1 || lock[0] < StateBound+step || lock[0] > StateBound+2*step ||
		len(slots) != 1 || slots[0] < FlowBound-step || slots[0] > FlowBound+step {
		t.Fatalf("reported %v", reports)
	}
}

// TestStaleStagedReleaseNotSuspended (plan M5a R15.6, T19): a staged release that equals what the inactive slot
// already holds blocks nothing while staging keeps failing.
func TestStaleStagedReleaseNotSuspended(t *testing.T) {
	d := newDevice(t)
	d.write(slotB, "agent v2")
	d.clock = time.Date(2026, 11, 16, 8, 0, 0, 0, time.UTC)
	p := Pass{Interval: interval}
	d.quiet(1, p)
	if err := RecordStaged(d.l, "2.0.0", sha("agent v2")); err != nil {
		t.Fatal(err)
	}
	for range 7 * time.Hour / interval {
		if ev := d.tick(p); len(ev) != 0 {
			t.Fatalf("reported %v", ev)
		}
	}
	// A changed slot still reports.
	d.write(slotB, "trojan")
	if ev := d.tick(p); !slices.Equal(ev, []string{slotB}) {
		t.Fatalf("reported %v", ev)
	}
}

// TestCorruptBaselineWithAGeneration (plan M5a R15.7, T20): a corrupt baseline that still carries a generation is
// rebuilt and reported, not dropped as raced, also when it cannot be moved aside or saved.
func TestCorruptBaselineWithAGeneration(t *testing.T) {
	d := clockedDevice(t)
	d.write(integrityFile, `{"generation":7,"expected":1}`)
	readOnlyState(t, d)
	if ev := d.tick(Pass{Interval: interval}); !slices.Equal(ev, []string{reset}) {
		t.Fatalf("reported %v", ev)
	}
	for range 2 {
		if ev := d.tick(Pass{Interval: interval}); len(ev) != 0 {
			t.Fatalf("reported %v again", ev)
		}
	}
}
