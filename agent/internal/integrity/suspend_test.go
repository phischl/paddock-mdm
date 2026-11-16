package integrity

import (
	"bufio"
	"os"
	"os/exec"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/pkg/protocol"
)

const interval = 5 * time.Minute

var (
	reset     = integrityFile + "#" + protocol.TamperReasonBaselineReset
	suspended = func(file string) string { return file + "#" + protocol.TamperReasonCheckSuspended }
)

// suspensions returns the check_suspended reports of a pass.
func suspensions(ev []string) []string {
	var out []string
	for _, e := range ev {
		if strings.HasSuffix(e, "#"+protocol.TamperReasonCheckSuspended) {
			out = append(out, e)
		}
	}
	return out
}

// tick advances the clock by one interval and runs a pass.
func (d *device) tick(p Pass) []string {
	d.t.Helper()
	d.clock = d.clock.Add(interval)
	return d.pass(p)
}

// suspendedAt runs passes one interval apart while a cause holds, the first one interval after the last pass: none
// reports a suspension before bound, the first pass at bound reports exactly file, and three later passes report
// nothing more.
func (d *device) suspendedAt(file string, bound time.Duration, p Pass) {
	d.t.Helper()
	p.Interval = interval
	if s := suspensions(d.tick(p)); len(s) != 0 {
		d.t.Fatalf("first pass reported %v", s)
	}
	for at := interval; at < bound; at += interval {
		if s := suspensions(d.tick(p)); len(s) != 0 {
			d.t.Fatalf("reported %v after %v, before the bound %v", s, at, bound)
		}
	}
	if s := suspensions(d.tick(p)); !slices.Equal(s, []string{suspended(file)}) {
		d.t.Fatalf("at the bound %v reported %v, want %s", bound, s, suspended(file))
	}
	for range 3 {
		if s := suspensions(d.tick(p)); len(s) != 0 {
			d.t.Fatalf("reported %v again", s)
		}
	}
}

func clockedDevice(t *testing.T) *device {
	t.Helper()
	d := newDevice(t)
	d.clock = time.Date(2026, 11, 16, 8, 0, 0, 0, time.UTC)
	d.quiet(1, Pass{Interval: interval})
	return d
}

func holdLock(t *testing.T, d *device) *os.File {
	t.Helper()
	f, err := os.OpenFile(d.l.IntegrityLock(), os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil { //nolint:gosec // a file descriptor fits an int
		t.Fatal(err)
	}
	return f
}

// readOnlyState makes the state directory read-only; root ignores the mode, so the test needs another user.
func readOnlyState(t *testing.T, d *device) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("root writes into a read-only directory")
	}
	dir := d.l.Join("/var/lib/paddock/state")
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
}

// TestSuspensionBounds (plan M5a R3, R4, T9): every cause reports itself once its observed time reaches its bound.
func TestSuspensionBounds(t *testing.T) {
	const state = "/var/lib/paddock/state/"
	for _, tc := range []struct {
		name, file string
		bound      time.Duration
		cause      func(t *testing.T, d *device, p *Pass)
	}{
		{"lock", state + "integrity.lock", StateBound, func(t *testing.T, d *device, _ *Pass) { holdLock(t, d) }},
		{"baseline_read", integrityFile, StateBound, func(t *testing.T, d *device, _ *Pass) {
			d.remove(integrityFile)
			if err := os.Mkdir(d.l.Integrity(), 0o700); err != nil {
				t.Fatal(err)
			}
		}},
		{"baseline_write", integrityFile, StateBound, func(t *testing.T, d *device, _ *Pass) { readOnlyState(t, d) }},
		{"update_request", "/var/lib/paddock/staging/request.json", FlowBound, func(_ *testing.T, d *device, _ *Pass) {
			d.write("/var/lib/paddock/staging/request.json", `{"version":"2.0.0"}`)
		}},
		{"probation", state + "probation.json", FlowBound, func(_ *testing.T, d *device, _ *Pass) {
			d.write(state+"probation.json", "{}")
		}},
		{"update_result", state + "update-result.json", FlowBound, func(_ *testing.T, d *device, _ *Pass) {
			d.write(state+"update-result.json", "{not json")
		}},
		{"supervisor_marker", state + "supervisor-upgrade.json", FlowBound, func(_ *testing.T, d *device, _ *Pass) {
			d.write(state+"supervisor-upgrade.json", "{}")
		}},
		{"staged", slotB, FlowBound, func(t *testing.T, d *device, _ *Pass) {
			if err := RecordStaged(d.l, "2.0.0", sha("agent v2")); err != nil {
				t.Fatal(err)
			}
			d.write(slotB, "agent v2")
		}},
		{"conversion", "/etc/paddock/disk-setup.json", FlowBound, func(_ *testing.T, d *device, p *Pass) {
			p.SkipFiles = []string{d.l.DiskSetupConfig()}
		}},
		{"dpkg_lock", "/var/lib/dpkg/lock-frontend", FlowBound, func(_ *testing.T, d *device, _ *Pass) { d.busy = true }},
		{"unit", "/etc/systemd/system/orbit.service.d", FlowBound, func(_ *testing.T, d *device, _ *Pass) {
			d.sys.units["orbit.service"] = "LoadState=loaded\nDropInPaths=\"/etc/systemd/system/orbit.service.d/a\n"
		}},
		{"package", "/var/lib/dpkg/info/paddock-revoke.md5sums", FlowBound, func(_ *testing.T, d *device, _ *Pass) {
			delete(d.sys.status, "paddock-revoke")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := clockedDevice(t)
			var p Pass
			tc.cause(t, d, &p)
			d.suspendedAt(tc.file, tc.bound, p)
		})
	}
}

// TestSuspensionEpisodes (T9): a cause that ends and comes back is a new episode; a long gap between two passes counts
// as two intervals; a restart continues the persisted count.
func TestSuspensionEpisodes(t *testing.T) {
	const request = "/var/lib/paddock/staging/request.json"
	p := Pass{Interval: interval}
	t.Run("new episode", func(t *testing.T) {
		d := clockedDevice(t)
		d.write(request, "{}")
		d.suspendedAt(request, FlowBound, p)
		d.remove(request)
		d.tick(p)
		d.write(request, "{}")
		d.suspendedAt(request, FlowBound, p)
	})
	t.Run("a night of sleep", func(t *testing.T) {
		d := clockedDevice(t)
		d.write(request, "{}")
		d.quiet(1, p)
		d.clock = d.clock.Add(12 * time.Hour)
		d.quiet(1, p)
		d.remove(request)
		d.quiet(1, p)
	})
	t.Run("restart", func(t *testing.T) {
		d := clockedDevice(t)
		d.write(request, "{}")
		d.quiet(1, p)
		for range FlowBound/interval - 1 {
			if s := suspensions(d.tick(p)); len(s) != 0 {
				t.Fatal(s)
			}
		}
		d.restart()
		if s := suspensions(d.tick(p)); !slices.Equal(s, []string{suspended(request)}) {
			t.Fatalf("after the restart reported %v", s)
		}
	})
}

// TestRegularFlowsNotSuspended (T10): a normal update, a two-hour conversion and a two-hour dpkg run stay below
// every bound.
func TestRegularFlowsNotSuspended(t *testing.T) {
	d := clockedDevice(t)
	p := Pass{Interval: interval}
	if err := RecordStaged(d.l, "2.0.0", sha("agent v2")); err != nil {
		t.Fatal(err)
	}
	d.write("/var/lib/paddock/staging/request.json", "{}")
	d.tick(p)
	d.write(slotB, "agent v2")
	d.write("/var/lib/paddock/state/probation.json", "{}")
	d.link("B", current)
	d.remove("/var/lib/paddock/staging/request.json")
	for range 3 {
		if ev := d.tick(p); len(ev) != 0 {
			t.Fatal(ev)
		}
	}
	d.remove("/var/lib/paddock/state/probation.json")
	at := d.clock
	writeResult(t, d, "2.0.0", "updated", at)
	d.tick(p)
	if err := UpdateResult(d.l, "2.0.0"); err != nil {
		t.Fatal(err)
	}
	p.ReportedUpdateAt = &at
	conv := p
	conv.SkipFiles = []string{d.l.DiskSetupConfig()}
	for range 2 * time.Hour / interval {
		if ev := d.tick(conv); len(ev) != 0 {
			t.Fatal(ev)
		}
	}
	d.busy = true
	for range 2 * time.Hour / interval {
		if ev := d.tick(p); len(ev) != 0 {
			t.Fatal(ev)
		}
	}
	d.busy = false
	if ev := d.tick(p); len(ev) != 0 || len(d.c.suspended) != 0 {
		t.Fatalf("reported %v, suspended %v", ev, d.c.suspended)
	}
}

// TestUnwritableBaselineReported (T9): a baseline that cannot be saved reports integrity.json after StateBound.
func TestUnwritableBaselineReported(t *testing.T) {
	d := clockedDevice(t)
	readOnlyState(t, d)
	d.suspendedAt(integrityFile, StateBound, Pass{})
}

// TestUnreadableBaselineSkipsThePass (R11 L2, T12): a baseline that cannot be read is neither recorded anew nor
// moved aside, and the pass reports nothing until the bound.
func TestUnreadableBaselineSkipsThePass(t *testing.T) {
	d := clockedDevice(t)
	d.remove(integrityFile)
	if err := os.Mkdir(d.l.Integrity(), 0o700); err != nil {
		t.Fatal(err)
	}
	d.write(slotB, "foreign")
	d.quiet(2, Pass{Interval: interval})
	if info, err := os.Lstat(d.l.Integrity()); err != nil || !info.IsDir() {
		t.Fatalf("integrity.json replaced: %v", err)
	}
	if _, err := os.Lstat(d.l.Integrity() + ".corrupt"); err == nil {
		t.Fatal("moved aside")
	}
	if _, ok := d.c.suspended[causeBaselineRead]; !ok {
		t.Fatalf("suspended %v", d.c.suspended)
	}
}

// TestHelperHoldDpkgLock is the child process of TestProductionDpkgBusy: it holds an F_SETLK write lock on the file
// named by PADDOCK_TEST_DPKG_LOCK until its stdin closes.
func TestHelperHoldDpkgLock(t *testing.T) {
	path := os.Getenv("PADDOCK_TEST_DPKG_LOCK")
	if path == "" {
		t.Skip("helper process only")
	}
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600) //nolint:gosec // a test path
	if err != nil {
		t.Fatal(err)
	}
	lk := syscall.Flock_t{Type: syscall.F_WRLCK}
	if err := syscall.FcntlFlock(f.Fd(), syscall.F_SETLK, &lk); err != nil {
		t.Fatal(err)
	}
	_, _ = os.Stdout.WriteString("locked\n")
	_, _ = bufio.NewReader(os.Stdin).ReadString('\n')
}

// TestProductionDpkgBusy (R11 L1, T11): the DpkgBusy of New sees a lock another process holds on dpkg's database or
// frontend lock, and the package check is suspended while it is held.
func TestProductionDpkgBusy(t *testing.T) {
	for _, lock := range []string{"/var/lib/dpkg/lock", "/var/lib/dpkg/lock-frontend"} {
		t.Run(lock, func(t *testing.T) {
			d := newDevice(t)
			d.c.DpkgBusy = New(d.l, d.sys).DpkgBusy
			d.quiet(1, Pass{})
			cmd := exec.Command(os.Args[0], "-test.run=^TestHelperHoldDpkgLock$") //nolint:gosec // the test binary itself
			cmd.Env = append(os.Environ(), "PADDOCK_TEST_DPKG_LOCK="+d.l.Join(lock))
			stdin, err := cmd.StdinPipe()
			if err != nil {
				t.Fatal(err)
			}
			stdout, err := cmd.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = stdin.Close(); _ = cmd.Wait() })
			if line, err := bufio.NewReader(stdout).ReadString('\n'); err != nil || line != "locked\n" {
				t.Fatalf("helper: %q, %v", line, err)
			}
			d.write("/opt/paddock/revoke/paddock-revoke", "foreign")
			d.quiet(1, Pass{})
			if _, ok := d.c.suspended["dpkg_lock"]; !ok {
				t.Fatalf("suspended %v", d.c.suspended)
			}
			_ = stdin.Close()
			_ = cmd.Wait()
			d.changedOnce("/opt/paddock/revoke/paddock-revoke", Pass{})
		})
	}
}
