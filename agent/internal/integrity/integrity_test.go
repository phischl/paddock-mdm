package integrity

import (
	"context"
	"crypto/md5" //nolint:gosec // the md5sums of the fake dpkg database
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/agent/internal/paths"
)

// fakeSys answers systemctl show per unit and dpkg-query per package.
type fakeSys struct {
	units    map[string]string // unit → show output; missing = not-found
	status   map[string]string // package → db:Status-Status
	onStatus func(pkg string)
	showErr  error
}

func (f *fakeSys) Systemctl(_ context.Context, args ...string) (string, int, error) {
	if f.showErr != nil {
		return "", -1, f.showErr
	}
	if out, ok := f.units[args[len(args)-1]]; ok {
		return out, 0, nil
	}
	return "LoadState=not-found\nFragmentPath=\nDropInPaths=\n", 0, nil
}

func (f *fakeSys) Output(_ context.Context, _ string, args ...string) ([]byte, error) {
	pkg := args[len(args)-1]
	if f.onStatus != nil {
		f.onStatus(pkg)
	}
	if s, ok := f.status[pkg]; ok {
		return []byte(s), nil
	}
	return nil, errors.New("dpkg-query: exit 1")
}

// device is a test root with an installed Paddock.
type device struct {
	t      *testing.T
	l      paths.Layout
	sys    *fakeSys
	busy   bool
	c      *Checker
	events []string
	logs   *logs
	// clock is the checker's time when set.
	clock time.Time
	// state is the agent state's suspensions, handed to every pass as the agent does.
	state map[string]Suspension
}

func show(fragment string, dropIns ...string) string {
	return "LoadState=loaded\nFragmentPath=" + fragment + "\nDropInPaths=" + strings.Join(dropIns, " ") + "\n"
}

// newDevice installs the agent in slot A, the five packages with their md5sums, the configuration files and units.
func newDevice(t *testing.T) *device {
	t.Helper()
	d := &device{t: t, l: paths.Layout{Root: t.TempDir()}, sys: &fakeSys{units: map[string]string{}, status: map[string]string{}}}
	d.logs = captureLogs(t)
	d.write(slotA, "agent v1")
	d.link("A", current)
	d.link(agentTarget, agentLink)
	for _, f := range []string{"/etc/paddock/agent.yml", "/etc/paddock/trust.json", "/etc/paddock/revoke-trust.json"} {
		d.write(f, "config of "+f)
	}
	d.install("paddock-agent", "/usr/lib/paddock/paddockd", "/usr/lib/systemd/system/paddock-disk-setup.service",
		"/usr/share/pam-configs/paddock-deny", "/usr/share/doc/paddock-agent/copyright")
	d.install(supervisorPackage, "/usr/sbin/paddock-supervisor", "/usr/lib/systemd/system/paddock-supervisor.service",
		"/usr/share/doc/paddock-supervisor/copyright")
	d.install("paddock-revoke", "/opt/paddock/revoke/paddock-revoke")
	d.install("paddock-self-service", "/usr/lib/paddock-self-service/paddock-self-service",
		"/usr/share/applications/com.paddock.SelfService.desktop")
	d.install("fleet-osquery", "/opt/orbit/bin/orbit/linux/stable/orbit", "/usr/lib/systemd/system/orbit.service",
		"/opt/orbit/tuf-metadata.json")
	d.link("linux/stable/orbit", "/opt/orbit/bin/orbit/orbit")
	d.sys.units["paddock-supervisor.service"] = show("/usr/lib/systemd/system/paddock-supervisor.service")
	d.sys.units["paddock-disk-setup.service"] = show("/lib/systemd/system/paddock-disk-setup.service")
	d.sys.units["orbit.service"] = show("/usr/lib/systemd/system/orbit.service", "/etc/systemd/system/orbit.service.d/90-paddock.conf")
	d.write("/etc/systemd/system/orbit.service.d/90-paddock.conf", "[Service]\n")
	d.write("/etc/systemd/system/paddock-updates.service", "[Service]\n")
	d.write("/etc/systemd/system/paddock-updates.timer", "[Timer]\n")
	d.sys.units["paddock-updates.service"] = show("/etc/systemd/system/paddock-updates.service")
	d.sys.units["paddock-updates.timer"] = show("/etc/systemd/system/paddock-updates.timer")
	// /lib is a symlink to /usr/lib on a merged-/usr system.
	if err := os.Symlink("usr/lib", d.l.Join("/lib")); err != nil {
		t.Fatal(err)
	}
	d.restart()
	return d
}

// restart replaces the checker, as an agent restart does: the hash cache and the Warn throttle are gone.
func (d *device) restart() {
	d.c = New(d.l, d.sys)
	d.c.DpkgBusy = func() bool { return d.busy }
	d.c.Sleep = func(time.Duration) {}
	d.c.Now = func() time.Time {
		if d.clock.IsZero() {
			return time.Now()
		}
		return d.clock
	}
	d.c.Emit = func(f, reason string) {
		if reason != "" {
			f += "#" + reason
		}
		d.events = append(d.events, f)
	}
}

func (d *device) write(path, content string) {
	d.t.Helper()
	full := d.l.Join(path)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		d.t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(content), 0o644); err != nil { //nolint:gosec // test files
		d.t.Fatal(err)
	}
	// The hash cache keys on the mtime; a rewrite within one clock tick must still count as a change.
	at := time.Now().Add(time.Duration(len(content)) * time.Second)
	_ = os.Chtimes(full, at, at)
}

func (d *device) remove(path string) {
	d.t.Helper()
	if err := os.Remove(d.l.Join(path)); err != nil {
		d.t.Fatal(err)
	}
}

func (d *device) link(target, path string) {
	d.t.Helper()
	full := d.l.Join(path)
	_ = os.MkdirAll(filepath.Dir(full), 0o755)
	_ = os.Remove(full)
	if err := os.Symlink(target, full); err != nil {
		d.t.Fatal(err)
	}
}

// install writes a package's files with the content "<file> 1" and its md5sums, as dpkg does.
func (d *device) install(pkg string, files ...string) {
	d.t.Helper()
	for _, f := range files {
		d.write(f, f+" 1")
	}
	d.writeSums(pkg, files...)
	d.sys.status[pkg] = "installed"
}

// writeSums writes the md5sums of the files as they are now.
func (d *device) writeSums(pkg string, files ...string) {
	d.t.Helper()
	var b strings.Builder
	for _, f := range files {
		data, err := os.ReadFile(d.l.Join(f))
		if err != nil {
			d.t.Fatal(err)
		}
		sum := md5.Sum(data) //nolint:gosec // dpkg's format
		b.WriteString(hex.EncodeToString(sum[:]) + "  " + strings.TrimPrefix(f, "/") + "\n")
	}
	d.write("/var/lib/dpkg/info/"+pkg+".md5sums", b.String())
}

// pass runs one check and returns the files it reported.
func (d *device) pass(p Pass) []string {
	d.t.Helper()
	d.events = nil
	if p.Suspended == nil {
		p.Suspended = d.state
	}
	d.state = d.c.Check(context.Background(), p).Suspended
	return d.events
}

// passes runs n checks and fails on any report.
func (d *device) quiet(n int, p Pass) {
	d.t.Helper()
	for i := range n {
		if ev := d.pass(p); len(ev) != 0 {
			d.t.Fatalf("pass %d reported %v, want nothing", i+1, ev)
		}
	}
}

// changedOnce asserts exactly one report of file, and none in the next three passes.
func (d *device) changedOnce(file string, p Pass) {
	d.t.Helper()
	if ev := d.pass(p); !slices.Equal(ev, []string{file}) {
		d.t.Fatalf("reported %v, want exactly [%s]", ev, file)
	}
	d.quiet(3, p)
}

func (d *device) baseline() *Baseline {
	d.t.Helper()
	data, err := os.ReadFile(d.l.Integrity())
	if err != nil {
		d.t.Fatal(err)
	}
	var b Baseline
	if err := json.Unmarshal(data, &b); err != nil {
		d.t.Fatal(err)
	}
	return &b
}

func sha(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// logs records the log lines of a test at Warn and above.
type logs struct {
	mu    sync.Mutex
	lines []slog.Record
}

func (l *logs) Enabled(_ context.Context, lv slog.Level) bool { return lv >= slog.LevelInfo }
func (l *logs) Handle(_ context.Context, r slog.Record) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines = append(l.lines, r)
	return nil
}
func (l *logs) WithAttrs([]slog.Attr) slog.Handler { return l }
func (l *logs) WithGroup(string) slog.Handler      { return l }

func (l *logs) count(lv slog.Level) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := 0
	for _, r := range l.lines {
		if r.Level == lv {
			n++
		}
	}
	return n
}

func (l *logs) reset() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines = nil
}

func captureLogs(t *testing.T) *logs {
	l := &logs{}
	old := slog.Default()
	slog.SetDefault(slog.New(l))
	t.Cleanup(func() { slog.SetDefault(old) })
	return l
}

func TestUnchangedStateReportsNothing(t *testing.T) {
	d := newDevice(t)
	d.quiet(5, Pass{})
	if n := d.logs.count(slog.LevelWarn) + d.logs.count(slog.LevelError); n != 0 {
		t.Fatalf("%d warnings or errors on an unchanged device: %v", n, d.logs.lines)
	}
	b := d.baseline()
	if b.Expected[slotA] != sha("agent v1") || b.Expected[slotB] != "" || b.Expected[current] != "A" ||
		b.Expected["/etc/paddock/disk-setup.json"] != "" {
		t.Fatalf("baseline %v", b.Expected)
	}
}

func TestSlotBinaryReplaced(t *testing.T) {
	d := newDevice(t)
	d.quiet(1, Pass{})
	d.write(slotB, "foreign")
	d.changedOnce(slotB, Pass{})
}

func TestCurrentFlipped(t *testing.T) {
	d := newDevice(t)
	d.write(slotB, "agent v0")
	d.quiet(1, Pass{})
	d.link("B", current)
	d.changedOnce(current, Pass{})
	d.link("A", current)
	d.quiet(3, Pass{})
	d.link("B", current)
	d.changedOnce(current, Pass{})
}

func TestPackageFilesChanged(t *testing.T) {
	for _, file := range []string{"/usr/sbin/paddock-supervisor", "/usr/lib/systemd/system/paddock-supervisor.service",
		"/opt/paddock/revoke/paddock-revoke", "/opt/orbit/bin/orbit/linux/stable/orbit", "/usr/lib/paddock/paddockd",
		"/usr/lib/systemd/system/paddock-disk-setup.service", "/usr/lib/paddock-self-service/paddock-self-service",
		"/usr/lib/systemd/system/orbit.service"} {
		t.Run(file, func(t *testing.T) {
			d := newDevice(t)
			d.quiet(1, Pass{})
			d.write(file, "foreign")
			d.changedOnce(file, Pass{})
		})
	}
	t.Run("removed", func(t *testing.T) {
		d := newDevice(t)
		d.quiet(1, Pass{})
		d.remove("/opt/paddock/revoke/paddock-revoke")
		d.changedOnce("/opt/paddock/revoke/paddock-revoke", Pass{})
	})
	t.Run("paddockd link", func(t *testing.T) {
		d := newDevice(t)
		d.quiet(1, Pass{})
		d.link("/tmp/paddockd", agentLink)
		d.changedOnce(agentLink, Pass{})
		d.link(agentTarget, agentLink)
		d.quiet(3, Pass{})
	})
	t.Run("documentation and fleetd data", func(t *testing.T) {
		d := newDevice(t)
		d.quiet(1, Pass{})
		d.write("/usr/share/doc/paddock-agent/copyright", "foreign")
		d.write("/opt/orbit/tuf-metadata.json", "rewritten by orbit")
		d.quiet(3, Pass{})
	})
}

func TestPackageSymlinkNotChecked(t *testing.T) {
	d := newDevice(t)
	d.quiet(1, Pass{})
	d.link("/tmp/orbit", "/opt/orbit/bin/orbit/orbit")
	d.quiet(3, Pass{})
	if n := d.logs.count(slog.LevelWarn) + d.logs.count(slog.LevelError); n != 0 {
		t.Fatalf("%d warnings or errors: %v", n, d.logs.lines)
	}
}

func TestConfigurationFiles(t *testing.T) {
	for name, change := range map[string]func(d *device) string{
		"edited": func(d *device) string {
			d.write("/etc/paddock/agent.yml", "drift_interval_s: 1")
			return "/etc/paddock/agent.yml"
		},
		"deleted": func(d *device) string { d.remove("/etc/paddock/trust.json"); return "/etc/paddock/trust.json" },
		"edited revoke trust": func(d *device) string {
			d.write("/etc/paddock/revoke-trust.json", "{}")
			return "/etc/paddock/revoke-trust.json"
		},
		"created": func(d *device) string {
			d.write("/etc/paddock/disk-setup.json", "{}")
			return "/etc/paddock/disk-setup.json"
		},
	} {
		t.Run(name, func(t *testing.T) {
			d := newDevice(t)
			d.quiet(1, Pass{})
			d.changedOnce(change(d), Pass{})
		})
	}
}

func TestPaddockWritesSynced(t *testing.T) {
	d := newDevice(t)
	d.quiet(1, Pass{})
	d.write("/etc/paddock/agent.yml", "re-enrolled")
	d.write("/etc/paddock/trust.json", "re-enrolled")
	d.write("/etc/paddock/disk-setup.json", "{}")
	if err := SyncFiles(d.l, d.l.AgentConfig(), d.l.Trust(), d.l.DiskSetupConfig()); err != nil {
		t.Fatal(err)
	}
	d.quiet(3, Pass{})
	d.remove("/etc/paddock/disk-setup.json")
	if err := SyncFiles(d.l, d.l.DiskSetupConfig()); err != nil {
		t.Fatal(err)
	}
	d.quiet(3, Pass{})
}

func TestSkippedFileWhileItsWriterRuns(t *testing.T) {
	d := newDevice(t)
	d.quiet(1, Pass{})
	d.write("/etc/paddock/disk-setup.json", "{}")
	d.quiet(2, Pass{SkipFiles: []string{d.l.DiskSetupConfig()}})
	if err := SyncFiles(d.l, d.l.DiskSetupConfig()); err != nil {
		t.Fatal(err)
	}
	d.quiet(2, Pass{})
}

func TestForeignDropIns(t *testing.T) {
	for _, file := range []string{"/etc/systemd/system/paddock-supervisor.service.d/x.conf",
		"/run/systemd/system/orbit.service.d/x.conf", "/etc/systemd/system/paddock-disk-setup.service.d/x.conf",
		"/etc/systemd/system/paddock-supervisor.service", "/run/systemd/system/paddock-updates.timer"} {
		t.Run(file, func(t *testing.T) {
			d := newDevice(t)
			d.quiet(1, Pass{})
			d.write(file, "[Service]\n")
			d.changedOnce(file, Pass{})
			d.write(file, "[Service]\nExecStart=\n")
			d.changedOnce(file, Pass{})
			d.remove(file)
			d.quiet(1, Pass{})
			d.write(file, "[Service]\n")
			d.changedOnce(file, Pass{})
		})
	}
	t.Run("systemd's view", func(t *testing.T) {
		d := newDevice(t)
		d.quiet(1, Pass{})
		d.write("/usr/lib/systemd/system/paddock-supervisor.service.d/x.conf", "[Service]\n")
		d.sys.units["paddock-supervisor.service"] = show("/usr/lib/systemd/system/paddock-supervisor.service",
			"/usr/lib/systemd/system/paddock-supervisor.service.d/x.conf")
		d.changedOnce("/usr/lib/systemd/system/paddock-supervisor.service.d/x.conf", Pass{})
		d.write("/usr/local/lib/systemd/system/paddock-disk-setup.service", "[Service]\n")
		d.sys.units["paddock-disk-setup.service"] = show("/usr/local/lib/systemd/system/paddock-disk-setup.service")
		d.changedOnce("/usr/local/lib/systemd/system/paddock-disk-setup.service", Pass{})
	})
	t.Run("systemctl fails", func(t *testing.T) {
		d := newDevice(t)
		d.write("/usr/lib/systemd/system/paddock-supervisor.service.d/x.conf", "[Service]\n")
		d.sys.units["paddock-supervisor.service"] = show("/usr/lib/systemd/system/paddock-supervisor.service",
			"/usr/lib/systemd/system/paddock-supervisor.service.d/x.conf")
		d.changedOnce("/usr/lib/systemd/system/paddock-supervisor.service.d/x.conf", Pass{})
		// A pass without systemd's view keeps the marks: the drop-in is not reported again once systemd answers.
		d.sys.showErr = errors.New("bus timeout")
		d.quiet(2, Pass{})
		d.sys.showErr = nil
		d.quiet(2, Pass{})
		d.remove("/usr/lib/systemd/system/paddock-supervisor.service.d/x.conf")
		d.sys.units["paddock-supervisor.service"] = show("/usr/lib/systemd/system/paddock-supervisor.service")
		d.quiet(2, Pass{})
	})
}

func TestAllowListedUnitFiles(t *testing.T) {
	d := newDevice(t)
	d.quiet(1, Pass{})
	d.write("/etc/systemd/system/orbit.service.d/90-paddock.conf", "[Service]\nEnvironmentFile=/etc/paddock/orbit.env\n")
	d.write("/etc/systemd/system/paddock-updates.service", "[Service]\nExecStart=/usr/bin/paddockd updates run\n")
	d.quiet(3, Pass{})
}

func TestRestartRepeatsNothing(t *testing.T) {
	d := newDevice(t)
	d.quiet(1, Pass{})
	d.write(slotB, "foreign")
	d.write("/usr/sbin/paddock-supervisor", "foreign")
	d.write("/etc/systemd/system/orbit.service.d/x.conf", "x")
	if ev := d.pass(Pass{}); len(ev) != 3 {
		t.Fatalf("reported %v", ev)
	}
	d.restart()
	d.quiet(3, Pass{})
}

// stagedUpdate stages v2 as the agent does and installs it into slot B as the supervisor does.
func stagedUpdate(t *testing.T, d *device) time.Time {
	t.Helper()
	if err := RecordStaged(d.l, "2.0.0", strings.ToUpper(sha("agent v2"))); err != nil {
		t.Fatal(err)
	}
	d.write("/var/lib/paddock/staging/request.json", `{"version":"2.0.0"}`)
	d.quiet(1, Pass{})
	d.write(slotB, "agent v2")
	d.quiet(1, Pass{})
	d.write("/var/lib/paddock/state/probation.json", "{}")
	d.link("B", current)
	d.quiet(1, Pass{})
	// The supervisor removes the request before it writes the result.
	d.remove("/var/lib/paddock/staging/request.json")
	return time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)
}

func writeResult(t *testing.T, d *device, version, outcome string, at time.Time) {
	t.Helper()
	data, _ := json.Marshal(map[string]any{"version": version, "from_version": "1.0.0", "outcome": outcome, "at": at})
	d.write("/var/lib/paddock/state/update-result.json", string(data))
}

func TestRegularUpdateReportsNothing(t *testing.T) {
	d := newDevice(t)
	d.quiet(1, Pass{})
	at := stagedUpdate(t, d)
	d.remove("/var/lib/paddock/state/probation.json")
	// Between the request's removal and the result: the staged release is no change.
	d.quiet(1, Pass{})
	writeResult(t, d, "2.0.0", "updated", at)
	d.quiet(1, Pass{})
	if _, err := UpdateResult(d.l, "2.0.0", "updated"); err != nil {
		t.Fatal(err)
	}
	d.quiet(3, Pass{ReportedUpdateAt: &at})
	b := d.baseline()
	if b.Expected[slotB] != sha("agent v2") || b.Expected[current] != "B" || b.Staged != nil {
		t.Fatalf("baseline %v, staged %v", b.Expected, b.Staged)
	}
	// The moved baseline still reports a later change.
	d.link("A", current)
	d.changedOnce(current, Pass{ReportedUpdateAt: &at})
}

func TestRegularRollbacksReportNothing(t *testing.T) {
	for _, tc := range []struct {
		outcome string
		slot    string
	}{{"rolled_back", "A"}, {"rollback_failed", "B"}, {"self_test_failed", "A"}} {
		t.Run(tc.outcome, func(t *testing.T) {
			d := newDevice(t)
			d.quiet(1, Pass{})
			at := stagedUpdate(t, d)
			d.link(tc.slot, current)
			d.remove("/var/lib/paddock/state/probation.json")
			writeResult(t, d, "2.0.0", tc.outcome, at)
			d.quiet(1, Pass{})
			if _, err := UpdateResult(d.l, "2.0.0", tc.outcome); err != nil {
				t.Fatal(err)
			}
			d.quiet(3, Pass{ReportedUpdateAt: &at})
			if b := d.baseline(); b.Expected[current] != tc.slot {
				t.Fatalf("baseline current %q, want %s", b.Expected[current], tc.slot)
			}
		})
	}
	t.Run("signature_invalid", func(t *testing.T) {
		d := newDevice(t)
		d.quiet(1, Pass{})
		if err := RecordStaged(d.l, "2.0.0", sha("agent v2")); err != nil {
			t.Fatal(err)
		}
		at := time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)
		writeResult(t, d, "2.0.0", "signature_invalid", at)
		if _, err := UpdateResult(d.l, "2.0.0", "signature_invalid"); err != nil {
			t.Fatal(err)
		}
		d.quiet(3, Pass{ReportedUpdateAt: &at})
	})
}

// TestResultWithoutStagedKeepsBaseline (plan M5a R16): a result without a release this agent staged keeps the
// baseline and is returned as unstaged; the next pass reports what changed in the slots.
func TestResultWithoutStagedKeepsBaseline(t *testing.T) {
	d := newDevice(t)
	d.quiet(1, Pass{})
	if err := RecordStaged(d.l, "3.0.0", sha("another release")); err != nil {
		t.Fatal(err)
	}
	d.write(slotA, "agent other")
	d.link("B", current)
	at := time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)
	writeResult(t, d, "0.9.0", "signature_invalid", at)
	d.quiet(1, Pass{})
	unstaged, err := UpdateResult(d.l, "0.9.0", "signature_invalid")
	if err != nil || !unstaged {
		t.Fatalf("unstaged %v, error %v", unstaged, err)
	}
	if ev := d.pass(Pass{ReportedUpdateAt: &at}); !slices.Equal(ev, []string{slotA, current}) {
		t.Fatalf("reported %v", ev)
	}
	d.quiet(3, Pass{ReportedUpdateAt: &at})
	if b := d.baseline(); b.Expected[current] != "A" || b.Expected[slotA] != sha("agent v1") {
		t.Fatalf("baseline %v", b.Expected)
	}
}

// TestFailedUpdateKeepsCurrent (plan M5a R16): an outcome other than updated or rollback_failed takes the slot with the
// staged release, but current stays where it was; a switch to that slot is reported.
func TestFailedUpdateKeepsCurrent(t *testing.T) {
	for _, outcome := range []string{"self_test_failed", "rolled_back", "signature_invalid", "downgrade_refused"} {
		t.Run(outcome, func(t *testing.T) {
			d := newDevice(t)
			d.quiet(1, Pass{})
			at := stagedUpdate(t, d)
			d.remove("/var/lib/paddock/state/probation.json")
			writeResult(t, d, "2.0.0", outcome, at)
			unstaged, err := UpdateResult(d.l, "2.0.0", outcome)
			if err != nil || unstaged {
				t.Fatalf("unstaged %v, error %v", unstaged, err)
			}
			d.changedOnce(current, Pass{ReportedUpdateAt: &at})
			if b := d.baseline(); b.Expected[current] != "A" || b.Expected[slotB] != sha("agent v2") {
				t.Fatalf("baseline %v", b.Expected)
			}
		})
	}
}

// TestUpdateResultTakesOnlyTheStagedSlot (plan M5a R16): updated and rollback_failed move current only to a slot that
// holds the staged release.
func TestUpdateResultTakesOnlyTheStagedSlot(t *testing.T) {
	for _, outcome := range []string{"updated", "rollback_failed"} {
		t.Run(outcome, func(t *testing.T) {
			d := newDevice(t)
			d.quiet(1, Pass{})
			at := stagedUpdate(t, d)
			d.remove("/var/lib/paddock/state/probation.json")
			d.write(slotB, "agent other")
			writeResult(t, d, "2.0.0", outcome, at)
			if _, err := UpdateResult(d.l, "2.0.0", outcome); err != nil {
				t.Fatal(err)
			}
			if ev := d.pass(Pass{ReportedUpdateAt: &at}); !slices.Equal(ev, []string{slotB, current}) {
				t.Fatalf("reported %v", ev)
			}
			if b := d.baseline(); b.Expected[current] != "A" {
				t.Fatalf("baseline %v", b.Expected)
			}
		})
	}
}

func writeSupervisorResult(t *testing.T, d *device, outcome string, at time.Time) {
	t.Helper()
	data, _ := json.Marshal(map[string]any{"version": "2.0.0", "from_version": "1.0.0", "outcome": outcome, "at": at})
	d.write("/var/lib/paddock/state/supervisor-upgrade-result.json", string(data))
}

// upgradeSupervisor installs supervisor content as dpkg does: files and md5sums together.
func upgradeSupervisor(d *device, content string) {
	d.write("/usr/sbin/paddock-supervisor", content)
	d.write("/usr/lib/systemd/system/paddock-supervisor.service", content+" unit")
	d.writeSums(supervisorPackage, "/usr/sbin/paddock-supervisor", "/usr/lib/systemd/system/paddock-supervisor.service")
}

func TestRegularSupervisorUpgradeReportsNothing(t *testing.T) {
	d := newDevice(t)
	d.quiet(1, Pass{})
	d.write("/var/lib/paddock/state/supervisor-upgrade.json", "{}")
	d.write("/usr/sbin/paddock-supervisor", "v2 half written")
	d.quiet(1, Pass{})
	upgradeSupervisor(d, "v2")
	d.remove("/var/lib/paddock/state/supervisor-upgrade.json")
	at := time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)
	writeSupervisorResult(t, d, "updated", at)
	d.quiet(1, Pass{})
	d.quiet(3, Pass{ReportedSupervisorAt: &at})
}

func TestDpkgBusySkipsPackages(t *testing.T) {
	d := newDevice(t)
	d.quiet(1, Pass{})
	d.write("/usr/sbin/paddock-supervisor", "being unpacked")
	d.busy = true
	d.quiet(2, Pass{})
	d.busy = false
	d.sys.status[supervisorPackage] = "half-installed"
	d.quiet(2, Pass{})
	d.sys.status[supervisorPackage] = "installed"
	upgradeSupervisor(d, "v2")
	d.quiet(2, Pass{})
	// A lock held when the pass starts skips every package, even if dpkg released it meanwhile.
	d.write("/usr/sbin/paddock-supervisor", "being unpacked")
	calls := 0
	d.c.DpkgBusy = func() bool { calls++; return calls == 1 }
	d.quiet(1, Pass{})
}

func TestMD5SumsChangedDuringPass(t *testing.T) {
	d := newDevice(t)
	d.quiet(1, Pass{})
	d.write("/usr/sbin/paddock-supervisor", "v2")
	d.sys.onStatus = func(pkg string) {
		if pkg == supervisorPackage {
			d.writeSums(supervisorPackage, "/usr/sbin/paddock-supervisor", "/usr/lib/systemd/system/paddock-supervisor.service")
		}
	}
	d.quiet(1, Pass{})
	d.sys.onStatus = nil
	d.quiet(2, Pass{})
}

func TestSupervisorRollbackException(t *testing.T) {
	for _, outcome := range []string{"rolled_back", "rolled_back_unreachable", "install_failed"} {
		t.Run(outcome, func(t *testing.T) {
			d := newDevice(t)
			d.quiet(1, Pass{})
			old, _ := os.ReadFile(d.l.Join("/usr/sbin/paddock-supervisor"))
			oldUnit, _ := os.ReadFile(d.l.Join("/usr/lib/systemd/system/paddock-supervisor.service"))
			if err := RecordSupervisorPre(d.l, d.c.Arch, "2.0.0"); err != nil {
				t.Fatal(err)
			}
			d.write("/var/lib/paddock/state/supervisor-upgrade.json", "{}")
			upgradeSupervisor(d, "v2")
			// The helper copies the previous binary and unit back; md5sums keep the failed version.
			d.write("/usr/sbin/paddock-supervisor", string(old))
			d.write("/usr/lib/systemd/system/paddock-supervisor.service", string(oldUnit))
			d.remove("/var/lib/paddock/state/supervisor-upgrade.json")
			at := time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)
			writeSupervisorResult(t, d, outcome, at)
			d.quiet(1, Pass{})
			if err := SupervisorResult(d.l, d.c.Arch, "2.0.0", outcome); err != nil {
				t.Fatal(err)
			}
			p := Pass{ReportedSupervisorAt: &at}
			d.quiet(3, p)
			d.write("/usr/sbin/paddock-supervisor", "foreign")
			d.changedOnce("/usr/sbin/paddock-supervisor", p)
			d.write("/usr/sbin/paddock-supervisor", string(old))
			d.quiet(1, p)
			// A later regular upgrade replaces the exception.
			upgradeSupervisor(d, "v3")
			d.quiet(3, p)
			if b := d.baseline(); len(b.Exceptions) != 0 {
				t.Fatalf("exceptions %v after the upgrade", b.Exceptions)
			}
		})
	}
}

func TestOptionalPackagesNotInstalled(t *testing.T) {
	d := newDevice(t)
	for _, pkg := range []string{"fleet-osquery", "paddock-self-service"} {
		d.remove("/var/lib/dpkg/info/" + pkg + ".md5sums")
		delete(d.sys.status, pkg)
	}
	delete(d.sys.units, "orbit.service")
	d.remove("/etc/systemd/system/orbit.service.d/90-paddock.conf")
	d.quiet(3, Pass{})
	if n := d.logs.count(slog.LevelWarn) + d.logs.count(slog.LevelError); n != 0 {
		t.Fatalf("%d warnings or errors: %v", n, d.logs.lines)
	}
}

func TestMultiArchMD5Sums(t *testing.T) {
	d := newDevice(t)
	d.quiet(1, Pass{})
	if err := os.Rename(d.l.Join("/var/lib/dpkg/info/paddock-revoke.md5sums"),
		d.l.Join("/var/lib/dpkg/info/paddock-revoke:"+debianArch(d.c.Arch)+".md5sums")); err != nil {
		t.Fatal(err)
	}
	d.quiet(1, Pass{})
	d.write("/opt/paddock/revoke/paddock-revoke", "foreign")
	d.changedOnce("/opt/paddock/revoke/paddock-revoke", Pass{})
}

func TestCorruptBaseline(t *testing.T) {
	d := newDevice(t)
	d.quiet(1, Pass{})
	d.write("/var/lib/paddock/state/integrity.json", "{not json")
	d.write("/etc/paddock/agent.yml", "changed while the baseline was corrupt")
	d.logs.reset()
	d.changedOnce(reset, Pass{})
	if n := d.logs.count(slog.LevelWarn); n != 1 {
		t.Fatalf("%d warnings, want 1", n)
	}
	if _, err := os.Stat(d.l.Integrity() + ".corrupt"); err != nil {
		t.Fatal(err)
	}
}

func TestLockHeldSkipsThePass(t *testing.T) {
	d := newDevice(t)
	d.quiet(1, Pass{})
	f, err := os.OpenFile(d.l.IntegrityLock(), os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil { //nolint:gosec // a file descriptor fits an int
		t.Fatal(err)
	}
	waited := time.Duration(0)
	d.c.Sleep = func(dt time.Duration) { waited += dt }
	d.write(slotB, "foreign")
	d.logs.reset()
	d.quiet(1, Pass{})
	if waited != LockWait || d.logs.count(slog.LevelWarn) != 1 {
		t.Fatalf("waited %v with %d warnings, want %v and 1", waited, d.logs.count(slog.LevelWarn), LockWait)
	}
	_ = f.Close()
	d.changedOnce(slotB, Pass{})
}
