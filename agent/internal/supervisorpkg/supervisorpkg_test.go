package supervisorpkg

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/agent/internal/buildinfo"
	"github.com/phischl/paddock-mdm/agent/internal/fsutil"
	"github.com/phischl/paddock-mdm/agent/internal/paths"
	"github.com/phischl/paddock-mdm/agent/internal/reconcile/fakesys"
	"github.com/phischl/paddock-mdm/pkg/bundle"
	"github.com/phischl/paddock-mdm/pkg/protocol"
)

func ref(version string, deb []byte) bundle.PackageRef {
	sum := sha256.Sum256(deb)
	return bundle.PackageRef{Version: version, URLPath: "packages/" + version + "/paddock-supervisor_" + version + "_amd64.deb",
		SHA256: hex.EncodeToString(sum[:])}
}

// TestPlan (ADR 0037 decision 3): the package is installed only when the policy allows it, the agent runs the
// package's release, dpkg reports an older version, no upgrade runs and the version did not fail before.
func TestPlan(t *testing.T) {
	current := ref(buildinfo.Version, []byte("x"))
	bad := current
	bad.URLPath = "../etc/passwd"
	for _, tc := range []struct {
		name       string
		ref        bundle.PackageRef
		installed  string
		allows     bool
		failed     string
		inProgress bool
		backoff    bool
		install    bool
		reason     string
	}{
		{name: "older installed", ref: current, installed: "0.0.0~alpha.1", allows: true, install: true},
		{name: "older release", ref: current, installed: "0.0.0", allows: true, install: false, reason: ReasonCurrent},
		{name: "same version", ref: current, installed: buildinfo.Version, allows: true, reason: ReasonCurrent},
		{name: "same version in Debian form", ref: current, installed: strings.Replace(buildinfo.Version, "-", "~", 1), allows: true,
			reason: ReasonCurrent},
		{name: "newer installed", ref: current, installed: "9.0.0", allows: true, reason: ReasonCurrent},
		{name: "policy", ref: current, installed: "0.0.0~alpha.1", allows: false, reason: ReasonPolicy},
		{name: "agent on another release", ref: ref("9.9.9", []byte("x")), installed: "0.0.0~alpha.1", allows: true, reason: ReasonAgentVersion},
		{name: "failed before", ref: current, installed: "0.0.0~alpha.1", allows: true, failed: buildinfo.Version, reason: ReasonFailed},
		{name: "waiting for its retry", ref: current, installed: "0.0.0~alpha.1", allows: true, backoff: true, reason: ReasonBackoff},
		{name: "in progress", ref: current, installed: "0.0.0~alpha.1", allows: true, inProgress: true, reason: ReasonInProgress},
		{name: "not installed by its package", ref: current, installed: "", allows: true, reason: ReasonNotInstalled},
		{name: "invalid reference", ref: bad, installed: "0.0.0~alpha.1", allows: true, reason: ReasonInvalid},
	} {
		t.Run(tc.name, func(t *testing.T) {
			install, reason := Plan(tc.ref, tc.installed, tc.allows, tc.failed, tc.inProgress, tc.backoff)
			if install != tc.install || reason != tc.reason {
				t.Fatalf("Plan = %v %q, want %v %q", install, reason, tc.install, tc.reason)
			}
		})
	}
}

func TestStage(t *testing.T) {
	l := paths.Layout{Root: t.TempDir()}
	deb := []byte("supervisor package")
	r := ref("1.2.0", deb)
	var asked string
	download := func(_ context.Context, url string, limit int64) ([]byte, error) {
		asked = url
		if limit != MaxPackage {
			t.Errorf("limit %d", limit)
		}
		return deb, nil
	}
	file, err := Stage(context.Background(), download, l, "https://bundles.example.test/"+r.URLPath, r)
	if err != nil || asked != "https://bundles.example.test/"+r.URLPath {
		t.Fatalf("Stage: %v (asked %s)", err, asked)
	}
	if want := filepath.Join(l.Packages(), "paddock-supervisor_1.2.0_"+runtime.GOARCH+".deb"); file != want {
		t.Fatalf("staged at %s, want %s", file, want)
	}
	if got, _ := os.ReadFile(file); string(got) != string(deb) {
		t.Fatalf("staged %q", got)
	}
	r.SHA256 = strings.Repeat("0", 64)
	if _, err := Stage(context.Background(), download, l, "u", r); err == nil || !strings.Contains(err.Error(), "SHA-256") {
		t.Fatalf("a package with another SHA-256 was staged: %v", err)
	}
	failing := func(context.Context, string, int64) ([]byte, error) { return nil, errors.New("offline") }
	if _, err := Stage(context.Background(), failing, l, "u", ref("1.2.0", deb)); err == nil {
		t.Fatal("a failed download was staged")
	}
}

func TestLaunch(t *testing.T) {
	l := paths.Layout{Root: t.TempDir()}
	var got []string
	run := func(_ context.Context, name string, args ...string) error {
		got = append([]string{name}, args...)
		return nil
	}
	if err := Launch(context.Background(), run, l, "/var/lib/paddock/packages/x.deb", "1.2.0", "1.1.0"); err != nil {
		t.Fatal(err)
	}
	want := []string{"systemd-run", "--unit=paddock-supervisor-upgrade", "--collect", "--no-block", "--property=KillMode=process",
		filepath.Join(l.Slots(), "current", "paddockd"), "supervisor-upgrade", "--deb", "/var/lib/paddock/packages/x.deb", "--from", "1.1.0"}
	if !slices.Equal(got, want) {
		t.Fatalf("ran %v\nwant %v", got, want)
	}
	m, err := ReadMarker(l)
	if err != nil || m == nil || m.Version != "1.2.0" || m.FromVersion != "1.1.0" || m.StartedAt.IsZero() {
		t.Fatalf("marker %+v, %v", m, err)
	}
	failing := func(context.Context, string, ...string) error { return errors.New("no systemd-run") }
	if err := Launch(context.Background(), failing, l, "x.deb", "1.3.0", "1.1.0"); err == nil {
		t.Fatal("a failed launch returned no error")
	}
	if m, _ := ReadMarker(l); m != nil {
		t.Fatalf("the marker of a failed launch stays: %+v", m)
	}
}

// upgradeWorld is a fake device with an installed supervisor, a staged package and a clock that the fake sleep
// advances; checkin, when set, is called after every sleep to play the device's agent and supervisor.
type upgradeWorld struct {
	sys     *fakesys.System
	l       paths.Layout
	now     time.Time
	deb     string
	checkin func(w *upgradeWorld)
}

func newUpgradeWorld(t *testing.T) *upgradeWorld {
	w := &upgradeWorld{sys: fakesys.New(), l: paths.Layout{Root: t.TempDir()}, now: time.Date(2026, 10, 18, 9, 0, 0, 0, time.UTC)}
	w.sys.Files[Binary] = &fakesys.File{Data: []byte("old supervisor"), Mode: 0o755}
	w.sys.Files[UnitFile] = &fakesys.File{Data: []byte("old unit"), Mode: 0o644}
	w.sys.Units[Service] = &fakesys.Unit{State: "enabled", Active: true}
	w.sys.Shows[Service] = "MainPID=100\nActiveState=active\n"
	w.deb = filepath.Join(w.l.Packages(), "paddock-supervisor_1.2.0_amd64.deb")
	w.sys.Files[w.deb] = &fakesys.File{Data: []byte("package"), Mode: 0o600}
	if err := fsutil.WriteFile(w.deb, []byte("package"), 0o600, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := writeJSON(w.l.SupervisorUpgrade(), Marker{Version: "1.2.0", FromVersion: "1.1.0", StartedAt: w.now}); err != nil {
		t.Fatal(err)
	}
	return w
}

func (w *upgradeWorld) upgrader() *Upgrader {
	return &Upgrader{Sys: w.sys, Layout: w.l, Now: func() time.Time { return w.now },
		Sleep: func(context.Context, time.Duration) error {
			w.now = w.now.Add(10 * time.Second)
			if w.checkin != nil {
				w.checkin(w)
			}
			return nil
		}, Poll: 10 * time.Second, Wait: CheckinWait, Hold: Stable}
}

func (w *upgradeWorld) checkedIn(t time.Time) {
	_ = fsutil.WriteFile(w.l.LastCheckin(), []byte(t.Format(time.RFC3339Nano)+"\n"), 0o644, 0o755)
}

func (w *upgradeWorld) result(t *testing.T, outcome string) {
	t.Helper()
	r, err := ReadResult(w.l)
	if err != nil || r == nil || r.Version != "1.2.0" || r.FromVersion != "1.1.0" || r.Outcome != outcome || !r.At.Equal(w.now) {
		t.Fatalf("result %+v, %v; want %s at %s", r, err, outcome, w.now)
	}
	if m, _ := ReadMarker(w.l); m != nil {
		t.Fatalf("marker %+v left", m)
	}
	if _, err := os.Stat(w.deb); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("staged package left: %v", err)
	}
	for _, f := range []string{"paddock-supervisor", Service} {
		if w.sys.Files[filepath.Join(BackupDir, f)] == nil {
			t.Fatalf("no backup of %s", f)
		}
	}
}

// TestUpgradeUpdated: the agent checks in after dpkg and the supervisor keeps its PID for a minute → updated, nothing
// restored.
func TestUpgradeUpdated(t *testing.T) {
	w := newUpgradeWorld(t)
	w.checkedIn(w.now.Add(-time.Minute)) // the old agent's check-in does not count
	w.checkin = func(w *upgradeWorld) {
		w.sys.Shows[Service] = "MainPID=200\nActiveState=active\n"
		w.checkedIn(w.now)
	}
	r := w.upgrader().Run(context.Background(), w.deb, "1.1.0")
	if r.Outcome != protocol.SupervisorOutcomeUpdated {
		t.Fatalf("outcome %s", r.Outcome)
	}
	w.result(t, protocol.SupervisorOutcomeUpdated)
	if w.sys.Versions[Package] != "1.2.0" || slices.Contains(w.sys.Calls, "systemctl restart "+Service) {
		t.Fatalf("installed %q, calls %v", w.sys.Versions[Package], w.sys.Calls)
	}
}

// TestUpgradeRolledBack: without a check-in within 10 minutes the backup is restored, systemd reloaded and the
// supervisor restarted.
func TestUpgradeRolledBack(t *testing.T) {
	w := newUpgradeWorld(t)
	start := w.now
	w.checkin = func(w *upgradeWorld) {
		w.sys.Files[Binary] = &fakesys.File{Data: []byte("new supervisor"), Mode: 0o755}
	}
	r := w.upgrader().Run(context.Background(), w.deb, "1.1.0")
	if r.Outcome != protocol.SupervisorOutcomeRolledBack || w.now.Sub(start) < CheckinWait {
		t.Fatalf("outcome %s after %s", r.Outcome, w.now.Sub(start))
	}
	w.result(t, protocol.SupervisorOutcomeRolledBack)
	if string(w.sys.Files[Binary].Data) != "old supervisor" || w.sys.Files[Binary].Mode != 0o755 {
		t.Fatalf("binary not restored: %q", w.sys.Files[Binary].Data)
	}
	calls := w.sys.TakeCalls()
	if i := slices.Index(calls, "systemctl daemon-reload"); i < 0 || !slices.Contains(calls[i:], "systemctl restart "+Service) {
		t.Fatalf("calls %v, want daemon-reload then restart", calls)
	}
}

// TestUpgradeRolledBackUnreachable (design contract 8): the new supervisor runs stable, but the agent's check-ins
// fail to reach the server → the backup is restored and the outcome rolled_back_unreachable lets the agent retry; a
// failed check-in before the installation does not count.
func TestUpgradeRolledBackUnreachable(t *testing.T) {
	w := newUpgradeWorld(t)
	mark := func(at time.Time) {
		_ = fsutil.WriteFile(w.l.LastCheckinFailed(), []byte(at.Format(time.RFC3339Nano)+"\n"), 0o644, 0o755)
	}
	mark(w.now.Add(-time.Minute))
	if r := w.upgrader().Run(context.Background(), w.deb, "1.1.0"); r.Outcome != protocol.SupervisorOutcomeRolledBack {
		t.Fatalf("an old failed check-in: outcome %s", r.Outcome)
	}

	w = newUpgradeWorld(t)
	w.checkin = func(w *upgradeWorld) {
		w.sys.Shows[Service] = "MainPID=200\nActiveState=active\n"
		mark(w.now)
	}
	r := w.upgrader().Run(context.Background(), w.deb, "1.1.0")
	if r.Outcome != protocol.SupervisorOutcomeRolledBackUnreachable {
		t.Fatalf("outcome %s", r.Outcome)
	}
	w.result(t, protocol.SupervisorOutcomeRolledBackUnreachable)
	if string(w.sys.Files[Binary].Data) != "old supervisor" || !slices.Contains(w.sys.TakeCalls(), "systemctl restart "+Service) {
		t.Fatal("the previous supervisor was not restored")
	}

	// A supervisor that does not stay up while check-ins fail is a local failure.
	w = newUpgradeWorld(t)
	pid := 200
	w.checkin = func(w *upgradeWorld) {
		pid++
		w.sys.Shows[Service] = "MainPID=" + strings.Repeat("1", pid%3+1) + "\nActiveState=active\n"
		mark(w.now)
	}
	if r := w.upgrader().Run(context.Background(), w.deb, "1.1.0"); r.Outcome != protocol.SupervisorOutcomeRolledBack {
		t.Fatalf("unstable supervisor: outcome %s", r.Outcome)
	}
}

// TestUpgradeUnstableSupervisor: a supervisor that keeps restarting (a new PID at every poll) while its agent checks
// in is rolled back.
func TestUpgradeUnstableSupervisor(t *testing.T) {
	w := newUpgradeWorld(t)
	pid := 200
	w.checkin = func(w *upgradeWorld) {
		pid++
		w.sys.Shows[Service] = "MainPID=" + strings.Repeat("1", pid%3+1) + "\nActiveState=active\n"
		w.checkedIn(w.now)
	}
	if r := w.upgrader().Run(context.Background(), w.deb, "1.1.0"); r.Outcome != protocol.SupervisorOutcomeRolledBack {
		t.Fatalf("outcome %s", r.Outcome)
	}
}

// TestUpgradeInstallFailed: a dpkg error is install_failed; the backup is not restored while the supervisor is active.
func TestUpgradeInstallFailed(t *testing.T) {
	w := newUpgradeWorld(t)
	w.sys.FailCmd = "dpkg -i " + w.deb
	if r := w.upgrader().Run(context.Background(), w.deb, "1.1.0"); r.Outcome != protocol.SupervisorOutcomeInstallFailed {
		t.Fatalf("outcome %s", r.Outcome)
	}
	w.result(t, protocol.SupervisorOutcomeInstallFailed)
	if slices.Contains(w.sys.Calls, "systemctl restart "+Service) {
		t.Fatalf("restarted an active supervisor: %v", w.sys.Calls)
	}

	w = newUpgradeWorld(t)
	w.sys.DpkgTimeout = true
	w.sys.Shows[Service] = "MainPID=0\nActiveState=failed\n"
	if r := w.upgrader().Run(context.Background(), w.deb, "1.1.0"); r.Outcome != protocol.SupervisorOutcomeInstallFailed {
		t.Fatalf("outcome %s", r.Outcome)
	}
	if !slices.Contains(w.sys.Calls, "systemctl restart "+Service) {
		t.Fatalf("a supervisor left inactive by dpkg was not restored: %v", w.sys.Calls)
	}
}

// TestUpgradeWithoutBackup: when the supervisor cannot be copied, dpkg is never run.
func TestUpgradeWithoutBackup(t *testing.T) {
	w := newUpgradeWorld(t)
	delete(w.sys.Files, Binary)
	if r := w.upgrader().Run(context.Background(), w.deb, "1.1.0"); r.Outcome != protocol.SupervisorOutcomeInstallFailed {
		t.Fatalf("outcome %s", r.Outcome)
	}
	for _, c := range w.sys.Calls {
		if strings.HasPrefix(c, "dpkg") {
			t.Fatalf("dpkg ran without a backup: %v", w.sys.Calls)
		}
	}
}

func TestVersionOf(t *testing.T) {
	if v, err := VersionOf("/var/lib/paddock/packages/paddock-supervisor_0.1.0-alpha.4_amd64.deb"); err != nil || v != "0.1.0-alpha.4" {
		t.Fatalf("VersionOf = %q, %v", v, err)
	}
	if _, err := VersionOf("/tmp/paddock-agent_1.0.0_amd64.deb"); err == nil {
		t.Fatal("another package accepted")
	}
}

// TestUpgradeDeferredWhenLocked: plan M8e amendment 2026-10-21, item 16 — dpkg refusing the install for a lock another
// package run holds (apt, the in-place encryption's initrd work) defers the upgrade: no install_failed.
func TestUpgradeDeferredWhenLocked(t *testing.T) {
	w := newUpgradeWorld(t)
	w.sys.DpkgLocked = true
	if r := w.upgrader().Run(context.Background(), w.deb, "1.1.0"); r.Outcome != OutcomeDeferred {
		t.Fatalf("outcome %s", r.Outcome)
	}
	w.result(t, OutcomeDeferred)
}
