package agent

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/agent/internal/fsutil"
	"github.com/phischl/paddock-mdm/agent/internal/state"
	"github.com/phischl/paddock-mdm/agent/internal/supervisorpkg"
	"github.com/phischl/paddock-mdm/agent/internal/testgw"
	"github.com/phischl/paddock-mdm/agent/internal/uninstall"
	"github.com/phischl/paddock-mdm/pkg/command"
	"github.com/phischl/paddock-mdm/pkg/protocol"
)

func uninstallAgent(t *testing.T) (*Agent, *[][]string) {
	t.Helper()
	a, launched, _ := uninstallAgentGW(t)
	return a, launched
}

func uninstallAgentGW(t *testing.T) (*Agent, *[][]string, *testgw.Gateway) {
	t.Helper()
	g := testgw.New(t)
	a := newAgent(t, g)
	self := filepath.Join(t.TempDir(), "paddockd")
	if err := os.WriteFile(self, []byte("agent binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	a.d.Executable = self
	a.d.NoExec = func(string) (bool, error) { return false, nil }
	launched := &[][]string{}
	a.d.RunUnit = func(_ context.Context, name string, args ...string) error {
		*launched = append(*launched, append([]string{name}, args...))
		return nil
	}
	return a, launched, g
}

func uninstallCmd(params string) *command.Command {
	return &command.Command{CommandID: "c-un", Type: command.TypeUninstall, Params: json.RawMessage(params),
		IssuedAt: time.Date(2026, 10, 18, 9, 0, 0, 0, time.UTC)}
}

// TestUninstallAccepted (plan M8d decision 39): the plan (0600) and the binary copy (0700) are written, the removal
// is pending, and it starts once — only after its result left the results the server has not accepted.
func TestUninstallAccepted(t *testing.T) {
	a, launched := uninstallAgent(t)
	a.st.EventSeq = 41
	status, result := a.uninstallCommand(context.Background(), uninstallCmd(`{"mode":"reset","clear_tpm":true}`))
	if status != protocol.CommandSucceeded || result["accepted"] != true {
		t.Fatalf("result %s %v", status, result)
	}
	plan, err := uninstall.ReadPlan(a.d.Layout.UninstallPlan())
	if err != nil || plan.CommandID != "c-un" || plan.Mode != "reset" || !plan.ClearTPM || plan.KeepLocalAdmin ||
		plan.DeviceID != a.st.DeviceID || plan.EventSeqBase != 41 || plan.RequestedAt.IsZero() {
		t.Fatalf("plan %+v, %v", plan, err)
	}
	for file, mode := range map[string]os.FileMode{a.d.Layout.UninstallPlan(): 0o600, a.d.Layout.UninstallBinary(): 0o700} {
		if info, err := os.Stat(file); err != nil || info.Mode().Perm() != mode {
			t.Fatalf("%s: %v %v", file, info, err)
		}
	}
	if bin, _ := os.ReadFile(a.d.Layout.UninstallBinary()); string(bin) != "agent binary" {
		t.Fatalf("binary copy %q", bin)
	}
	if st, _ := state.Load(a.d.Layout.State()); st.PendingUninstall == nil || st.PendingUninstall.CommandID != "c-un" {
		t.Fatalf("pending mark not persisted: %+v", st.PendingUninstall)
	}
	a.st.CommandResults = []state.CommandResult{{CommandID: "c-un", Status: protocol.CommandSucceeded}}
	a.launchUninstall(context.Background())
	if len(*launched) != 0 {
		t.Fatalf("started before the result was accepted: %v", *launched)
	}
	a.postResults(context.Background())
	if a.st.PendingUninstall == nil || !a.st.PendingUninstall.Reported {
		t.Fatalf("accepted result not marked: %+v", a.st.PendingUninstall)
	}
	a.launchUninstall(context.Background())
	a.launchUninstall(context.Background())
	want := []string{"systemd-run", "--unit=paddock-uninstall", "--collect", "--no-block", "--property=KillMode=process",
		a.d.Layout.UninstallBinary(), "uninstall", "--plan", a.d.Layout.UninstallPlan()}
	if len(*launched) != 1 || !slices.Equal((*launched)[0], want) || a.st.PendingUninstall.LaunchedAt == nil {
		t.Fatalf("launched %v", *launched)
	}
}

// TestUninstallRefused: unknown params and reset-only options with leave are invalid_params; a revocation handed
// within 24 hours refuses with revocation_pending; nothing is prepared then.
func TestUninstallRefused(t *testing.T) {
	a, _ := uninstallAgent(t)
	for _, params := range []string{`{"mode":"wipe"}`, `{"mode":"leave","clear_tpm":true}`, `{"mode":"leave","keep_local_admin":true}`,
		`{"mode":"leave","extra":1}`, `{}`} {
		if status, result := a.uninstallCommand(context.Background(), uninstallCmd(params)); status != protocol.CommandFailed ||
			result["reason"] != "invalid_params" {
			t.Fatalf("%s: %s %v", params, status, result)
		}
	}
	a.st.HandedRevocations = map[string]time.Time{"h": a.d.Now().Add(-23 * time.Hour)}
	if status, result := a.uninstallCommand(context.Background(), uninstallCmd(`{"mode":"leave"}`)); status != protocol.CommandFailed ||
		result["reason"] != "revocation_pending" {
		t.Fatalf("revocation pending: %s %v", status, result)
	}
	if _, err := os.Stat(a.d.Layout.UninstallPlan()); !errors.Is(err, os.ErrNotExist) || a.st.PendingUninstall != nil {
		t.Fatalf("prepared a refused uninstall: %v %+v", err, a.st.PendingUninstall)
	}
	a.st.HandedRevocations = map[string]time.Time{"h": a.d.Now().Add(-25 * time.Hour)}
	if status, _ := a.uninstallCommand(context.Background(), uninstallCmd(`{"mode":"leave"}`)); status != protocol.CommandSucceeded {
		t.Fatalf("an old revocation still refuses: %s", status)
	}
}

// TestUninstallRelaunchAdoptsRunningRemoval (review 2 finding E): after a crash between systemd-run and saving
// LaunchedAt, the relaunch fails because paddock-uninstall.service is still running; the agent adopts the running
// removal instead of reporting helper_failed.
func TestUninstallRelaunchAdoptsRunningRemoval(t *testing.T) {
	a, _ := uninstallAgent(t)
	var calls []string
	a.d.RunUnit = func(_ context.Context, name string, args ...string) error {
		calls = append(calls, name+" "+strings.Join(args, " "))
		if name == "systemd-run" {
			return errors.New("Unit paddock-uninstall.service was already loaded or has a fragment file.")
		}
		return nil
	}
	if status, _ := a.uninstallCommand(context.Background(), uninstallCmd(`{"mode":"leave"}`)); status != protocol.CommandSucceeded {
		t.Fatal(status)
	}
	a.st.PendingUninstall.Reported = true
	a.launchUninstall(context.Background())
	if a.st.PendingUninstall == nil || a.st.PendingUninstall.LaunchedAt == nil {
		t.Fatalf("pending uninstall %+v, want launched", a.st.PendingUninstall)
	}
	if pending, err := a.d.Spool.Pending(); err != nil || len(pending) != 0 {
		t.Fatalf("spool %+v, %v; want no helper_failed", pending, err)
	}
	if len(calls) != 2 || calls[1] != "systemctl is-active --quiet paddock-uninstall.service" {
		t.Fatalf("calls %q", calls)
	}
}

// TestUninstallHelperFailed: a failed systemd-run is reported as agent.uninstalled with outcome helper_failed and
// the pending mark is cleared.
func TestUninstallHelperFailed(t *testing.T) {
	a, _ := uninstallAgent(t)
	a.d.RunUnit = func(context.Context, string, ...string) error { return errors.New("no systemd-run") }
	if status, _ := a.uninstallCommand(context.Background(), uninstallCmd(`{"mode":"leave"}`)); status != protocol.CommandSucceeded {
		t.Fatal(status)
	}
	a.st.PendingUninstall.Reported = true
	a.launchUninstall(context.Background())
	pending, err := a.d.Spool.Pending()
	if err != nil || len(pending) != 1 || pending[0].Type != protocol.EventAgentUninstalled {
		t.Fatalf("spool %+v, %v", pending, err)
	}
	var data protocol.AgentUninstalled
	if err := json.Unmarshal(pending[0].Data, &data); err != nil || data.Outcome != protocol.UninstallHelperFailed || data.CommandID != "c-un" ||
		data.Mode != "leave" {
		t.Fatalf("event %+v, %v", data, err)
	}
	if a.st.PendingUninstall != nil {
		t.Fatalf("pending mark kept: %+v", a.st.PendingUninstall)
	}
	for _, f := range []string{a.d.Layout.UninstallPlan(), a.d.Layout.UninstallBinary(), filepath.Dir(a.d.Layout.UninstallPlan())} {
		if _, err := os.Stat(f); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s kept after helper_failed: %v", f, err)
		}
	}
}

// TestUninstallHelperDirNoexec (ADR 0037 amendment 2026-10-19): when the helper's directory is on a file system
// mounted noexec, or its mount options cannot be read, systemd-run is not called; the removal is reported as
// helper_failed and its preparation removed.
func TestUninstallHelperDirNoexec(t *testing.T) {
	for name, noexec := range map[string]func(string) (bool, error){
		"noexec":     func(string) (bool, error) { return true, nil },
		"statfs err": func(string) (bool, error) { return false, errors.New("statfs: permission denied") },
	} {
		t.Run(name, func(t *testing.T) {
			a, launched := uninstallAgent(t)
			var checked string
			a.d.NoExec = func(dir string) (bool, error) { checked = dir; return noexec(dir) }
			if status, _ := a.uninstallCommand(context.Background(), uninstallCmd(`{"mode":"leave"}`)); status != protocol.CommandSucceeded {
				t.Fatal(status)
			}
			a.st.PendingUninstall.Reported = true
			a.launchUninstall(context.Background())
			if checked != filepath.Dir(a.d.Layout.UninstallBinary()) {
				t.Fatalf("checked %q, want the helper's directory", checked)
			}
			if len(*launched) != 0 {
				t.Fatalf("systemd-run called: %v", *launched)
			}
			pending, err := a.d.Spool.Pending()
			if err != nil || len(pending) != 1 || pending[0].Type != protocol.EventAgentUninstalled {
				t.Fatalf("spool %+v, %v", pending, err)
			}
			var data protocol.AgentUninstalled
			if err := json.Unmarshal(pending[0].Data, &data); err != nil || data.Outcome != protocol.UninstallHelperFailed {
				t.Fatalf("event %+v, %v", data, err)
			}
			if a.st.PendingUninstall != nil {
				t.Fatalf("pending mark kept: %+v", a.st.PendingUninstall)
			}
			if _, err := os.Stat(a.d.Layout.UninstallBinary()); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("binary copy kept: %v", err)
			}
		})
	}
}

// TestNoexecStatfs: the statfs check reads the mount options of an existing directory.
func TestNoexecStatfs(t *testing.T) {
	if _, err := noexec(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	if _, err := noexec(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("no error for a missing directory")
	}
}

// TestNoexecStatfsFlag: the statfs check reports the noexec option as the mount table of this process lists it, for a
// mount with the option and for one without; ST_NOEXEC is defined by hand, so a wrong value fails here.
func TestNoexecStatfsFlag(t *testing.T) {
	raw, err := os.ReadFile("/proc/self/mounts")
	if err != nil {
		t.Skipf("no mount table: %v", err)
	}
	// A later line for the same mount point is mounted over the earlier one and is the one statfs sees.
	options := map[string]string{}
	for line := range strings.Lines(string(raw)) {
		if fields := strings.Fields(line); len(fields) >= 4 && !strings.ContainsRune(fields[1], '\\') {
			options[fields[1]] = fields[3]
		}
	}
	seen := map[bool]bool{}
	for dir, opts := range options {
		want := slices.Contains(strings.Split(opts, ","), "noexec")
		got, err := noexec(dir)
		if err != nil {
			continue
		}
		if got != want {
			t.Fatalf("noexec(%s) = %v, mount options %s", dir, got, opts)
		}
		seen[want] = true
	}
	if !seen[true] || !seen[false] {
		t.Skipf("mount table lacks a readable mount with or without noexec: %v", seen)
	}
}

// TestUninstallRefusedResultWithdraws (review finding 1): a result the server refuses (cancelled: 409, removed from
// cmd: 404) never starts the removal; the mark, the plan and the binary copy are removed.
func TestUninstallRefusedResultWithdraws(t *testing.T) {
	for _, status := range []int{http.StatusConflict, http.StatusNotFound} {
		a, launched, g := uninstallAgentGW(t)
		if s, _ := a.uninstallCommand(context.Background(), uninstallCmd(`{"mode":"leave"}`)); s != protocol.CommandSucceeded {
			t.Fatal(s)
		}
		a.st.CommandResults = []state.CommandResult{{CommandID: "c-un", Status: protocol.CommandSucceeded}}
		g.ResultFail = status
		a.postResults(context.Background())
		a.launchUninstall(context.Background())
		if len(*launched) != 0 || a.st.PendingUninstall != nil || len(a.st.CommandResults) != 0 {
			t.Fatalf("%d: launched %v, pending %+v", status, *launched, a.st.PendingUninstall)
		}
		for _, f := range []string{a.d.Layout.UninstallPlan(), a.d.Layout.UninstallBinary(), filepath.Dir(a.d.Layout.UninstallPlan())} {
			if _, err := os.Stat(f); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("%d: %s kept: %v", status, f, err)
			}
		}
	}
}

// TestUninstallLaunchedAtAfterStart (review finding 8): a failing start leaves no LaunchedAt behind before the
// helper_failed report, and a successful start sets it only afterwards.
func TestUninstallLaunchedAtAfterStart(t *testing.T) {
	a, _ := uninstallAgent(t)
	var seen *time.Time
	a.d.RunUnit = func(context.Context, string, ...string) error {
		if st, _ := state.Load(a.d.Layout.State()); st.PendingUninstall != nil {
			seen = st.PendingUninstall.LaunchedAt
		}
		return nil
	}
	a.uninstallCommand(context.Background(), uninstallCmd(`{"mode":"leave"}`))
	a.st.PendingUninstall.Reported = true
	a.saveState()
	a.launchUninstall(context.Background())
	if seen != nil || a.st.PendingUninstall.LaunchedAt == nil {
		t.Fatalf("LaunchedAt saved before the start (%v) or not after it (%v)", seen, a.st.PendingUninstall.LaunchedAt)
	}
}

// TestUninstallInterruptedLaunchRetries: a start interrupted because the agent is being stopped (a supervisor restart
// cancels its context) is no helper failure: the request stays pending and the next start launches the removal.
func TestUninstallInterruptedLaunchRetries(t *testing.T) {
	a, launched := uninstallAgent(t)
	if status, _ := a.uninstallCommand(context.Background(), uninstallCmd(`{"mode":"leave"}`)); status != protocol.CommandSucceeded {
		t.Fatal(status)
	}
	a.st.PendingUninstall.Reported = true
	run := a.d.RunUnit
	a.d.RunUnit = func(ctx context.Context, _ string, _ ...string) error { return ctx.Err() }
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	a.launchUninstall(ctx)
	if pending, err := a.d.Spool.Pending(); err != nil || len(pending) != 0 {
		t.Fatalf("spool %+v, %v; want no helper_failed", pending, err)
	}
	if a.st.PendingUninstall == nil || a.st.PendingUninstall.LaunchedAt != nil {
		t.Fatalf("pending uninstall %+v, want pending and not launched", a.st.PendingUninstall)
	}
	a.d.RunUnit = run
	a.launchUninstall(context.Background())
	if len(*launched) != 1 || a.st.PendingUninstall.LaunchedAt == nil {
		t.Fatalf("launched %v after the restart", *launched)
	}
}

// TestUninstallWaitsForSupervisorUpgrade: while a supervisor upgrade runs (its marker exists) the removal does not
// start, since the upgrade's rollback would restore the supervisor the removal purges; it starts once the upgrade
// wrote its result.
func TestUninstallWaitsForSupervisorUpgrade(t *testing.T) {
	a, launched := uninstallAgent(t)
	// The upgrade runs: its marker is younger than supervisorpkg.StaleAfter, after which it no longer holds (PDK-479).
	a.d.Now = func() time.Time { return time.Date(2026, 10, 18, 9, 5, 0, 0, time.UTC) }
	marker := `{"version":"1.2.0","from_version":"1.1.0","started_at":"2026-10-18T09:00:00Z"}`
	if err := fsutil.WriteFile(a.d.Layout.SupervisorUpgrade(), []byte(marker), 0o600, 0o700); err != nil {
		t.Fatal(err)
	}
	if status, _ := a.uninstallCommand(context.Background(), uninstallCmd(`{"mode":"leave"}`)); status != protocol.CommandSucceeded {
		t.Fatal(status)
	}
	a.st.PendingUninstall.Reported = true
	a.launchUninstall(context.Background())
	if len(*launched) != 0 || a.st.PendingUninstall.LaunchedAt != nil {
		t.Fatalf("started during the supervisor upgrade: %v", *launched)
	}
	if err := supervisorpkg.WriteResult(a.d.Layout, supervisorpkg.Result{Version: "1.2.0", FromVersion: "1.1.0",
		Outcome: protocol.SupervisorOutcomeRolledBack, At: a.d.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	a.launchUninstall(context.Background())
	if len(*launched) != 1 || a.st.PendingUninstall.LaunchedAt == nil {
		t.Fatalf("launched %v after the upgrade finished", *launched)
	}
}

// TestUninstallUnreadableSupervisorMarker: an unreadable supervisor-upgrade marker holds back the removal only until
// it is older than supervisorpkg.StaleAfter, so the removal never waits for it forever.
func TestUninstallUnreadableSupervisorMarker(t *testing.T) {
	for _, tc := range []struct {
		name   string
		age    time.Duration
		starts bool
	}{
		{"younger than StaleAfter", supervisorpkg.StaleAfter - time.Minute, false},
		{"older than StaleAfter", supervisorpkg.StaleAfter + time.Minute, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, launched := uninstallAgent(t)
			marker := a.d.Layout.SupervisorUpgrade()
			if err := fsutil.WriteFile(marker, []byte("{not json"), 0o600, 0o700); err != nil {
				t.Fatal(err)
			}
			mtime := a.d.Now().Add(-tc.age)
			if err := os.Chtimes(marker, mtime, mtime); err != nil {
				t.Fatal(err)
			}
			if status, _ := a.uninstallCommand(context.Background(), uninstallCmd(`{"mode":"leave"}`)); status != protocol.CommandSucceeded {
				t.Fatal(status)
			}
			a.st.PendingUninstall.Reported = true
			a.launchUninstall(context.Background())
			if started := len(*launched) == 1 && a.st.PendingUninstall.LaunchedAt != nil; started != tc.starts {
				t.Fatalf("started %v, want %v: %v", started, tc.starts, *launched)
			}
		})
	}
}
