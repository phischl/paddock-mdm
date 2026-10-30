package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"runtime"
	"slices"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/agent/internal/buildinfo"
	"github.com/phischl/paddock-mdm/agent/internal/fsutil"
	"github.com/phischl/paddock-mdm/agent/internal/reconcile/fakesys"
	"github.com/phischl/paddock-mdm/agent/internal/state"
	"github.com/phischl/paddock-mdm/agent/internal/supervisorpkg"
	"github.com/phischl/paddock-mdm/agent/internal/testgw"
	"github.com/phischl/paddock-mdm/agent/internal/update"
	"github.com/phischl/paddock-mdm/pkg/bundle"
	"github.com/phischl/paddock-mdm/pkg/protocol"
)

// supervisorAgent is an agent whose applied bundle carries the supervisor package of its own release, on a device
// with an older paddock-supervisor package; launched collects the systemd-run calls.
func supervisorAgent(t *testing.T, policy string) (*Agent, *testgw.Gateway, *[][]string) {
	t.Helper()
	g := testgw.New(t)
	a := newAgent(t, g)
	deb := []byte("supervisor package")
	sum := sha256.Sum256(deb)
	ref := bundle.PackageRef{Version: buildinfo.Version, SHA256: hex.EncodeToString(sum[:]),
		URLPath: "packages/" + buildinfo.Version + "/paddock-supervisor_" + buildinfo.Version + "_amd64.deb"}
	a.current = &bundle.Bundle{Agent: bundle.AgentCfg{UpdatePolicy: policy, SupervisorPackages: map[string]bundle.PackageRef{runtime.GOARCH: ref}}}
	sys := fakesys.New()
	sys.Packages[supervisorpkg.Package], sys.Versions[supervisorpkg.Package] = true, "0.0.0~alpha.1"
	a.d.Sys = sys
	a.d.Config.ServerURL = "https://device.example.test"
	a.d.Download = func(_ context.Context, url string, _ int64) ([]byte, error) {
		if url != "https://bundles.example.test/"+ref.URLPath {
			t.Errorf("downloaded %s", url)
		}
		return deb, nil
	}
	launched := &[][]string{}
	a.d.RunUnit = func(_ context.Context, name string, args ...string) error {
		*launched = append(*launched, append([]string{name}, args...))
		return nil
	}
	return a, g, launched
}

// TestSupervisorPackageLaunched (plan M8d decision 31): the package of the agent's release is staged and the helper
// started once; while it runs nothing is started again.
func TestSupervisorPackageLaunched(t *testing.T) {
	a, _, launched := supervisorAgent(t, "")
	a.Cycle(context.Background())
	if len(*launched) != 1 || (*launched)[0][0] != "systemd-run" || !slices.Contains((*launched)[0], "--from") ||
		(*launched)[0][len((*launched)[0])-1] != "0.0.0~alpha.1" {
		t.Fatalf("launched %v", *launched)
	}
	if m, err := supervisorpkg.ReadMarker(a.d.Layout); err != nil || m == nil || m.Version != buildinfo.Version {
		t.Fatalf("marker %+v, %v", m, err)
	}
	a.Cycle(context.Background())
	if len(*launched) != 1 {
		t.Fatalf("started again while the upgrade runs: %v", *launched)
	}
}

// TestSupervisorPackagePolicy (plan M8d decision 23): under the manual policy the package is not installed unless an
// update was requested at the check-in; a version that failed before is never installed again.
func TestSupervisorPackagePolicy(t *testing.T) {
	a, g, launched := supervisorAgent(t, bundle.UpdatePolicyManual)
	a.Cycle(context.Background())
	if len(*launched) != 0 {
		t.Fatalf("installed under the manual policy: %v", *launched)
	}
	// An update-now request for the release the agent already runs allows the supervisor package of that check-in.
	at := time.Date(2026, 10, 18, 9, 0, 0, 0, time.UTC)
	offer(g, buildinfo.Version, []byte("x"))
	g.Checkin.AgentUpdate.Requested, g.Checkin.AgentUpdate.RequestedAt = true, &at
	a.Cycle(context.Background())
	if len(*launched) != 1 {
		t.Fatalf("a requested update did not install the supervisor package: %v", *launched)
	}

	// A requested agent update of another release goes first.
	c, g, launched := supervisorAgent(t, bundle.UpdatePolicyManual)
	offer(g, "9.1.0", []byte("x"))
	g.Checkin.AgentUpdate.Requested, g.Checkin.AgentUpdate.RequestedAt = true, &at
	c.d.Supervisor = func() (int, error) { return 1, nil }
	c.d.Signal = func(int) error { return nil }
	c.Cycle(context.Background())
	if len(*launched) != 0 {
		t.Fatalf("installed while an agent update is pending: %v", *launched)
	}

	// An accepted uninstall removes the supervisor package: no upgrade starts under it.
	u, _, launched := supervisorAgent(t, "")
	u.st.PendingUninstall = &state.PendingUninstall{CommandID: "c-un", Mode: "leave"}
	u.Cycle(context.Background())
	if len(*launched) != 0 {
		t.Fatalf("installed while an uninstall is pending: %v", *launched)
	}

	b, _, launched := supervisorAgent(t, "")
	b.st.FailedSupervisorVersion = buildinfo.Version
	b.Cycle(context.Background())
	if len(*launched) != 0 {
		t.Fatalf("a failed version was installed again: %v", *launched)
	}
}

// TestSupervisorUpgradeReported (plan M8d decision 32): the result becomes one agent.supervisor_updated event, a
// failed version is remembered, and the result is removed once the server accepted the event.
func TestSupervisorUpgradeReported(t *testing.T) {
	a, g, _ := supervisorAgent(t, "")
	a.st.FailedSupervisorVersion = buildinfo.Version // keep the helper from starting in this test
	res := `{"version":"1.2.0","from_version":"1.1.0","outcome":"rolled_back","at":"2026-10-18T10:00:00Z"}`
	if err := fsutil.WriteFile(a.d.Layout.SupervisorUpgradeResult(), []byte(res), 0o600, 0o700); err != nil {
		t.Fatal(err)
	}
	g.EventsFail = 503
	a.Cycle(context.Background())
	if _, err := os.Stat(a.d.Layout.SupervisorUpgradeResult()); err != nil {
		t.Fatal("the result was removed before the server accepted its event")
	}
	g.Mu.Lock()
	g.EventsFail = 0
	g.Mu.Unlock()
	a.Cycle(context.Background())
	a.Cycle(context.Background())
	ev := eventsOf(g, protocol.EventAgentSupervisorUpdated)
	if len(ev) != 1 || string(ev[0].Data) != `{"from_version":"1.1.0","outcome":"rolled_back","version":"1.2.0"}` {
		t.Fatalf("agent.supervisor_updated events %+v", ev)
	}
	if _, err := os.Stat(a.d.Layout.SupervisorUpgradeResult()); !os.IsNotExist(err) {
		t.Fatal("result not removed after the event was accepted")
	}
	if a.st.FailedSupervisorVersion != "1.2.0" {
		t.Fatalf("failed version not remembered: %q", a.st.FailedSupervisorVersion)
	}
}

// TestSupervisorUpgradeStale: a marker older than 30 minutes without a result is reported as install_failed; a
// younger one is left alone.
func TestSupervisorUpgradeStale(t *testing.T) {
	a, g, launched := supervisorAgent(t, "")
	now := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	a.d.Now = func() time.Time { return now }
	marker := `{"version":"` + buildinfo.Version + `","from_version":"0.0.0~alpha.1","started_at":"2026-10-18T11:40:00Z"}`
	if err := fsutil.WriteFile(a.d.Layout.SupervisorUpgrade(), []byte(marker), 0o600, 0o700); err != nil {
		t.Fatal(err)
	}
	a.Cycle(context.Background())
	if len(eventsOf(g, protocol.EventAgentSupervisorUpdated)) != 0 || len(*launched) != 0 {
		t.Fatal("a running upgrade was reported or a second one started")
	}
	now = now.Add(11 * time.Minute)
	a.Cycle(context.Background())
	a.Cycle(context.Background())
	ev := eventsOf(g, protocol.EventAgentSupervisorUpdated)
	if len(ev) != 1 || string(ev[0].Data) != `{"from_version":"0.0.0~alpha.1","outcome":"install_failed","version":"`+buildinfo.Version+`"}` {
		t.Fatalf("events %+v", ev)
	}
	if a.st.FailedSupervisorVersion != buildinfo.Version || len(*launched) != 0 {
		t.Fatalf("failed version %q, launched %v", a.st.FailedSupervisorVersion, *launched)
	}
	if m, _ := supervisorpkg.ReadMarker(a.d.Layout); m != nil {
		t.Fatalf("stale marker left: %+v", m)
	}
}

// TestSupervisorRetryAfterUnreachable (design contract 8, ADR 0037 amendment 2026-10-18): a rollback only because the
// server was unreachable does not mark the version failed; the next attempt waits 24 hours, and the third such
// rollback marks it failed. A successful upgrade forgets the retry.
func TestSupervisorRetryAfterUnreachable(t *testing.T) {
	a, _, launched := supervisorAgent(t, "")
	now := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	a.d.Now = func() time.Time { return now }
	unreachable := func(at time.Time) {
		t.Helper()
		r := supervisorpkg.Result{Version: buildinfo.Version, FromVersion: "0.0.0~alpha.1", Outcome: protocol.SupervisorOutcomeRolledBackUnreachable, At: at}
		if err := supervisorpkg.WriteResult(a.d.Layout, r); err != nil {
			t.Fatal(err)
		}
		a.reportSupervisorUpgrade()
		if err := supervisorpkg.RemoveResult(a.d.Layout); err != nil {
			t.Fatal(err)
		}
	}
	for attempt := 1; attempt < supervisorpkg.MaxAttempts; attempt++ {
		unreachable(now)
		if a.st.FailedSupervisorVersion != "" || a.st.SupervisorRetry == nil || a.st.SupervisorRetry.Attempts != attempt {
			t.Fatalf("attempt %d: failed %q, retry %+v", attempt, a.st.FailedSupervisorVersion, a.st.SupervisorRetry)
		}
		now = now.Add(supervisorpkg.RetryAfter - time.Minute)
		a.handleSupervisorPackage(context.Background())
		if len(*launched) != attempt-1 {
			t.Fatalf("attempt %d: retried before 24 hours: %v", attempt, *launched)
		}
		now = now.Add(2 * time.Minute)
		a.handleSupervisorPackage(context.Background())
		if len(*launched) != attempt {
			t.Fatalf("attempt %d: not retried after 24 hours: %v", attempt, *launched)
		}
		if err := os.Remove(a.d.Layout.SupervisorUpgrade()); err != nil {
			t.Fatal(err)
		}
	}
	unreachable(now)
	if a.st.FailedSupervisorVersion != buildinfo.Version || a.st.SupervisorRetry != nil {
		t.Fatalf("after %d attempts: failed %q, retry %+v", supervisorpkg.MaxAttempts, a.st.FailedSupervisorVersion, a.st.SupervisorRetry)
	}

	b, _, _ := supervisorAgent(t, "")
	b.st.SupervisorRetry = &state.SupervisorRetry{Version: buildinfo.Version, Attempts: 1}
	if err := supervisorpkg.WriteResult(b.d.Layout, supervisorpkg.Result{Version: buildinfo.Version, Outcome: protocol.SupervisorOutcomeUpdated,
		At: now}); err != nil {
		t.Fatal(err)
	}
	b.reportSupervisorUpgrade()
	if b.st.SupervisorRetry != nil || b.st.FailedSupervisorVersion != "" {
		t.Fatalf("after an update: retry %+v, failed %q", b.st.SupervisorRetry, b.st.FailedSupervisorVersion)
	}
}

// TestCheckinFailureMarked (design contract 8): a check-in that does not reach the server (5xx of the proxy) leaves
// the mark the supervisor upgrade helper reads; a refusal by the server does not.
func TestCheckinFailureMarked(t *testing.T) {
	a, g, _ := supervisorAgent(t, "")
	g.CheckinFail = 401
	a.Cycle(context.Background())
	if _, err := os.Stat(a.d.Layout.LastCheckinFailed()); !os.IsNotExist(err) {
		t.Fatalf("a refused check-in was marked: %v", err)
	}
	g.CheckinFail = 503
	a.Cycle(context.Background())
	if _, err := os.Stat(a.d.Layout.LastCheckinFailed()); err != nil {
		t.Fatalf("an unreachable server was not marked: %v", err)
	}
}

// TestAgentUpdateWaitsForSupervisorUpgrade (review finding 12): an agent update offered while a supervisor upgrade
// runs is not staged.
func TestAgentUpdateWaitsForSupervisorUpgrade(t *testing.T) {
	a, g, _ := supervisorAgent(t, "")
	signalled := 0
	a.d.Supervisor = func() (int, error) { return 1, nil }
	a.d.Signal = func(int) error { signalled++; return nil }
	marker := `{"version":"` + buildinfo.Version + `","from_version":"0.0.0~alpha.1","started_at":"2026-10-18T11:40:00Z"}`
	if err := fsutil.WriteFile(a.d.Layout.SupervisorUpgrade(), []byte(marker), 0o600, 0o700); err != nil {
		t.Fatal(err)
	}
	a.d.Now = func() time.Time { return time.Date(2026, 10, 18, 11, 45, 0, 0, time.UTC) }
	offer(g, "9.1.0", []byte("new agent"))
	a.Cycle(context.Background())
	if signalled != 0 || update.Pending(a.d.Layout) {
		t.Fatalf("staged during a supervisor upgrade: signalled %d", signalled)
	}
	if err := os.Remove(a.d.Layout.SupervisorUpgrade()); err != nil {
		t.Fatal(err)
	}
	a.Cycle(context.Background())
	if signalled != 1 {
		t.Fatalf("not staged after the supervisor upgrade: signalled %d", signalled)
	}
}

// TestSupervisorUpgradeDeferred: plan M8e amendment 2026-10-21, item 16 — a deferred upgrade (dpkg locked by another
// package run) reports no event, counts toward no failure, and is retried after a doubling wait.
func TestSupervisorUpgradeDeferred(t *testing.T) {
	a, g, launched := supervisorAgent(t, "")
	now := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	a.d.Now = func() time.Time { return now }
	defer_ := func() {
		t.Helper()
		if err := os.Remove(a.d.Layout.SupervisorUpgrade()); err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
		if err := supervisorpkg.WriteResult(a.d.Layout, supervisorpkg.Result{Version: buildinfo.Version, Outcome: supervisorpkg.OutcomeDeferred,
			At: now}); err != nil {
			t.Fatal(err)
		}
		a.reportSupervisorUpgrade()
	}
	defer_()
	if r, _ := supervisorpkg.ReadResult(a.d.Layout); r != nil || a.st.FailedSupervisorVersion != "" || a.st.SupervisorRetry == nil ||
		a.st.SupervisorRetry.Attempts != 0 || !a.st.SupervisorRetry.NotBefore.Equal(now.Add(supervisorpkg.DeferFirst)) {
		t.Fatalf("deferred: result %+v, retry %+v", r, a.st.SupervisorRetry)
	}
	for _, e := range spooled(t, a) {
		if e.Type == protocol.EventAgentSupervisorUpdated {
			t.Fatalf("a deferral was reported: %+v", e)
		}
	}
	a.handleSupervisorPackage(context.Background())
	if len(*launched) != 0 {
		t.Fatal("retried within the wait")
	}
	now = now.Add(supervisorpkg.DeferFirst)
	a.handleSupervisorPackage(context.Background())
	if len(*launched) != 1 {
		t.Fatal("not retried after the wait")
	}
	defer_()
	if !a.st.SupervisorRetry.NotBefore.Equal(now.Add(2 * supervisorpkg.DeferFirst)) {
		t.Fatalf("second deferral: %+v", a.st.SupervisorRetry)
	}
	_ = g
}

// TestSupervisorUpgradeHeldDuringInitrdWork: plan M8e amendment 2026-10-21, items 16 and 17 — no supervisor upgrade
// starts while the conversion worker runs (it may hold dpkg's locks); a cleanup waiting for its next attempt, which may
// never finish, does not hold it.
func TestSupervisorUpgradeHeldDuringInitrdWork(t *testing.T) {
	a, _, launched := supervisorAgent(t, "")
	a.conversionBusy = true
	a.handleSupervisorPackage(context.Background())
	if len(*launched) != 0 {
		t.Fatalf("installed while the worker ran: %v", *launched)
	}
	a.conversionBusy = false
	a.st.Conversion = &state.DiskConversion{ID: testConversionID, Phase: state.ConversionCancelled, CleanupPending: true}
	a.handleSupervisorPackage(context.Background())
	if len(*launched) != 1 {
		t.Fatal("a pending cleanup held the upgrade")
	}
}

// writeUnreadableMarker writes a corrupt supervisor-upgrade.json whose mtime lies age before the agent's clock.
func writeUnreadableMarker(t *testing.T, a *Agent, age time.Duration) {
	t.Helper()
	marker := a.d.Layout.SupervisorUpgrade()
	if err := fsutil.WriteFile(marker, []byte("{not json"), 0o600, 0o700); err != nil {
		t.Fatal(err)
	}
	mtime := a.d.Now().Add(-age)
	if err := os.Chtimes(marker, mtime, mtime); err != nil {
		t.Fatal(err)
	}
}

// TestAgentUpdateUnreadableSupervisorMarker (PDK-337): an unreadable supervisor upgrade marker holds an agent update
// back only until its mtime is older than supervisorpkg.StaleAfter.
func TestAgentUpdateUnreadableSupervisorMarker(t *testing.T) {
	for _, tc := range []struct {
		name   string
		age    time.Duration
		staged bool
	}{
		{"younger than StaleAfter", supervisorpkg.StaleAfter - time.Minute, false},
		{"older than StaleAfter", supervisorpkg.StaleAfter + time.Minute, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, g, _ := supervisorAgent(t, "")
			signalled := 0
			a.d.Supervisor = func() (int, error) { return 1, nil }
			a.d.Signal = func(int) error { signalled++; return nil }
			writeUnreadableMarker(t, a, tc.age)
			offer(g, "9.1.0", []byte("new agent"))
			a.Cycle(context.Background())
			if staged := signalled == 1 && update.Pending(a.d.Layout); staged != tc.staged {
				t.Fatalf("staged %v, want %v: signalled %d", staged, tc.staged, signalled)
			}
		})
	}
}

// TestSupervisorPackageUnreadableMarker (PDK-337): an unreadable supervisor upgrade marker holds a further supervisor
// upgrade back only until its mtime is older than supervisorpkg.StaleAfter.
func TestSupervisorPackageUnreadableMarker(t *testing.T) {
	for _, tc := range []struct {
		name    string
		age     time.Duration
		started bool
	}{
		{"younger than StaleAfter", supervisorpkg.StaleAfter - time.Minute, false},
		{"older than StaleAfter", supervisorpkg.StaleAfter + time.Minute, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, _, launched := supervisorAgent(t, "")
			writeUnreadableMarker(t, a, tc.age)
			a.Cycle(context.Background())
			if started := len(*launched) == 1; started != tc.started {
				t.Fatalf("started %v, want %v: %v", started, tc.started, *launched)
			}
			if !tc.started {
				return
			}
			if m, err := supervisorpkg.ReadMarker(a.d.Layout); err != nil || m == nil || m.Version != buildinfo.Version {
				t.Fatalf("marker %+v, %v", m, err)
			}
		})
	}
}
