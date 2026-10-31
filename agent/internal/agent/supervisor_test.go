package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
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

// writeSupervisorMarker writes a readable supervisor-upgrade.json started at startedAt.
func writeSupervisorMarker(t *testing.T, a *Agent, startedAt time.Time) {
	t.Helper()
	marker, err := json.Marshal(supervisorpkg.Marker{Version: "1.2.0", FromVersion: "1.1.0", StartedAt: startedAt})
	if err != nil {
		t.Fatal(err)
	}
	if err := fsutil.WriteFile(a.d.Layout.SupervisorUpgrade(), marker, 0o600, 0o700); err != nil {
		t.Fatal(err)
	}
}

// markerHolds asks both users of the one marker rule (PDK-479) — supervisorUpgradeHolds and the conversion worker's
// holdForSupervisor — and fails when they disagree.
func markerHolds(t *testing.T, a *Agent) bool {
	t.Helper()
	holds, _ := a.supervisorUpgradeHolds()
	a.d.Sleep = func(context.Context, time.Duration) error { return context.Canceled }
	waited := a.holdForSupervisor(context.Background()) != nil
	if holds != waited {
		t.Fatalf("supervisorUpgradeHolds %v, holdForSupervisor waited %v", holds, waited)
	}
	return holds
}

// TestSupervisorMarkerBoundary (PDK-479): a marker holds while it is younger than supervisorpkg.StaleAfter, counted
// from StartedAt or, when unreadable, from its mtime, and no longer at exactly StaleAfter.
func TestSupervisorMarkerBoundary(t *testing.T) {
	for _, tc := range []struct {
		name     string
		readable bool
		age      time.Duration
		holds    bool
	}{
		{"readable, younger", true, supervisorpkg.StaleAfter - time.Second, true},
		{"readable, exactly StaleAfter", true, supervisorpkg.StaleAfter, false},
		{"unreadable, younger", false, supervisorpkg.StaleAfter - time.Second, true},
		{"unreadable, exactly StaleAfter", false, supervisorpkg.StaleAfter, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, _, _ := supervisorAgent(t, "")
			now := time.Date(2026, 10, 21, 9, 0, 0, 0, time.UTC)
			a.d.Now = func() time.Time { return now }
			if tc.readable {
				writeSupervisorMarker(t, a, now.Add(-tc.age))
			} else {
				writeUnreadableMarker(t, a, tc.age)
			}
			if holds := markerHolds(t, a); holds != tc.holds {
				t.Fatalf("holds %v, want %v", holds, tc.holds)
			}
		})
	}
}

// TestSupervisorMarkerUnplaceableStart (PDK-479): a marker whose start the agent cannot place — the stat fails with
// something other than not-exist, or the start lies ahead of a clock set back — holds for supervisorpkg.StaleAfter
// from the agent's first sighting, not forever; a readable one then counts as install_failed.
func TestSupervisorMarkerUnplaceableStart(t *testing.T) {
	for _, tc := range []struct {
		name  string
		write func(t *testing.T, a *Agent, now time.Time)
	}{
		{"stat error", func(t *testing.T, a *Agent, _ time.Time) {
			marker := a.d.Layout.SupervisorUpgrade()
			if err := os.MkdirAll(filepath.Dir(marker), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(marker, marker); err != nil {
				t.Fatal(err)
			}
		}},
		{"unreadable, mtime ahead", func(t *testing.T, a *Agent, _ time.Time) { writeUnreadableMarker(t, a, -2*time.Hour) }},
		{"readable, start ahead", func(t *testing.T, a *Agent, now time.Time) { writeSupervisorMarker(t, a, now.Add(2*time.Hour)) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, _, _ := supervisorAgent(t, "")
			seen := time.Date(2026, 10, 21, 9, 0, 0, 0, time.UTC)
			now := seen
			a.d.Now = func() time.Time { return now }
			tc.write(t, a, now)
			if !markerHolds(t, a) {
				t.Fatal("not held at the first sighting")
			}
			now = seen.Add(supervisorpkg.StaleAfter - time.Second)
			if !markerHolds(t, a) {
				t.Fatal("not held within StaleAfter of the first sighting")
			}
			now = seen.Add(supervisorpkg.StaleAfter)
			if markerHolds(t, a) {
				t.Fatal("held at StaleAfter after the first sighting")
			}
			if tc.name != "readable, start ahead" {
				return
			}
			a.reportSupervisorUpgrade()
			if r, err := supervisorpkg.ReadResult(a.d.Layout); err != nil || r == nil || r.Outcome != protocol.SupervisorOutcomeInstallFailed {
				t.Fatalf("not counted as failed: %+v %v", r, err)
			}
		})
	}
}

// TestSupervisorMarkerClockCatchesUp (PDK-479): once the clock passes the start of a marker it first saw ahead of the
// clock, the hold still ends StaleAfter after the first sighting instead of beginning anew.
func TestSupervisorMarkerClockCatchesUp(t *testing.T) {
	a, _, _ := supervisorAgent(t, "")
	seen := time.Date(2026, 10, 21, 9, 0, 0, 0, time.UTC)
	now := seen
	a.d.Now = func() time.Time { return now }
	writeUnreadableMarker(t, a, -10*time.Minute)
	if !markerHolds(t, a) {
		t.Fatal("not held at the first sighting")
	}
	now = seen.Add(20 * time.Minute)
	if !markerHolds(t, a) {
		t.Fatal("not held within StaleAfter of the first sighting")
	}
	now = seen.Add(supervisorpkg.StaleAfter)
	if markerHolds(t, a) {
		t.Fatal("the hold began anew once the clock passed the marker's mtime")
	}
}

// TestSupervisorPackageOverridesStaleMarker (PDK-479): a supervisor upgrade that overrides a stale unreadable marker
// logs a warning, and the marker it writes holds — already while systemd-run starts the helper — a further upgrade back
// although its start lies ahead of the clock.
func TestSupervisorPackageOverridesStaleMarker(t *testing.T) {
	a, _, launched := supervisorAgent(t, "")
	seen := time.Now().Add(-time.Hour)
	now := seen
	a.d.Now = func() time.Time { return now }
	writeUnreadableMarker(t, a, -10*time.Minute)
	a.handleSupervisorPackage(context.Background())
	if len(*launched) != 0 {
		t.Fatalf("started while the marker held: %v", *launched)
	}
	now = seen.Add(supervisorpkg.StaleAfter)
	run := a.d.RunUnit
	heldAtLaunch := false
	a.d.RunUnit = func(ctx context.Context, name string, args ...string) error {
		heldAtLaunch, _ = a.supervisorUpgradeHolds()
		return run(ctx, name, args...)
	}
	var logs strings.Builder
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	a.handleSupervisorPackage(context.Background())
	slog.SetDefault(prev)
	if !heldAtLaunch {
		t.Fatal("the new marker did not hold while systemd-run started the helper (review 1, m1)")
	}
	if len(*launched) != 1 {
		t.Fatalf("not started over the stale marker: %v", *launched)
	}
	if !strings.Contains(logs.String(), "level=WARN") || !strings.Contains(logs.String(), "unreadable supervisor upgrade marker is stale") {
		t.Fatalf("no warning: %s", logs.String())
	}
	a.handleSupervisorPackage(context.Background())
	if len(*launched) != 1 {
		t.Fatalf("started again while the new upgrade runs: %v", *launched)
	}
}

// TestSupervisorResultUnreadable (PDK-479): a corrupt supervisor-upgrade-result.json — invalid JSON or a field of the
// wrong type — is discarded with a warning and no event, and no longer holds the next supervisor upgrade back. One that
// cannot be read for an I/O error is kept and still holds (review 1, E2): it may hide a failure that must be reported.
func TestSupervisorResultUnreadable(t *testing.T) {
	for _, tc := range []struct {
		name    string
		write   func(t *testing.T, file string)
		discard bool
	}{
		{"syntax error", func(t *testing.T, file string) {
			if err := fsutil.WriteFile(file, []byte("{not json"), 0o600, 0o700); err != nil {
				t.Fatal(err)
			}
		}, true},
		{"type error", func(t *testing.T, file string) {
			if err := fsutil.WriteFile(file, []byte(`{"version":5}`), 0o600, 0o700); err != nil {
				t.Fatal(err)
			}
		}, true},
		{"malformed time", func(t *testing.T, file string) {
			if err := fsutil.WriteFile(file, []byte(`{"at":"2026-13-99T00:00:00Z"}`), 0o600, 0o700); err != nil {
				t.Fatal(err)
			}
		}, true},
		{"time of the wrong type", func(t *testing.T, file string) {
			if err := fsutil.WriteFile(file, []byte(`{"at":123}`), 0o600, 0o700); err != nil {
				t.Fatal(err)
			}
		}, true},
		{"I/O error", func(t *testing.T, file string) {
			if err := os.MkdirAll(file, 0o700); err != nil {
				t.Fatal(err)
			}
		}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, _, launched := supervisorAgent(t, "")
			file := a.d.Layout.SupervisorUpgradeResult()
			tc.write(t, file)
			var logs strings.Builder
			prev := slog.Default()
			slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
			a.reportSupervisorUpgrade()
			slog.SetDefault(prev)
			want := "level=ERROR msg=\"reading the supervisor upgrade result failed\""
			if tc.discard {
				want = "level=WARN msg=\"the supervisor upgrade result is corrupt; it is discarded\""
			}
			if !strings.Contains(logs.String(), want) {
				t.Fatalf("log %q missing: %s", want, logs.String())
			}
			if _, err := os.Stat(file); os.IsNotExist(err) != tc.discard {
				t.Fatalf("discarded %v, want %v", os.IsNotExist(err), tc.discard)
			}
			for _, e := range spooled(t, a) {
				if e.Type == protocol.EventAgentSupervisorUpdated {
					t.Fatalf("reported: %+v", e)
				}
			}
			a.handleSupervisorPackage(context.Background())
			if started := len(*launched) == 1; started != tc.discard {
				t.Fatalf("started %v, want %v: %v", started, tc.discard, *launched)
			}
		})
	}
}

// TestSupervisorPackageWaitsForConversion (PDK-479, review 1 M1): a readable marker that turns stale between
// reportSupervisorUpgrade and handleSupervisorPackage in the same cycle is not overwritten by a new upgrade; the next
// cycle converts it into install_failed, reports it and does not install the failed version again.
func TestSupervisorPackageWaitsForConversion(t *testing.T) {
	a, g, launched := supervisorAgent(t, "")
	start := time.Date(2026, 10, 21, 9, 0, 0, 0, time.UTC)
	now := start.Add(supervisorpkg.StaleAfter - time.Second)
	a.d.Now = func() time.Time { return now }
	marker, err := json.Marshal(supervisorpkg.Marker{Version: buildinfo.Version, FromVersion: "0.0.0~alpha.1", StartedAt: start})
	if err != nil {
		t.Fatal(err)
	}
	if err := fsutil.WriteFile(a.d.Layout.SupervisorUpgrade(), marker, 0o600, 0o700); err != nil {
		t.Fatal(err)
	}
	a.reportSupervisorUpgrade()
	if r, err := supervisorpkg.ReadResult(a.d.Layout); err != nil || r != nil {
		t.Fatalf("fresh marker converted: %+v %v", r, err)
	}
	now = start.Add(supervisorpkg.StaleAfter)
	a.handleSupervisorPackage(context.Background())
	if len(*launched) != 0 {
		t.Fatalf("started over the unconverted marker: %v", *launched)
	}
	if m, err := supervisorpkg.ReadMarker(a.d.Layout); err != nil || m == nil || !m.StartedAt.Equal(start) {
		t.Fatalf("marker overwritten: %+v %v", m, err)
	}
	a.Cycle(context.Background())
	ev := eventsOf(g, protocol.EventAgentSupervisorUpdated)
	if len(ev) != 1 || string(ev[0].Data) != `{"from_version":"0.0.0~alpha.1","outcome":"install_failed","version":"`+buildinfo.Version+`"}` {
		t.Fatalf("events %+v", ev)
	}
	if a.st.FailedSupervisorVersion != buildinfo.Version || len(*launched) != 0 {
		t.Fatalf("failed version %q, launched %v", a.st.FailedSupervisorVersion, *launched)
	}
}

// TestSupervisorMarkerClockSetBack (PDK-479, review 1 E1): a wall clock set back by less than a marker's age leaves its
// start in the past but shortens the age; the hold still ends StaleAfter after the agent first saw the marker, also
// after repeated small steps back.
func TestSupervisorMarkerClockSetBack(t *testing.T) {
	for _, tc := range []struct {
		name  string
		steps []time.Duration
	}{
		{"one step", []time.Duration{19 * time.Minute}},
		{"repeated steps", []time.Duration{4 * time.Minute, 4 * time.Minute, 4 * time.Minute, 4 * time.Minute}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, _, _ := supervisorAgent(t, "")
			start := time.Date(2026, 10, 21, 10, 0, 0, 0, time.UTC)
			elapsed := time.Duration(0)
			wall := start.Add(time.Minute)
			a.d.Now = func() time.Time { return wall }
			a.d.Monotonic = func() time.Time { return start.Add(elapsed) }
			writeSupervisorMarker(t, a, start)
			if !markerHolds(t, a) {
				t.Fatal("not held at the first sighting")
			}
			for _, step := range tc.steps {
				elapsed += 5 * time.Minute
				wall = wall.Add(5*time.Minute - step)
				if !markerHolds(t, a) {
					t.Fatal("not held within StaleAfter of the first sighting")
				}
			}
			advance := supervisorpkg.StaleAfter - time.Second - elapsed
			elapsed, wall = elapsed+advance, wall.Add(advance)
			if !markerHolds(t, a) {
				t.Fatal("not held a second before StaleAfter after the first sighting")
			}
			elapsed, wall = elapsed+time.Second, wall.Add(time.Second)
			if wall.Sub(start) >= supervisorpkg.StaleAfter {
				t.Fatalf("the wall clock alone would release it: %v", wall.Sub(start))
			}
			if markerHolds(t, a) {
				t.Fatal("held StaleAfter after the first sighting")
			}
			a.reportSupervisorUpgrade()
			if r, err := supervisorpkg.ReadResult(a.d.Layout); err != nil || r == nil || r.Outcome != protocol.SupervisorOutcomeInstallFailed {
				t.Fatalf("not counted as failed: %+v %v", r, err)
			}
		})
	}
}
