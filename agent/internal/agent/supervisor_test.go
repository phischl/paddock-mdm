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
	"github.com/phischl/paddock-mdm/agent/internal/supervisorpkg"
	"github.com/phischl/paddock-mdm/agent/internal/testgw"
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
