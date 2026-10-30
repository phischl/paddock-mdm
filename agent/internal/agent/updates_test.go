package agent

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/agent/internal/buildinfo"
	"github.com/phischl/paddock-mdm/agent/internal/fsutil"
	"github.com/phischl/paddock-mdm/agent/internal/state"
	"github.com/phischl/paddock-mdm/agent/internal/testgw"
	"github.com/phischl/paddock-mdm/agent/internal/update"
	"github.com/phischl/paddock-mdm/pkg/bundle"
	"github.com/phischl/paddock-mdm/pkg/protocol"
)

func offer(g *testgw.Gateway, version string, bin []byte) {
	sum := sha256.Sum256(bin)
	g.Mu.Lock()
	defer g.Mu.Unlock()
	g.Files["paddockd-"+version] = bin
	g.Checkin.AgentUpdate = &protocol.AgentUpdate{
		Version: version, URL: g.FileURL("paddockd-" + version), SHA256: hex.EncodeToString(sum[:]),
		Size: int64(len(bin)), Minisig: base64.StdEncoding.EncodeToString([]byte("untrusted comment: test\nsig")),
	}
}

func TestUpdateStagedAndSupervisorAsked(t *testing.T) {
	g := testgw.New(t)
	a := newAgent(t, g)
	var signalled []int
	a.d.Supervisor = func() (int, error) { return 4242, nil }
	a.d.Signal = func(pid int) error { signalled = append(signalled, pid); return nil }
	offer(g, "9.1.0", []byte("new agent"))
	a.Cycle(context.Background())
	staged, err := os.ReadFile(filepath.Join(a.d.Layout.Staging(), "9.1.0", "paddockd"))
	if err != nil || string(staged) != "new agent" || !update.Pending(a.d.Layout) || len(signalled) != 1 || signalled[0] != 4242 {
		t.Fatalf("staged %q, %v, pending %v, signalled %v", staged, err, update.Pending(a.d.Layout), signalled)
	}
	if sig, _ := os.ReadFile(filepath.Join(a.d.Layout.Staging(), "9.1.0", "paddockd.minisig")); string(sig) != "untrusted comment: test\nsig" {
		t.Fatalf("signature file %q", sig)
	}
	// While the request waits for the supervisor, the offer is not staged again.
	a.Cycle(context.Background())
	if len(signalled) != 1 {
		t.Fatalf("signalled %d times", len(signalled))
	}
}

// TestIgnoredReleaseSwept (PDK-075): the supervisor ignores a request that arrives during a probation or a pending
// rollback and later removes only request.json; the next check-in removes the release left without a request.
func TestIgnoredReleaseSwept(t *testing.T) {
	g := testgw.New(t)
	a := newAgent(t, g)
	a.d.Supervisor = func() (int, error) { return 1, nil }
	a.d.Signal = func(int) error { return nil }
	offer(g, "9.1.0", []byte("new agent"))
	a.Cycle(context.Background())
	release := filepath.Join(a.d.Layout.Staging(), "9.1.0")
	if _, err := os.Stat(release); err != nil || !update.Pending(a.d.Layout) {
		t.Fatalf("not staged: %v, pending %v", err, update.Pending(a.d.Layout))
	}
	// While the request waits for the supervisor, nothing under staging is removed.
	a.Cycle(context.Background())
	if _, err := os.Stat(filepath.Join(release, "paddockd")); err != nil {
		t.Fatalf("staged release removed while requested: %v", err)
	}
	if err := os.Remove(a.d.Layout.UpdateRequest()); err != nil {
		t.Fatal(err)
	}
	g.Mu.Lock()
	g.Checkin.AgentUpdate = nil
	g.Mu.Unlock()
	a.Cycle(context.Background())
	if _, err := os.Stat(release); !os.IsNotExist(err) {
		t.Fatalf("ignored release left in staging: %v", err)
	}
}

// TestLeftoverReleaseSweptAtStart (PDK-075): a release directory without request.json is removed when the daemon
// starts, before its first check-in; New alone (also used by `paddockd plan`) and PlanCurrent leave it untouched.
func TestLeftoverReleaseSweptAtStart(t *testing.T) {
	g := testgw.New(t)
	g.CheckinFail = 503 // a failed check-in does not reach handleUpdate, so only the start sweep can remove the release
	a := newAgent(t, g)
	release := filepath.Join(a.d.Layout.Staging(), "9.1.0", "paddockd")
	if err := fsutil.WriteFile(release, []byte("x"), 0o700, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := New(a.d); err != nil {
		t.Fatal(err)
	}
	// PlanCurrent must get past Load and New, or the check below proves nothing.
	if _, _, err := PlanCurrent(context.Background(), a.d.Layout); err == nil || err.Error() != "no applied bundle" {
		t.Fatalf("PlanCurrent = %v, want the no-applied-bundle error", err)
	}
	if _, err := os.Stat(release); err != nil {
		t.Fatalf("New or PlanCurrent removed a staged release: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx) }()
	waitFor(t, func() bool { return checkins(g) >= 1 })
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("run: %v", err)
	}
	if _, err := os.Stat(filepath.Dir(release)); !os.IsNotExist(err) {
		t.Fatalf("leftover release not removed at start: %v", err)
	}
}

func TestUpdateNotStaged(t *testing.T) {
	tests := []struct {
		name  string
		setup func(a *Agent, g *testgw.Gateway)
	}{
		{"not under the supervisor", func(a *Agent, g *testgw.Gateway) {
			a.d.Supervisor = func() (int, error) { return 0, errors.New("not running under paddock-supervisor") }
			offer(g, "9.1.0", []byte("x"))
		}},
		{"hash mismatch", func(a *Agent, g *testgw.Gateway) {
			offer(g, "9.1.0", []byte("x"))
			g.Checkin.AgentUpdate.SHA256 = "00"
		}},
		{"size mismatch", func(a *Agent, g *testgw.Gateway) {
			offer(g, "9.1.0", []byte("x"))
			g.Checkin.AgentUpdate.Size = 5
		}},
		{"path in version", func(a *Agent, g *testgw.Gateway) { offer(g, "../../etc", []byte("x")) }},
		{"previously failed version", func(a *Agent, g *testgw.Gateway) {
			a.st.FailedUpdateVersion = "9.1.0"
			offer(g, "9.1.0", []byte("x"))
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := testgw.New(t)
			a := newAgent(t, g)
			signalled := 0
			a.d.Supervisor = func() (int, error) { return 1, nil }
			a.d.Signal = func(int) error { signalled++; return nil }
			tt.setup(a, g)
			a.Cycle(context.Background())
			if update.Pending(a.d.Layout) || signalled != 0 {
				t.Fatalf("staged (pending %v, signalled %d)", update.Pending(a.d.Layout), signalled)
			}
		})
	}
}

// TestUpdatePolicyManual (plan M8d decision 23): under the manual policy an offer is not staged and the supervisor is
// not asked, logged once per version; a requested offer is staged; the fleetd gate follows the same rule.
func TestUpdatePolicyManual(t *testing.T) {
	g := testgw.New(t)
	a := newAgent(t, g)
	signalled := 0
	a.d.Supervisor = func() (int, error) { return 1, nil }
	a.d.Signal = func(int) error { signalled++; return nil }
	a.current = &bundle.Bundle{Agent: bundle.AgentCfg{UpdatePolicy: bundle.UpdatePolicyManual}}
	offer(g, "9.1.0", []byte("x"))
	a.Cycle(context.Background())
	a.Cycle(context.Background())
	if update.Pending(a.d.Layout) || signalled != 0 || a.policySkipped != "9.1.0" || a.updatesAllowed() {
		t.Fatalf("staged under manual (pending %v, signalled %d, skipped %q)", update.Pending(a.d.Layout), signalled, a.policySkipped)
	}
	requestedAt := time.Date(2026, 10, 17, 9, 0, 0, 0, time.UTC)
	g.Mu.Lock()
	g.Checkin.AgentUpdate.Requested, g.Checkin.AgentUpdate.RequestedAt = true, &requestedAt
	g.Mu.Unlock()
	a.Cycle(context.Background())
	if !update.Pending(a.d.Layout) || signalled != 1 || !a.updatesAllowed() {
		t.Fatalf("requested offer not staged (pending %v, signalled %d)", update.Pending(a.d.Layout), signalled)
	}
	a.current = &bundle.Bundle{}
	a.updateRequested = false
	if !a.updatesAllowed() {
		t.Fatal("automatic policy does not allow updates")
	}
}

// TestUpdateNowHandledOnce (plan M8d decision 28): a fresh request overrides a failed version and the manual policy
// once; the same request again follows the normal rules; a newer request is handled again.
func TestUpdateNowHandledOnce(t *testing.T) {
	g := testgw.New(t)
	a := newAgent(t, g)
	signalled := 0
	a.d.Supervisor = func() (int, error) { return 1, nil }
	a.d.Signal = func(int) error { signalled++; return nil }
	a.current = &bundle.Bundle{Agent: bundle.AgentCfg{UpdatePolicy: bundle.UpdatePolicyManual}}
	a.st.FailedUpdateVersion = "9.1.0"
	first := time.Date(2026, 10, 17, 9, 0, 0, 0, time.UTC)
	offer(g, "9.1.0", []byte("x"))
	g.Checkin.AgentUpdate.Requested, g.Checkin.AgentUpdate.RequestedAt = true, &first
	a.Cycle(context.Background())
	if !update.Pending(a.d.Layout) || signalled != 1 || a.st.UpdateRequestHandledAt == nil || !a.st.UpdateRequestHandledAt.Equal(first) {
		t.Fatalf("fresh request not staged (pending %v, signalled %d, handled %v)", update.Pending(a.d.Layout), signalled, a.st.UpdateRequestHandledAt)
	}
	if err := os.Remove(a.d.Layout.UpdateRequest()); err != nil { // the supervisor took the request and it failed
		t.Fatal(err)
	}
	a.Cycle(context.Background())
	if update.Pending(a.d.Layout) || signalled != 1 {
		t.Fatalf("the same request staged twice (signalled %d)", signalled)
	}
	second := first.Add(time.Hour)
	g.Mu.Lock()
	g.Checkin.AgentUpdate.RequestedAt = &second
	g.Mu.Unlock()
	a.Cycle(context.Background())
	if !update.Pending(a.d.Layout) || signalled != 2 {
		t.Fatalf("a newer request was not staged (signalled %d)", signalled)
	}
	if st, _ := state.Load(a.d.Layout.State()); st.UpdateRequestHandledAt == nil || !st.UpdateRequestHandledAt.Equal(second) {
		t.Fatalf("handled request not persisted: %+v", st.UpdateRequestHandledAt)
	}
}

// TestPreReleaseOffers (PDK-022): the agent compares versions only for equality and leaves their order to the
// supervisor, so every pre-release of the sequence is staged, also right after its predecessor failed; the running
// version itself is never staged.
func TestPreReleaseOffers(t *testing.T) {
	sequence := []string{"0.1.0-alpha.1", "0.1.0-alpha.2", "0.1.0-beta.1", "0.1.0-rc.1", "0.1.0"}
	for i, v := range sequence {
		t.Run(v, func(t *testing.T) {
			g := testgw.New(t)
			a := newAgent(t, g)
			if i > 0 {
				a.st.FailedUpdateVersion = sequence[i-1]
			}
			a.d.Supervisor = func() (int, error) { return 1, nil }
			a.d.Signal = func(int) error { return nil }
			offer(g, v, []byte("agent "+v))
			a.Cycle(context.Background())
			if staged, err := os.ReadFile(filepath.Join(a.d.Layout.Staging(), v, "paddockd")); err != nil || string(staged) != "agent "+v {
				t.Fatalf("staged %q, %v", staged, err)
			}
		})
	}
	t.Run("running version", func(t *testing.T) {
		g := testgw.New(t)
		a := newAgent(t, g)
		a.d.Supervisor = func() (int, error) { return 1, nil }
		a.d.Signal = func(int) error { return nil }
		offer(g, buildinfo.Version, []byte("x"))
		a.Cycle(context.Background())
		if update.Pending(a.d.Layout) {
			t.Fatal("the running version was staged")
		}
	})
}

func TestUpdateResultReportedOnce(t *testing.T) {
	g := testgw.New(t)
	a := newAgent(t, g)
	res := `{"version":"9.1.0","from_version":"0.0.0-dev","outcome":"rolled_back","at":"2026-10-04T10:00:00Z"}`
	if err := fsutil.WriteFile(a.d.Layout.UpdateResult(), []byte(res), 0o600, 0o700); err != nil {
		t.Fatal(err)
	}
	g.EventsFail = 503
	a.Cycle(context.Background())
	if _, err := os.Stat(a.d.Layout.UpdateResult()); err != nil {
		t.Fatal("the result was removed before the server accepted its event")
	}
	g.Mu.Lock()
	g.EventsFail = 0
	g.Mu.Unlock()
	a.Cycle(context.Background())
	a.Cycle(context.Background())
	ev := eventsOf(g, protocol.EventAgentRolledBack)
	if len(ev) != 1 || string(ev[0].Data) != `{"from_version":"0.0.0-dev","outcome":"rolled_back","version":"9.1.0"}` {
		t.Fatalf("agent.rolled_back events %+v", ev)
	}
	if _, err := os.Stat(a.d.Layout.UpdateResult()); !os.IsNotExist(err) {
		t.Fatal("result not removed after the event was accepted")
	}
	if a.st.FailedUpdateVersion != "9.1.0" {
		t.Fatalf("failed version not remembered: %+v", a.st)
	}
}

func TestUpdateResultEventTypes(t *testing.T) {
	for outcome, want := range map[string]string{
		update.OutcomeUpdated: protocol.EventAgentUpdated, update.OutcomeRolledBack: protocol.EventAgentRolledBack,
		update.OutcomeSelfTestFailed: protocol.EventAgentUpdateFailed, update.OutcomeSignatureInvalid: protocol.EventAgentUpdateFailed,
		update.OutcomeRollbackFailed: protocol.EventAgentUpdateFailed,
	} {
		if got := (update.Result{Outcome: outcome}).EventType(); got != want {
			t.Errorf("%s → %s", outcome, got)
		}
	}
}

// TestSignatureInvalidResultMarksReleaseFailed (PDK-480): the supervisor reports signature_invalid for a request whose
// release directory a crash removed; the agent marks that release failed, does not stage it again, and takes a later
// version.
func TestSignatureInvalidResultMarksReleaseFailed(t *testing.T) {
	g := testgw.New(t)
	a := newAgent(t, g)
	a.d.Supervisor = func() (int, error) { return 4242, nil }
	a.d.Signal = func(int) error { return nil }
	res := `{"version":"9.1.0","from_version":"0.0.0-dev","outcome":"signature_invalid","at":"2026-10-04T10:00:00Z"}`
	if err := fsutil.WriteFile(a.d.Layout.UpdateResult(), []byte(res), 0o600, 0o700); err != nil {
		t.Fatal(err)
	}
	offer(g, "9.1.0", []byte("failed agent"))
	a.Cycle(context.Background())
	if a.st.FailedUpdateVersion != "9.1.0" {
		t.Fatalf("failed version not remembered: %+v", a.st)
	}
	if len(eventsOf(g, protocol.EventAgentUpdateFailed)) != 1 {
		t.Fatal("no agent.update_failed event")
	}
	if update.Pending(a.d.Layout) {
		t.Fatal("the failed release was staged again")
	}
	offer(g, "9.2.0", []byte("later agent"))
	a.Cycle(context.Background())
	if _, err := os.Stat(filepath.Join(a.d.Layout.Staging(), "9.2.0", "paddockd")); err != nil || !update.Pending(a.d.Layout) {
		t.Fatalf("later version not staged: %v", err)
	}
}
