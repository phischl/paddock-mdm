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

	"github.com/phischl/paddock-mdm/agent/internal/buildinfo"
	"github.com/phischl/paddock-mdm/agent/internal/fsutil"
	"github.com/phischl/paddock-mdm/agent/internal/testgw"
	"github.com/phischl/paddock-mdm/agent/internal/update"
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
	} {
		if got := (update.Result{Outcome: outcome}).EventType(); got != want {
			t.Errorf("%s → %s", outcome, got)
		}
	}
}
