package agent

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/agent/internal/state"
	"github.com/phischl/paddock-mdm/agent/internal/testgw"
	"github.com/phischl/paddock-mdm/agent/internal/uninstall"
	"github.com/phischl/paddock-mdm/pkg/command"
	"github.com/phischl/paddock-mdm/pkg/protocol"
)

func uninstallAgent(t *testing.T) (*Agent, *[][]string) {
	t.Helper()
	g := testgw.New(t)
	a := newAgent(t, g)
	self := filepath.Join(t.TempDir(), "paddockd")
	if err := os.WriteFile(self, []byte("agent binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	a.d.Executable = self
	launched := &[][]string{}
	a.d.RunUnit = func(_ context.Context, name string, args ...string) error {
		*launched = append(*launched, append([]string{name}, args...))
		return nil
	}
	return a, launched
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
	a.st.CommandResults = nil
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

// TestUninstallHelperFailed: a failed systemd-run is reported as agent.uninstalled with outcome helper_failed and
// the pending mark is cleared.
func TestUninstallHelperFailed(t *testing.T) {
	a, _ := uninstallAgent(t)
	a.d.RunUnit = func(context.Context, string, ...string) error { return errors.New("no systemd-run") }
	if status, _ := a.uninstallCommand(context.Background(), uninstallCmd(`{"mode":"leave"}`)); status != protocol.CommandSucceeded {
		t.Fatal(status)
	}
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
}
