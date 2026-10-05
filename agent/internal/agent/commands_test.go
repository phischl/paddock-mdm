package agent

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/paddock-mdm/paddock/agent/internal/commands"
	"github.com/paddock-mdm/paddock/agent/internal/state"
	"github.com/paddock-mdm/paddock/agent/internal/testgw"
	"github.com/paddock-mdm/paddock/pkg/bundle"
	"github.com/paddock-mdm/paddock/pkg/command"
	"github.com/paddock-mdm/paddock/pkg/protocol"
)

func testCommand(id, typ string, issued time.Time) command.Command {
	return command.Command{CommandID: id, DeviceID: testgw.DeviceID, OrganizationID: testgw.OrgID, Type: typ,
		IssuedAt: issued, ExpiresAt: issued.Add(time.Hour)}
}

// TestCommandsExecutedOnceAndReported: a verified command runs once, its result is retried until the server
// accepted it, and a forged, expired or unsupported command never runs a handler (plan M4a decision 3).
func TestCommandsExecutedOnceAndReported(t *testing.T) {
	g := testgw.New(t)
	a := newAgent(t, g)
	runs := 0
	a.d.Commands = commands.New(map[string]commands.Handler{"test": func(context.Context, *command.Command) (string, map[string]any) {
		runs++
		return protocol.CommandSucceeded, map[string]any{"ok": true}
	}}, time.Now)
	a.current = &bundle.Bundle{Keys: testgw.CommandKeys()}
	now := time.Now().UTC().Truncate(time.Second)
	good := testgw.SignedCommand(t, testCommand("0190f000-0000-7000-8000-0000000000c1", "test", now))
	unsupported := testgw.SignedCommand(t, testCommand("0190f000-0000-7000-8000-0000000000c2", "install_now", now))
	expired := testgw.SignedCommand(t, testCommand("0190f000-0000-7000-8000-0000000000c3", "test", now.Add(-2*time.Hour)))
	other := testCommand("0190f000-0000-7000-8000-0000000000c4", "test", now)
	other.DeviceID = "0190f000-0000-7000-8000-0000000000ee"
	envelopes := []json.RawMessage{good, unsupported, expired, testgw.SignedCommand(t, other)}

	g.Mu.Lock()
	g.Checkin.Commands = envelopes
	g.ResultFail = http.StatusServiceUnavailable
	g.Mu.Unlock()
	a.Cycle(context.Background())
	if runs != 1 || len(g.Results) != 0 || len(a.st.CommandResults) != 2 {
		t.Fatalf("first cycle: %d runs, results %v, kept %+v", runs, g.Results, a.st.CommandResults)
	}
	st, _ := state.Load(a.d.Layout.State())
	if len(st.ExecutedCommands) != 2 || len(st.CommandResults) != 2 {
		t.Fatalf("persisted state %+v", st)
	}

	g.Mu.Lock()
	g.ResultFail = 0
	g.Mu.Unlock()
	a.Cycle(context.Background())
	if runs != 1 {
		t.Fatalf("command executed %d times", runs)
	}
	ok, refused := g.Results["0190f000-0000-7000-8000-0000000000c1"], g.Results["0190f000-0000-7000-8000-0000000000c2"]
	if len(g.Results) != 2 || ok.Status != "succeeded" || string(ok.Result) != `{"ok":true}` ||
		refused.Status != "failed" || string(refused.Result) != `{"reason":"unsupported_type"}` || len(a.st.CommandResults) != 0 {
		t.Fatalf("results %+v, kept %+v", g.Results, a.st.CommandResults)
	}
}

// TestCommandsWithoutKeys: without command keys in the applied bundle nothing runs.
func TestCommandsWithoutKeys(t *testing.T) {
	g := testgw.New(t)
	a := newAgent(t, g)
	g.Checkin.Commands = []json.RawMessage{testgw.SignedCommand(t, testCommand("0190f000-0000-7000-8000-0000000000c1", "test", time.Now()))}
	a.Cycle(context.Background())
	if len(a.st.ExecutedCommands) != 0 || len(g.Results) != 0 {
		t.Fatalf("executed %v, results %v", a.st.ExecutedCommands, g.Results)
	}
}

// TestCommandResultRefusedIsDropped: a result the server refuses with 404 or 409 is not retried.
func TestCommandResultRefusedIsDropped(t *testing.T) {
	g := testgw.New(t)
	a := newAgent(t, g)
	a.st.CommandResults = []state.CommandResult{{CommandID: "0190f000-0000-7000-8000-0000000000c1", Status: "failed"}}
	g.ResultFail = http.StatusConflict
	a.Cycle(context.Background())
	if len(a.st.CommandResults) != 0 {
		t.Fatalf("kept %+v", a.st.CommandResults)
	}
}
