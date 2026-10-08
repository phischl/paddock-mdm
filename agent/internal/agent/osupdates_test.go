package agent

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/agent/internal/commands"
	"github.com/phischl/paddock-mdm/agent/internal/osupdates"
	"github.com/phischl/paddock-mdm/agent/internal/reconcile"
	"github.com/phischl/paddock-mdm/agent/internal/state"
	"github.com/phischl/paddock-mdm/agent/internal/testgw"
	"github.com/phischl/paddock-mdm/pkg/bundle"
	"github.com/phischl/paddock-mdm/pkg/command"
	"github.com/phischl/paddock-mdm/pkg/protocol"
)

// TestInstallNow (plan M5b decision 7): the command is executed by the install worker, an installed package is only
// upgraded, a missing one installed, and the result is sent at the next check-in.
func TestInstallNow(t *testing.T) {
	g := testgw.New(t)
	a := newAgent(t, g)
	sys := withSystem(t, a)
	sys.Packages["curl"], sys.Versions["curl"] = true, "8.5.0-1"
	sys.AptVersion = "2.0-1"
	a.current = &bundle.Bundle{SchemaVersion: 2, Keys: testgw.CommandKeys()}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go a.runInstalls(ctx)
	now := time.Now().UTC()
	params, _ := json.Marshal(command.InstallNowParams{Packages: []string{"curl", "htop"}})
	g.Mu.Lock()
	g.Checkin.Commands = []json.RawMessage{testgw.SignedCommand(t, command.Command{CommandID: "0190f000-0000-7000-8000-0000000000d1",
		DeviceID: testgw.DeviceID, OrganizationID: testgw.OrgID, Type: command.TypeInstallNow, Params: params, IssuedAt: now, ExpiresAt: now.Add(time.Hour)})}
	g.Mu.Unlock()
	a.Cycle(ctx)
	g.Mu.Lock()
	g.Checkin.Commands = nil
	g.Mu.Unlock()
	select {
	case d := <-a.installDone:
		a.finishInstall(d)
	case <-time.After(5 * time.Second):
		t.Fatal("install worker did not finish")
	}
	a.Cycle(ctx)
	r, ok := g.Results["0190f000-0000-7000-8000-0000000000d1"]
	if !ok || r.Status != protocol.CommandSucceeded {
		t.Fatalf("results %+v", g.Results)
	}
	var res command.InstallNowResult
	if err := json.Unmarshal(r.Result, &res); err != nil || !slices.Equal(res.Installed, []string{"curl", "htop"}) || len(res.Failed) != 0 {
		t.Fatalf("result %s %v", r.Result, err)
	}
	calls := sys.TakeCalls()
	if !slices.Contains(calls, "apt-get update") || !slices.Contains(calls, "apt-get install curl") || !slices.Contains(calls, "apt-get install htop") {
		t.Fatalf("calls %v", calls)
	}
}

func TestInstallNowRefusesInvalidPackages(t *testing.T) {
	a := newAgent(t, testgw.New(t))
	withSystem(t, a)
	params, _ := json.Marshal(command.InstallNowParams{Packages: []string{"-oAPT::Update::Pre-Invoke::=x"}})
	if status, result := a.installNowCommand(context.Background(), &command.Command{CommandID: "c", Params: params}); status != protocol.CommandFailed ||
		result["reason"] != "invalid_params" {
		t.Fatalf("%s %v", status, result)
	}
	if len(a.installJobs) != 0 {
		t.Fatal("queued an invalid command")
	}
}

func TestInstallPackagesFailure(t *testing.T) {
	a := newAgent(t, testgw.New(t))
	sys := withSystem(t, a)
	sys.FailCmd = "apt-get install"
	status, result := installPackages(context.Background(), sys, []string{"htop"}, func() bool { return true })
	if status != protocol.CommandFailed || result["reboot_required"] != true {
		t.Fatalf("%s %v", status, result)
	}
	if failed, _ := result["failed"].([]any); len(failed) != 1 || failed[0] != "htop" {
		t.Fatalf("result %v", result)
	}
}

// TestReportUpdateRuns (plan M5b decision 6): the regular run's result file and a finished apt-daily-upgrade.service
// each become one updates.run event.
func TestReportUpdateRuns(t *testing.T) {
	g := testgw.New(t)
	a := newAgent(t, g)
	sys := withSystem(t, a)
	ctx := context.Background()
	finished := time.Date(2026, 10, 10, 4, 12, 0, 0, time.UTC)
	if err := osupdates.WriteResult(a.d.Layout, protocol.UpdatesRun{Kind: protocol.UpdatesKindRegular, StartedAt: finished.Add(-10 * time.Minute),
		FinishedAt: finished, Upgraded: 3, HeldBack: []string{}, Result: protocol.UpdatesResultOK}); err != nil {
		t.Fatal(err)
	}
	log := a.d.Layout.UnattendedLog()
	if err := os.MkdirAll(filepath.Dir(log), 0o755); err != nil {
		t.Fatal(err)
	}
	start := time.Date(2026, 10, 10, 3, 20, 0, 0, time.Local)
	data := start.Format("2006-01-02 15:04:05") + ",000 INFO Starting unattended upgrades script\n" +
		start.Format("2006-01-02 15:04:05") + ",500 INFO Packages that will be upgraded: libssl3t64\n"
	if err := os.WriteFile(log, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
	exit := start.Add(5 * time.Minute)
	sys.Shows[reconcile.SecurityUnit] = "ExecMainStartTimestamp=@" + strconv.FormatInt(start.Unix(), 10) +
		"\nExecMainExitTimestamp=@" + strconv.FormatInt(exit.Unix(), 10) + "\nResult=success\n"

	a.reportUpdateRuns(ctx)
	a.reportUpdateRuns(ctx) // nothing new
	a.Cycle(ctx)
	var runs []protocol.UpdatesRun
	for _, e := range g.Events {
		if e.Type == protocol.EventUpdatesRun {
			var r protocol.UpdatesRun
			_ = json.Unmarshal(e.Data, &r)
			runs = append(runs, r)
		}
	}
	if len(runs) != 2 || runs[0].Kind != protocol.UpdatesKindRegular || runs[0].Upgraded != 3 ||
		runs[1].Kind != protocol.UpdatesKindSecurity || runs[1].Upgraded != 1 || !runs[1].FinishedAt.Equal(exit.UTC()) ||
		!runs[1].StartedAt.Equal(start.UTC()) || runs[1].Result != protocol.UpdatesResultOK {
		t.Fatalf("runs %+v", runs)
	}
	// A failed unit is a failed run.
	sys.Shows[reconcile.SecurityUnit] = "ExecMainStartTimestamp=@" + strconv.FormatInt(exit.Unix()+86000, 10) +
		"\nExecMainExitTimestamp=@" + strconv.FormatInt(exit.Unix()+86400, 10) + "\nResult=exit-code\n"
	a.reportUpdateRuns(ctx)
	a.Cycle(ctx)
	last := g.Events[len(g.Events)-1]
	var r protocol.UpdatesRun
	if _ = json.Unmarshal(last.Data, &r); last.Type != protocol.EventUpdatesRun || r.Result != protocol.UpdatesResultFailed {
		t.Fatalf("last event %s %+v", last.Type, r)
	}
}

// TestInstallNowInterruptedByARestart (review 2): an accepted install_now is kept in the agent state until it
// finished; a new agent on the same state reports it as failed with reason interrupted, runs nothing and forgets it.
func TestInstallNowInterruptedByARestart(t *testing.T) {
	g := testgw.New(t)
	a := newAgent(t, g)
	withSystem(t, a)
	params, _ := json.Marshal(command.InstallNowParams{Packages: []string{"htop"}})
	if status, _ := a.installNowCommand(context.Background(), &command.Command{CommandID: "c-restart", Params: params}); status != commands.Deferred {
		t.Fatalf("status %q", status)
	}
	// The agent stops before the worker ran the job.
	st, err := state.Load(a.d.Layout.State())
	if err != nil || len(st.PendingInstalls) != 1 || st.PendingInstalls[0].CommandID != "c-restart" {
		t.Fatalf("persisted %+v %v", st.PendingInstalls, err)
	}
	b := newAgent(t, g)
	b.d.Layout = a.d.Layout
	b.st = st
	sys := withSystem(t, b)
	b.reportInterruptedInstalls()
	if len(b.installJobs) != 0 || sys.Packages["htop"] || len(sys.TakeCalls()) != 0 {
		t.Fatal("an interrupted job was run")
	}
	st, err = state.Load(b.d.Layout.State())
	if err != nil || len(st.PendingInstalls) != 0 || len(st.CommandResults) != 1 {
		t.Fatalf("state %+v %v", st, err)
	}
	r := st.CommandResults[0]
	var res command.InstallNowResult
	if err := json.Unmarshal(r.Result, &res); err != nil || r.CommandID != "c-restart" || r.Status != protocol.CommandFailed ||
		res.Reason != "interrupted" || !slices.Equal(res.Failed, []string{"htop"}) {
		t.Fatalf("result %+v %s %v", r, r.Result, err)
	}
	b.Cycle(context.Background())
	if got, ok := g.Results["c-restart"]; !ok || got.Status != protocol.CommandFailed {
		t.Fatalf("results %+v", g.Results)
	}
}

// TestInstallPackagesRecoversDpkg (review 1): an installation interrupted earlier is finished with
// dpkg --configure -a and the install is retried; a cancelled context does not stop it.
func TestInstallPackagesRecoversDpkg(t *testing.T) {
	a := newAgent(t, testgw.New(t))
	sys := withSystem(t, a)
	sys.DpkgInterrupted = true
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	status, result := installPackages(context.WithoutCancel(ctx), sys, []string{"htop"}, func() bool { return false })
	if status != protocol.CommandSucceeded || !sys.Packages["htop"] {
		t.Fatalf("%s %v", status, result)
	}
	if calls := sys.TakeCalls(); !slices.Contains(calls, "dpkg --configure -a") {
		t.Fatalf("calls %v", calls)
	}
}
