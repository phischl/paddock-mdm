package agent

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"slices"
	"strings"

	"github.com/phischl/paddock-mdm/agent/internal/commands"
	"github.com/phischl/paddock-mdm/agent/internal/health"
	"github.com/phischl/paddock-mdm/agent/internal/osupdates"
	"github.com/phischl/paddock-mdm/agent/internal/reconcile"
	"github.com/phischl/paddock-mdm/agent/internal/state"
	"github.com/phischl/paddock-mdm/pkg/bundle"
	"github.com/phischl/paddock-mdm/pkg/command"
	"github.com/phischl/paddock-mdm/pkg/protocol"
)

// installJob is an install_now command for the install worker; installDone its result.
type (
	installJob struct {
		commandID string
		packages  []string
	}
	installDone struct {
		commandID string
		status    string
		result    map[string]any
	}
)

// installQueue bounds the install_now commands waiting for the worker.
const installQueue = 8

// refreshRebootRequired puts the reboot marker into the health report of the next check-in (plan M5b decision 8).
func (a *Agent) refreshRebootRequired() {
	required := osupdates.RebootRequired(a.d.Layout)
	a.d.Health.Update(func(r *health.Report) { r.RebootRequired = required })
}

// reportUpdateRuns reports, once each, the last regular update run (paddockd updates run) and the last run of the
// daily security updates (apt-daily-upgrade.service), as updates.run (plan M5b decision 6).
func (a *Agent) reportUpdateRuns(ctx context.Context) {
	if r, err := osupdates.ReadResult(a.d.Layout); err != nil {
		slog.WarnContext(ctx, "reading the update result failed", "error", err)
	} else if r != nil && (a.st.ReportedRegularAt == nil || r.FinishedAt.After(*a.st.ReportedRegularAt)) {
		a.event(protocol.EventUpdatesRun, r)
		at := r.FinishedAt
		a.st.ReportedRegularAt = &at
		a.saveState()
	}
	if a.d.Sys == nil {
		return
	}
	out, exit, err := a.d.Sys.Systemctl(ctx, "show", "--timestamp=unix", "-p", "ActiveExitTimestamp,Result", reconcile.SecurityUnit)
	if err != nil || exit != 0 {
		return
	}
	exited, result, ok := osupdates.ParseUnitExit(out)
	if !ok || (a.st.ReportedSecurityAt != nil && !exited.After(*a.st.ReportedSecurityAt)) {
		return
	}
	log, err := os.ReadFile(a.d.Layout.UnattendedLog())
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		slog.WarnContext(ctx, "reading the unattended-upgrades log failed", "error", err)
	}
	run, found := osupdates.ParseUnattendedLog(log)
	if !found || run.StartedAt.After(exited) {
		run = protocol.UpdatesRun{Kind: protocol.UpdatesKindSecurity, StartedAt: exited, HeldBack: []string{}, Result: protocol.UpdatesResultOK}
	}
	run.FinishedAt, run.RebootRequired = exited, osupdates.RebootRequired(a.d.Layout)
	if result != "success" {
		run.Result = protocol.UpdatesResultFailed
		if run.Error == "" {
			run.Error = reconcile.SecurityUnit + ": " + result
		}
	}
	a.event(protocol.EventUpdatesRun, run)
	a.st.ReportedSecurityAt = &exited
	a.saveState()
}

// installNowCommand queues install_now for the install worker, which reports the result when the packages are
// installed: apt must not hold up the run loop (plan M5b decision 7).
func (a *Agent) installNowCommand(_ context.Context, c *command.Command) (string, map[string]any) {
	var p command.InstallNowParams
	if json.Unmarshal(c.Params, &p) != nil || len(p.Packages) == 0 || len(p.Packages) > command.MaxInstallPackages {
		return protocol.CommandFailed, map[string]any{"reason": "invalid_params"}
	}
	for _, pkg := range p.Packages {
		if !bundle.ValidPackage(pkg) {
			return protocol.CommandFailed, map[string]any{"reason": "invalid_params"}
		}
	}
	if a.d.Sys == nil {
		return protocol.CommandFailed, map[string]any{"reason": "unsupported"}
	}
	select {
	case a.installJobs <- installJob{commandID: c.CommandID, packages: p.Packages}:
		return commands.Deferred, nil
	default:
		return protocol.CommandFailed, map[string]any{"reason": "busy"}
	}
}

// runInstalls executes the queued install_now commands one after another until ctx ends.
func (a *Agent) runInstalls(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case job := <-a.installJobs:
			status, result := installPackages(ctx, a.d.Sys, job.packages, func() bool { return osupdates.RebootRequired(a.d.Layout) })
			select {
			case a.installDone <- installDone{commandID: job.commandID, status: status, result: result}:
			case <-ctx.Done():
				return
			}
		}
	}
}

// finishInstall keeps the result of an install_now command until the server accepted it.
func (a *Agent) finishInstall(d installDone) {
	slog.Info("install_now finished", "command_id", d.commandID, "status", d.status)
	a.st.CommandResults = append(a.st.CommandResults, state.CommandResult{CommandID: d.commandID, Status: d.status, Result: commands.Encode(d.result)})
	a.saveState()
}

// aptInstall are the options of install_now: apt waits for a dpkg lock held by another package operation and keeps
// changed configuration files.
var aptInstall = []string{"install", "-y", "-q", "-o", "DPkg::Lock::Timeout=600", "-o", "Dpkg::Options::=--force-confdef",
	"-o", "Dpkg::Options::=--force-confold"}

// installPackages refreshes the package lists, upgrades the installed packages among pkgs (--only-upgrade) and
// installs the others through the bounded package path, and returns the command status and result
// (command.InstallNowResult).
func installPackages(ctx context.Context, sys reconcile.System, pkgs []string, rebootRequired func() bool) (string, map[string]any) {
	r := command.InstallNowResult{Installed: []string{}, Failed: []string{}}
	var upgrade, install []string
	for _, p := range pkgs {
		if sys.PackageInstalled(p) {
			upgrade = append(upgrade, p)
		} else {
			install = append(install, p)
		}
	}
	timedOut := false
	aptRun := func(args ...string) bool {
		out, exit, err := sys.AptGet(ctx, args...)
		if errors.Is(err, context.DeadlineExceeded) {
			timedOut = true
		}
		if err != nil || exit != 0 {
			slog.WarnContext(ctx, "install_now: apt-get failed", "args", strings.Join(args, " "), "exit", exit, "error", err,
				"output", lastOutputLine(out))
			return false
		}
		return true
	}
	aptRun("update", "-q", "-o", "DPkg::Lock::Timeout=600")
	var failed []string
	if len(upgrade) > 0 && (timedOut || !aptRun(append(append(append([]string{}, aptInstall...), "--only-upgrade", "--"), upgrade...)...)) {
		failed = upgrade
	}
	if len(install) > 0 && !timedOut {
		aptRun(append(append(append([]string{}, aptInstall...), "--"), install...)...)
	}
	for _, p := range pkgs {
		if sys.PackageInstalled(p) && !slices.Contains(failed, p) {
			r.Installed = append(r.Installed, p)
		} else {
			r.Failed = append(r.Failed, p)
		}
	}
	if timedOut {
		r.Reason = "timeout"
	}
	r.RebootRequired = rebootRequired()
	status := protocol.CommandSucceeded
	if len(r.Failed) > 0 || timedOut {
		status = protocol.CommandFailed
	}
	raw, _ := json.Marshal(r)
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	return status, out
}

func lastOutputLine(out string) string {
	lines := strings.Split(strings.TrimSpace(out), "\n")
	return lines[len(lines)-1]
}
