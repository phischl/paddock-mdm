package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"syscall"
	"time"

	"github.com/phischl/paddock-mdm/agent/internal/fsutil"
	"github.com/phischl/paddock-mdm/agent/internal/state"
	"github.com/phischl/paddock-mdm/agent/internal/uninstall"
	"github.com/phischl/paddock-mdm/pkg/command"
	"github.com/phischl/paddock-mdm/pkg/protocol"
)

// UninstallUnit is the transient unit the removal runs in, outside the supervisor's cgroup.
const UninstallUnit = "paddock-uninstall"

// revocationWindow: a revocation handed to paddock-revoke this recently refuses an uninstall (plan M8d decision 39).
const revocationWindow = 24 * time.Hour

// uninstallCommand accepts an uninstall command (plan M8d decision 39): it validates the params, refuses while a
// revocation was handed over within 24 hours or while an in-place encryption is pending (plan M8e decision 36),
// writes the plan and a copy of the running binary below /root/paddock-uninstall and marks the removal pending; the
// run loop starts it once the result was accepted.
func (a *Agent) uninstallCommand(ctx context.Context, c *command.Command) (string, map[string]any) {
	var p command.UninstallParams
	dec := json.NewDecoder(bytes.NewReader(c.Params))
	dec.DisallowUnknownFields()
	if dec.Decode(&p) != nil || (p.Mode != command.UninstallLeave && p.Mode != command.UninstallReset) ||
		(p.Mode == command.UninstallLeave && (p.ClearTPM || p.KeepLocalAdmin)) {
		return protocol.CommandFailed, map[string]any{"accepted": false, "reason": "invalid_params"}
	}
	now := a.d.Now()
	for _, at := range a.st.HandedRevocations {
		if now.Sub(at) < revocationWindow {
			return protocol.CommandFailed, map[string]any{"accepted": false, "reason": "revocation_pending"}
		}
	}
	if a.conversionPending(ctx) {
		return protocol.CommandFailed, map[string]any{"accepted": false, "reason": "conversion_pending"}
	}
	plan := uninstall.Plan{CommandID: c.CommandID, Mode: p.Mode, ClearTPM: p.ClearTPM, KeepLocalAdmin: p.KeepLocalAdmin,
		DeviceID: a.st.DeviceID, EventSeqBase: a.st.EventSeq, RequestedAt: c.IssuedAt}
	data, err := json.Marshal(plan)
	if err == nil {
		err = fsutil.WriteFile(a.d.Layout.UninstallPlan(), data, 0o600, 0o700)
	}
	if err == nil {
		err = a.copySelf()
	}
	if err != nil {
		slog.Error("preparing the uninstall failed", "command_id", c.CommandID, "error", err)
		return protocol.CommandFailed, map[string]any{"accepted": false, "reason": "helper_failed"}
	}
	a.st.PendingUninstall = &state.PendingUninstall{CommandID: c.CommandID, Mode: p.Mode}
	_ = a.persist()
	slog.Info("uninstall accepted; Paddock is removed once the result is reported", "command_id", c.CommandID, "mode", p.Mode)
	return protocol.CommandSucceeded, map[string]any{"accepted": true}
}

// copySelf copies the running paddockd to /root/paddock-uninstall/paddockd (0700): removing the paddock-agent package
// must not remove the binary the removal runs as.
func (a *Agent) copySelf() error {
	self := a.d.Executable
	if self == "" {
		var err error
		if self, err = os.Executable(); err != nil {
			return err
		}
	}
	bin, err := os.ReadFile(self) //nolint:gosec // the running binary
	if err != nil {
		return err
	}
	return fsutil.WriteFile(a.d.Layout.UninstallBinary(), bin, 0o700, 0o700)
}

// withdrawUninstall drops a pending uninstall whose result the server refused and removes its plan and binary copy.
func (a *Agent) withdrawUninstall(ctx context.Context) {
	p := a.st.PendingUninstall
	slog.WarnContext(ctx, "uninstall withdrawn by the server; Paddock stays installed", "command_id", p.CommandID)
	a.removeUninstallPreparation(ctx)
	a.st.PendingUninstall = nil
}

// removeUninstallPreparation removes the plan, the binary copy and the then empty directory of a removal that will
// not run.
func (a *Agent) removeUninstallPreparation(ctx context.Context) {
	uninstall.Discard(ctx, a.d.Layout.UninstallPlan(), a.d.Layout.UninstallBinary())
}

// launchUninstall starts the accepted removal once the server accepted its command result (2xx), exactly once.
// LaunchedAt is saved only after systemd-run succeeded, so a crash before the start retries it. A start that fails is
// reported as agent.uninstalled with outcome helper_failed, and the mark is cleared. The start waits while a supervisor
// upgrade runs: its helper restores and restarts the previous supervisor on a rollback, which would bring back what
// the removal purged; the agent counts an upgrade without a result as failed after supervisorpkg.StaleAfter, so the
// wait ends.
func (a *Agent) launchUninstall(ctx context.Context) {
	p := a.st.PendingUninstall
	if p == nil || p.LaunchedAt != nil || !p.Reported ||
		slices.ContainsFunc(a.st.CommandResults, func(r state.CommandResult) bool { return r.CommandID == p.CommandID }) {
		return
	}
	if a.supervisorUpgradeRuns(ctx, p.CommandID) {
		return
	}
	if err := a.helperExecutable(); err != nil {
		a.uninstallHelperFailed(ctx, err)
		return
	}
	err := a.d.RunUnit(ctx, "systemd-run", "--unit="+UninstallUnit, "--collect", "--no-block", "--property=KillMode=process",
		a.d.Layout.UninstallBinary(), "uninstall", "--plan", a.d.Layout.UninstallPlan())
	// The agent is being stopped (a supervisor restart cancels ctx and with it systemd-run): the start may not have
	// happened, and the next start launches the removal or adopts the running one instead of ending the request with
	// helper_failed.
	if err != nil && ctx.Err() != nil {
		slog.WarnContext(ctx, "starting the removal of Paddock interrupted; retrying at the next start", "command_id", p.CommandID, "error", err)
		return
	}
	// A crash between systemd-run and saving LaunchedAt reruns the launch while the removal still runs; systemd-run
	// then fails because the unit is loaded, and reporting helper_failed would end the request under the running
	// removal (review 2 finding E). The transient unit is Type=simple, so a running helper is active.
	if err != nil && a.d.RunUnit(ctx, "systemctl", "is-active", "--quiet", UninstallUnit+".service") == nil {
		slog.WarnContext(ctx, "the removal of Paddock is already running; adopting it", "command_id", p.CommandID, "error", err)
		err = nil
	}
	if err == nil {
		at := a.d.Now().UTC()
		p.LaunchedAt = &at
		a.saveState()
		slog.InfoContext(ctx, "removal of Paddock started", "command_id", p.CommandID, "unit", UninstallUnit)
		return
	}
	a.uninstallHelperFailed(ctx, err)
}

// uninstallHelperFailed reports a removal that could not be started as agent.uninstalled with outcome helper_failed,
// removes its preparation and clears the mark.
func (a *Agent) uninstallHelperFailed(ctx context.Context, err error) {
	p := a.st.PendingUninstall
	slog.ErrorContext(ctx, "starting the removal of Paddock failed", "command_id", p.CommandID, "error", err)
	a.event(protocol.EventAgentUninstalled, protocol.AgentUninstalled{CommandID: p.CommandID, Mode: p.Mode,
		Outcome: protocol.UninstallHelperFailed, LocalAdmin: uninstall.LocalAdminKept, TPM: uninstall.TPMNotRequested,
		Steps: map[string]string{}})
	a.removeUninstallPreparation(ctx)
	a.st.PendingUninstall = nil
	a.saveState()
}

// stNoexec is ST_NOEXEC of statvfs(3), which package syscall does not define.
const stNoexec = 0x8

// noexec reports whether the file system holding dir is mounted noexec.
func noexec(dir string) (bool, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {
		return false, err
	}
	return st.Flags&stNoexec != 0, nil
}

// helperExecutable fails when the binary copy cannot be executed where it lies: systemd-run then only reports
// "Permission denied", which names neither the mount nor the option.
func (a *Agent) helperExecutable() error {
	dir := filepath.Dir(a.d.Layout.UninstallBinary())
	off, err := a.d.NoExec(dir)
	if err != nil {
		return fmt.Errorf("check the mount options of %s: %w", dir, err)
	}
	if off {
		return fmt.Errorf("%s is on a file system mounted noexec; the removal helper cannot run from it", dir)
	}
	return nil
}

// supervisorUpgradeRuns reports whether a supervisor upgrade holds back the removal (see supervisorUpgradeHolds); the
// removal must not wait longer than the 30 minutes of the ADR 0037 amendment.
func (a *Agent) supervisorUpgradeRuns(ctx context.Context, commandID string) bool {
	holds, err := a.supervisorUpgradeHolds()
	if holds {
		slog.InfoContext(ctx, "removal of Paddock waits for the running supervisor upgrade", "command_id", commandID, "error", err)
		return true
	}
	if err != nil {
		slog.WarnContext(ctx, "unreadable supervisor upgrade marker is stale; starting the removal of Paddock",
			"command_id", commandID, "error", err)
	}
	return false
}
