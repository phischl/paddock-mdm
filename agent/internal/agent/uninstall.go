package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"slices"
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
// revocation was handed over within 24 hours, writes the plan and a copy of the running binary below
// /run/paddock/uninstall and marks the removal pending; the run loop starts it once the result was accepted.
func (a *Agent) uninstallCommand(_ context.Context, c *command.Command) (string, map[string]any) {
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

// copySelf copies the running paddockd to /run/paddock/uninstall/paddockd (0700): removing the paddock-agent package
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

// launchUninstall starts the accepted removal once its command result left CommandResults, exactly once. A start
// that fails is reported as agent.uninstalled with outcome helper_failed, and the mark is cleared.
func (a *Agent) launchUninstall(ctx context.Context) {
	p := a.st.PendingUninstall
	if p == nil || p.LaunchedAt != nil ||
		slices.ContainsFunc(a.st.CommandResults, func(r state.CommandResult) bool { return r.CommandID == p.CommandID }) {
		return
	}
	at := a.d.Now().UTC()
	p.LaunchedAt = &at
	a.saveState()
	err := a.d.RunUnit(ctx, "systemd-run", "--unit="+UninstallUnit, "--collect", "--no-block", "--property=KillMode=process",
		a.d.Layout.UninstallBinary(), "uninstall", "--plan", a.d.Layout.UninstallPlan())
	if err == nil {
		slog.InfoContext(ctx, "removal of Paddock started", "command_id", p.CommandID, "unit", UninstallUnit)
		return
	}
	slog.ErrorContext(ctx, "starting the removal of Paddock failed", "command_id", p.CommandID, "error", err)
	a.event(protocol.EventAgentUninstalled, protocol.AgentUninstalled{CommandID: p.CommandID, Mode: p.Mode,
		Outcome: protocol.UninstallHelperFailed, LocalAdmin: uninstall.LocalAdminKept, TPM: uninstall.TPMNotRequested,
		Steps: map[string]string{}})
	a.st.PendingUninstall = nil
	a.saveState()
}
