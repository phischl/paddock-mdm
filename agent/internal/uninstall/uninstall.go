// Package uninstall is `paddockd uninstall --plan <file>` (ADR 0037 decision 4, plan M8d decision 40): it removes
// Paddock from the device in a transient systemd unit, step by step, reports the outcome once and leaves a summary in
// /root/paddock-uninstall/. It never deletes user data, never touches LUKS keyslots, /etc/crypttab, /etc/fstab, the
// ESP or the boot loader, and never changes the revocation code (it removes the paddock-revoke package like any
// package).
package uninstall

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/phischl/paddock-mdm/agent/internal/fsutil"
	"github.com/phischl/paddock-mdm/pkg/command"
	"github.com/phischl/paddock-mdm/pkg/protocol"
)

// Plan is /root/paddock-uninstall/plan.json, written by the agent when it accepted the command.
type Plan struct {
	CommandID      string    `json:"command_id"`
	Mode           string    `json:"mode"`
	ClearTPM       bool      `json:"clear_tpm"`
	KeepLocalAdmin bool      `json:"keep_local_admin"`
	DeviceID       string    `json:"device_id"`
	EventSeqBase   int64     `json:"event_seq_base"`
	RequestedAt    time.Time `json:"requested_at"`
}

// Validate checks the plan the agent wrote.
func (p Plan) Validate() error {
	if p.CommandID == "" || p.DeviceID == "" {
		return fmt.Errorf("uninstall: plan without command or device")
	}
	if p.Mode != command.UninstallLeave && p.Mode != command.UninstallReset {
		return fmt.Errorf("uninstall: unknown mode %q", p.Mode)
	}
	if p.Mode == command.UninstallLeave && (p.ClearTPM || p.KeepLocalAdmin) {
		return fmt.Errorf("uninstall: clear_tpm and keep_local_admin apply to mode reset only")
	}
	return nil
}

// ReadPlan reads a plan file.
func ReadPlan(path string) (Plan, error) {
	var p Plan
	data, err := os.ReadFile(path) //nolint:gosec // the plan path the agent passed
	if err != nil {
		return p, err
	}
	if err := json.Unmarshal(data, &p); err != nil {
		return p, fmt.Errorf("parse %s: %w", path, err)
	}
	return p, p.Validate()
}

// Steps in the order they run; the keys of AgentUninstalled.Steps.
const (
	StepStop        = "stop_services"
	StepUpdates     = "update_configuration"
	StepAccess      = "sudoers_and_notices"
	StepQuarantine  = "quarantine_copy"
	StepManaged     = "managed_files"
	StepHimmelblau  = "himmelblau"
	StepLocalAdmin  = "local_admin"
	StepPackages    = "packages"
	StepTPM         = "tpm"
	stepDone        = "done"
	stepSkipped     = "skipped"
	stepFailedLabel = "failed:"
)

// Results of the managed local administrator and of the TPM in AgentUninstalled.
const (
	LocalAdminRemoved       = "removed"
	LocalAdminKept          = "kept"
	LocalAdminKeptLastAdmin = "kept_last_admin"
	TPMCleared              = "cleared"
	TPMRequestedAtNextBoot  = "requested_at_next_boot"
	TPMSkippedInUse         = "skipped_in_use"
	TPMNotRequested         = "not_requested"
	TPMFailed               = "failed"
)

// ResultDir keeps the quarantine copy and the summary (0700), and until the summary is written the plan and the binary
// copy the helper runs as; the only place below /root the helper writes.
const ResultDir = "/root/paddock-uninstall"

// Runner runs a tool non-interactively in a process group of its own, killed with the group at timeout; exit is -1
// with an error wrapping context.DeadlineExceeded then.
type Runner func(ctx context.Context, timeout time.Duration, name string, args ...string) (output string, exit int, err error)

// Helper removes Paddock. Root is "/" on a device and a temporary directory in tests; every path below is a device
// path.
type Helper struct {
	Root string
	Run  Runner
	Now  func() time.Time
	// Sleep waits d or until ctx ends (the report's back-off).
	Sleep func(ctx context.Context, d time.Duration) error
	// TPM re-checks the volumes and clears the TPM (tpm.go); nil on a device builds the real one.
	TPM TPM
	// Send delivers events to the server with the device's identity; ReportFor bounds the retries.
	Send      func(ctx context.Context, events []protocol.Event) error
	ReportFor time.Duration
	// LocalAdmin is the managed local administrator of the agent state ("" when there is none).
	LocalAdmin string
	// EventSeq reads the agent state's last event sequence number. The report calls it after the agent was stopped:
	// events the agent spooled and delivered while the helper started would otherwise share the final event's
	// sequence number, and the server drops a seen (device, event_seq) without a trace.
	EventSeq func() int64
	// Preparation is the plan and the binary copy the agent left for the helper, removed once the summary was written;
	// paths as given, not below Root.
	Preparation []string
}

// Summary is /root/paddock-uninstall/result.json and the data of the final event.
type Summary struct {
	protocol.AgentUninstalled
	Delivered bool      `json:"delivered"`
	At        time.Time `json:"at"`
}

func (h *Helper) path(p string) string { return filepath.Join(h.Root, p) }

// Execute runs every step of plan in order, reports the outcome, removes Paddock's state and configuration
// directories and writes the summary. A failed step never stops the following ones.
func (h *Helper) Execute(ctx context.Context, plan Plan) Summary {
	s := Summary{AgentUninstalled: protocol.AgentUninstalled{CommandID: plan.CommandID, Mode: plan.Mode, Steps: map[string]string{},
		LocalAdmin: LocalAdminKept, TPM: TPMNotRequested}}
	reset := plan.Mode == command.UninstallReset
	s.Steps[StepStop] = h.stopServices(ctx)
	s.Steps[StepUpdates] = h.updateConfiguration(ctx)
	s.Steps[StepAccess] = h.sudoersAndNotices(ctx)
	s.Steps[StepQuarantine] = h.quarantineCopy()
	s.Steps[StepManaged] = skipUnless(reset, func() string { return h.managedFiles(ctx) })
	s.Steps[StepHimmelblau] = skipUnless(reset, func() string { return h.himmelblau(ctx) })
	s.Steps[StepLocalAdmin] = stepSkipped
	if reset && !plan.KeepLocalAdmin {
		s.LocalAdmin, s.Steps[StepLocalAdmin] = h.localAdmin(ctx)
	}
	s.Steps[StepPackages] = h.packages(ctx)
	s.Steps[StepTPM] = stepSkipped
	if reset && plan.ClearTPM {
		s.TPM, s.Steps[StepTPM] = h.clearTPM(ctx)
	}
	s.Outcome = protocol.UninstallCompleted
	for _, st := range s.Steps {
		if strings.HasPrefix(st, stepFailedLabel) {
			s.Outcome = protocol.UninstallPartial
		}
	}
	s.Delivered = h.report(ctx, plan, s.AgentUninstalled)
	for _, dir := range []string{"/var/lib/paddock", "/etc/paddock"} {
		if err := os.RemoveAll(h.path(dir)); err != nil {
			slog.ErrorContext(ctx, "removing a Paddock directory failed", "path", dir, "error", err)
		}
	}
	s.At = h.Now().UTC()
	data, _ := json.MarshalIndent(s, "", "  ")
	if err := fsutil.WriteFile(h.path(filepath.Join(ResultDir, "result.json")), append(data, '\n'), 0o600, 0o700); err != nil {
		slog.ErrorContext(ctx, "writing the uninstall summary failed", "error", err)
	}
	for _, f := range h.Preparation {
		if err := os.Remove(f); err != nil && !errors.Is(err, os.ErrNotExist) {
			slog.ErrorContext(ctx, "removing the uninstall preparation failed", "file", f, "error", err)
		}
	}
	slog.InfoContext(ctx, "Paddock removed", "command_id", plan.CommandID, "mode", plan.Mode, "outcome", s.Outcome,
		"local_admin", s.LocalAdmin, "tpm", s.TPM, "reported", s.Delivered, "summary", filepath.Join(ResultDir, "result.json"))
	return s
}

// Discard removes the preparation of a removal that does not run, then its directory if nothing else lies in it: a
// summary or a quarantine copy of an earlier removal keeps it. Below /root nothing clears it at a reboot, unlike /run.
func Discard(ctx context.Context, files ...string) {
	dirs := map[string]bool{}
	for _, f := range files {
		if err := os.Remove(f); err != nil && !errors.Is(err, os.ErrNotExist) {
			slog.WarnContext(ctx, "removing the uninstall preparation failed", "file", f, "error", err)
		}
		dirs[filepath.Dir(f)] = true
	}
	for dir := range dirs {
		if err := os.Remove(dir); err != nil && !errors.Is(err, os.ErrNotExist) && !errors.Is(err, syscall.ENOTEMPTY) {
			slog.WarnContext(ctx, "removing the uninstall directory failed", "path", dir, "error", err)
		}
	}
}

func skipUnless(run bool, step func() string) string {
	if !run {
		return stepSkipped
	}
	return step()
}

// failed is the status of a failed step; the message is cut so the event stays within the server's bounds.
func failed(format string, args ...any) string {
	msg := fmt.Sprintf(format, args...)
	if len(msg) > 200 {
		msg = msg[:200]
	}
	return stepFailedLabel + msg
}

// run runs a tool with the package timeout and returns an error for a non-zero exit with the last output line.
func (h *Helper) run(ctx context.Context, name string, args ...string) error {
	out, exit, err := h.Run(ctx, packageTimeout, name, args...)
	if err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	if exit != 0 {
		lines := strings.Split(strings.TrimSpace(out), "\n")
		return fmt.Errorf("%s %s: exit %d: %s", name, strings.Join(args, " "), exit, lines[len(lines)-1])
	}
	return nil
}

// packageTimeout bounds every tool run, apt-get included (the agent's PackageTimeout).
const packageTimeout = 15 * time.Minute
