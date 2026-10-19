package app

import (
	"context"
	"log/slog"
	"slices"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/pkg/command"
	"github.com/phischl/paddock-mdm/pkg/protocol"
	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
	"github.com/phischl/paddock-mdm/server/internal/domain/device"
	"github.com/phischl/paddock-mdm/server/internal/domain/devicecommand"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/problem"
)

// Uninstalls are the uninstall use cases (ADR 0037 decision 4, plan M8d decisions 37 and 38): an organization
// administrator asks a device to remove Paddock with the signed command uninstall, and cancels the request while the
// device has not received it.
type Uninstalls struct {
	runner *ActionRunner
	org    *db.OrgPool
	cache  UninstallCache
	now    func() time.Time
}

// UninstallCache withdraws a cancelled uninstall from the gateway (devicecache.Cache): the result claim makes a later
// result of the device a conflict, and the command leaves cmd:<device_id>.
type UninstallCache interface {
	ClaimResult(ctx context.Context, device, id uuid.UUID, status string) (uuid.UUID, string, error)
	DeleteCommand(ctx context.Context, device, id uuid.UUID) error
}

// NewUninstalls creates the use cases.
func NewUninstalls(runner *ActionRunner, org *db.OrgPool, cache UninstallCache) *Uninstalls {
	return &Uninstalls{runner: runner, org: org, cache: cache, now: time.Now}
}

// UninstallReportTimeout is how long after the device received the command, or reported its result, an uninstall
// may stay without a removal report before an administrator can cancel or request it again: the helper runs from
// tmpfs (/run), so a reboot during the removal loses it and no report ever arrives (review finding 8).
const UninstallReportTimeout = 24 * time.Hour

// UninstallReportOverdue reports whether the device received the uninstall command (status delivered or succeeded)
// at least UninstallReportTimeout before now, counted from its result or else from the delivery; the caller checks
// that no removal report arrived.
func UninstallReportOverdue(status string, finishedAt, deliveredAt *time.Time, now time.Time) bool {
	at := finishedAt
	if at == nil {
		at = deliveredAt
	}
	return (status == devicecommand.StatusDelivered || status == devicecommand.StatusSucceeded) && at != nil &&
		now.Sub(*at) >= UninstallReportTimeout
}

func reportOverdue(cmd pgstore.DeviceCommand, now time.Time) bool {
	return UninstallReportOverdue(cmd.Status, cmd.FinishedAt, cmd.DeliveredAt, now)
}

// Specs of the uninstall actions.
var (
	SpecUninstallRequest = ActionSpec{Code: audit.CodeDeviceUninstallRequested, AllowedRoles: RolesAdmin, RequiresStepUp: true}
	SpecUninstallCancel  = ActionSpec{Code: audit.CodeDeviceUninstallCancelled, AllowedRoles: RolesAdmin}
)

// UninstallInput is an uninstall request.
type UninstallInput struct {
	Mode            string // command.UninstallLeave or command.UninstallReset
	ConfirmHostname string
	Reason          string
	ClearTPM        bool // reset only
	KeepLocalAdmin  bool // reset only
}

// Uninstall reasons are bounded like those of Lock and Destroy.
const (
	minUninstallReason = 2
	maxUninstallReason = 500
)

// Request issues the command uninstall to an active device (audited: device.uninstall_requested, with a step-up).
func (u *Uninstalls) Request(ctx context.Context, deviceID uuid.UUID, in UninstallInput) (pgstore.Device, error) {
	spec := SpecUninstallRequest
	spec.Target = &audit.Target{Type: "device", ID: deviceID.String()}
	spec.Params = map[string]any{"mode": in.Mode, "clear_tpm": in.ClearTPM, "keep_local_admin": in.KeepLocalAdmin, "reason": in.Reason}
	var out pgstore.Device
	var withdrawn uuid.UUID
	err := u.runner.RunTx(ctx, ScopeOrg, spec, func(ctx context.Context, q *pgstore.Queries, rec Recorder) error {
		// overdue is the delivered command of an overdue request, withdrawn only after every check passed: the result
		// claim lives in Valkey and survives a rollback (review 3 finding G).
		var overdue pgstore.DeviceCommand
		dev, err := q.LockDevice(ctx, deviceID)
		if err != nil {
			return notFound(err)
		}
		rec.SetTarget(audit.Target{Type: "device", ID: deviceID.String(), Display: dev.Hostname})
		rec.SetParam("hostname", dev.Hostname)
		if in.Mode != command.UninstallLeave && in.Mode != command.UninstallReset {
			return problem.InvalidRequestUnprocessed.WithDetail("mode must be leave or reset")
		}
		if n := utf8.RuneCountInString(in.Reason); n < minUninstallReason || n > maxUninstallReason {
			return problem.InvalidRequestUnprocessed.WithDetail("reason must have 2 to 500 characters")
		}
		if dev.State != device.StateActive {
			return problem.InvalidState.WithDetail("only active devices can be uninstalled")
		}
		if in.ConfirmHostname != dev.Hostname {
			return problem.InvalidRequestUnprocessed.WithDetail("confirm_hostname does not match")
		}
		if dev.UninstallRequestedAt != nil && dev.UninstalledAt == nil {
			open, err := q.GetDeviceCommand(ctx, dev.UninstallCommandID.UUID)
			if err != nil && !db.IsNoRows(err) {
				return err
			}
			if err != nil || !reportOverdue(open, u.now()) {
				return problem.InvalidState.WithDetail("an uninstall is already requested")
			}
			rec.SetParam("report_overdue", true)
			if open.Status == devicecommand.StatusDelivered {
				overdue = open
			}
		}
		revoking, err := q.DeviceHasOpenRevocation(ctx, deviceID)
		if err != nil {
			return err
		}
		if revoking {
			return problem.InvalidState.WithDetail("a lock or destroy is pending for this device")
		}
		if in.Mode == command.UninstallLeave && (in.ClearTPM || in.KeepLocalAdmin) {
			return problem.InvalidRequestUnprocessed.WithDetail("clear_tpm and keep_local_admin apply to mode reset only")
		}
		if in.ClearTPM {
			inUse, err := tpmInUse(ctx, q, deviceID)
			if err != nil {
				return err
			}
			if inUse {
				return problem.TPMInUseByDisk.WithDetail("the disk unlocks with the TPM; clearing it would leave only the recovery key")
			}
		}
		params := map[string]any{"mode": in.Mode}
		if in.ClearTPM {
			params["clear_tpm"] = true
		}
		if in.KeepLocalAdmin {
			params["keep_local_admin"] = true
		}
		now := u.now()
		if overdue.ID != uuid.Nil {
			claimed, ok, err := withdrawUninstallCommand(ctx, q, u.cache, deviceID, overdue, now)
			if err != nil {
				return err
			}
			if claimed != "" {
				return problem.InvalidState.WithDetail("the device already reported a result")
			}
			if !ok {
				return errCommandFinished()
			}
			withdrawn = overdue.ID
		}
		cmd, err := issueCommand(ctx, q, rec, deviceID, command.TypeUninstall, params, now, nil)
		if err != nil {
			return err
		}
		requested := now.UTC()
		out, err = q.SetDeviceUninstall(ctx, pgstore.SetDeviceUninstallParams{ID: deviceID, RequestedAt: &requested,
			Mode: &in.Mode, CommandID: uuid.NullUUID{UUID: cmd.ID, Valid: true}})
		return err
	})
	if err == nil {
		dropWithdrawnCommand(ctx, u.cache, deviceID, withdrawn)
	}
	return out, err
}

// tpmInUse reports whether the last health report lists a TPM keyslot on any volume of the device.
func tpmInUse(ctx context.Context, q *pgstore.Queries, deviceID uuid.UUID) (bool, error) {
	status, err := q.GetDeviceStatus(ctx, deviceID)
	if db.IsNoRows(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	disk := diskHealth(status.Health)
	if disk == nil {
		return false, nil
	}
	tpm := func(tokens []string) bool {
		return slices.ContainsFunc(tokens, func(t string) bool { return t == "tpm2" || t == "tpm2+pin" })
	}
	return tpm(disk.Tokens) || slices.ContainsFunc(disk.Volumes, func(v protocol.DiskVolume) bool { return tpm(v.Tokens) }), nil
}

// Cancel withdraws an uninstall the device has not received (audited: device.uninstall_cancelled): the command is
// cancelled, its result is claimed as cancelled in the same transaction (a result the device posts afterwards is a
// conflict, so the agent never starts the removal; one it posted first refuses the cancel), and after the commit the
// command leaves cmd:<device_id> so the gateway no longer delivers it. A request whose removal report is overdue
// (UninstallReportTimeout) is withdrawn as well, with the param report_overdue: a delivered command the same way, a
// succeeded one stays as it is (the helper ran or died, runbook uninstall.md).
func (u *Uninstalls) Cancel(ctx context.Context, deviceID uuid.UUID) (pgstore.Device, error) {
	spec := SpecUninstallCancel
	spec.Target = &audit.Target{Type: "device", ID: deviceID.String()}
	var out pgstore.Device
	var withdrawn uuid.UUID
	err := u.runner.RunTx(ctx, ScopeOrg, spec, func(ctx context.Context, q *pgstore.Queries, rec Recorder) error {
		dev, err := q.LockDevice(ctx, deviceID)
		if err != nil {
			return notFound(err)
		}
		rec.SetTarget(audit.Target{Type: "device", ID: deviceID.String(), Display: dev.Hostname})
		rec.SetParam("hostname", dev.Hostname)
		if dev.UninstallRequestedAt == nil || !dev.UninstallCommandID.Valid {
			return problem.InvalidState.WithDetail("no uninstall is requested")
		}
		if dev.UninstallMode != nil {
			rec.SetParam("mode", *dev.UninstallMode)
		}
		rec.SetParam("command_id", dev.UninstallCommandID.UUID.String())
		if dev.UninstalledAt != nil {
			return problem.InvalidState.WithDetail("the uninstall completed")
		}
		cmd, err := q.GetDeviceCommand(ctx, dev.UninstallCommandID.UUID)
		if err != nil {
			return err
		}
		now := u.now()
		overdue := reportOverdue(cmd, now)
		if overdue {
			rec.SetParam("report_overdue", true)
		}
		switch {
		case cmd.Status == devicecommand.StatusSucceeded && overdue:
		case cmd.Status == devicecommand.StatusPending || (cmd.Status == devicecommand.StatusDelivered && overdue):
			claimed, ok, err := withdrawUninstallCommand(ctx, q, u.cache, deviceID, cmd, now)
			if err != nil {
				return err
			}
			if claimed != "" && cmd.Status == devicecommand.StatusPending {
				return problem.InvalidState.WithDetail("the device already received the command")
			}
			if claimed != "" {
				return problem.InvalidState.WithDetail("the device already reported a result")
			}
			if !ok {
				return errCommandFinished()
			}
			withdrawn = cmd.ID
		case cmd.Status == devicecommand.StatusDelivered:
			return problem.InvalidState.WithDetail("the device already received the command")
		case cmd.Status == devicecommand.StatusSucceeded:
			return problem.InvalidState.WithDetail("the uninstall completed")
		default:
			n, err := q.CancelDeviceCommand(ctx, pgstore.CancelDeviceCommandParams{ID: cmd.ID, FinishedAt: now.UTC()})
			if err != nil {
				return err
			}
			if n != 1 {
				return problem.InvalidState.WithDetail("the command can no longer be cancelled")
			}
			withdrawn = cmd.ID
		}
		out, err = q.ClearDeviceUninstall(ctx, deviceID)
		return err
	})
	if err == nil {
		dropWithdrawnCommand(ctx, u.cache, deviceID, withdrawn)
	}
	return out, err
}

// withdrawUninstallCommand cancels an uninstall command without a result (pending or delivered): it claims the
// result as cancelled first, so a result the device posts afterwards is a conflict and the agent never starts the
// removal, then cancels the command. When the device's result was claimed first it returns that status and leaves
// the command as it is. withdrawn is false also when the command already has a result although the claim was won:
// the gateway publishes a result before it claims it, so the worker may have recorded it meanwhile. The caller
// decides whether either refuses its action and runs dropWithdrawnCommand after the commit.
func withdrawUninstallCommand(ctx context.Context, q *pgstore.Queries, cache UninstallCache, deviceID uuid.UUID,
	cmd pgstore.DeviceCommand, now time.Time) (claimed string, withdrawn bool, err error) {
	owner, status, err := cache.ClaimResult(ctx, deviceID, cmd.ID, devicecommand.StatusCancelled)
	if err != nil {
		return "", false, err
	}
	if owner != deviceID || status != devicecommand.StatusCancelled {
		return status, false, nil
	}
	n, err := q.WithdrawDeviceCommand(ctx, pgstore.WithdrawDeviceCommandParams{ID: cmd.ID, FinishedAt: now.UTC()})
	if err != nil {
		return "", false, err
	}
	return "", n == 1, nil
}

// errCommandFinished refuses a cancel of an uninstall command that got its result while it was withdrawn.
func errCommandFinished() error {
	return problem.InvalidState.WithDetail("the command can no longer be cancelled")
}

// dropWithdrawnCommand removes a withdrawn command (uuid.Nil: none) from cmd:<device_id>, so the gateway no longer
// delivers it.
func dropWithdrawnCommand(ctx context.Context, cache UninstallCache, deviceID, id uuid.UUID) {
	if id == uuid.Nil {
		return
	}
	if err := cache.DeleteCommand(ctx, deviceID, id); err != nil {
		// The result claim already makes the device's result a conflict; the worker's command round removes it.
		slog.WarnContext(ctx, "removing the withdrawn uninstall from the device cache failed", "device_id", deviceID,
			"command_id", id, "error", err)
	}
}
