package app

import (
	"context"
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
	now    func() time.Time
}

// NewUninstalls creates the use cases.
func NewUninstalls(runner *ActionRunner, org *db.OrgPool) *Uninstalls {
	return &Uninstalls{runner: runner, org: org, now: time.Now}
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
	err := u.runner.RunTx(ctx, ScopeOrg, spec, func(ctx context.Context, q *pgstore.Queries, rec Recorder) error {
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
			return problem.InvalidState.WithDetail("an uninstall is already requested")
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
		cmd, err := issueCommand(ctx, q, rec, deviceID, command.TypeUninstall, params, now, nil)
		if err != nil {
			return err
		}
		requested := now.UTC()
		out, err = q.SetDeviceUninstall(ctx, pgstore.SetDeviceUninstallParams{ID: deviceID, RequestedAt: &requested,
			Mode: &in.Mode, CommandID: uuid.NullUUID{UUID: cmd.ID, Valid: true}})
		return err
	})
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
// cancelled and the worker's command round removes it from cmd:<device_id>.
func (u *Uninstalls) Cancel(ctx context.Context, deviceID uuid.UUID) (pgstore.Device, error) {
	spec := SpecUninstallCancel
	spec.Target = &audit.Target{Type: "device", ID: deviceID.String()}
	var out pgstore.Device
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
		switch cmd.Status {
		case devicecommand.StatusDelivered:
			return problem.InvalidState.WithDetail("the device already received the command")
		case devicecommand.StatusSucceeded:
			return problem.InvalidState.WithDetail("the uninstall completed")
		}
		n, err := q.CancelDeviceCommand(ctx, pgstore.CancelDeviceCommandParams{ID: cmd.ID, FinishedAt: u.now().UTC()})
		if err != nil {
			return err
		}
		if n != 1 {
			return problem.InvalidState.WithDetail("the command can no longer be cancelled")
		}
		out, err = q.ClearDeviceUninstall(ctx, deviceID)
		return err
	})
	return out, err
}
