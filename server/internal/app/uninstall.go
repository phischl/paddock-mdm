package app

import (
	"context"
	"encoding/json"
	"fmt"
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
	"github.com/phischl/paddock-mdm/server/internal/ingest"
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
// result of the device a conflict, and the command leaves cmd:<device_id>; a claim of a rolled-back withdrawal is
// released.
type UninstallCache interface {
	ClaimResult(ctx context.Context, device, id uuid.UUID, status string) (uuid.UUID, string, error)
	ReleaseResult(ctx context.Context, device, id uuid.UUID, status string) (bool, error)
	DeleteCommand(ctx context.Context, device, id uuid.UUID) error
}

// NewUninstalls creates the use cases.
func NewUninstalls(runner *ActionRunner, org *db.OrgPool, cache UninstallCache) *Uninstalls {
	return &Uninstalls{runner: runner, org: org, cache: cache, now: time.Now}
}

// UninstallReasonOrganizationOffboarding marks the uninstall the deletion of the organization issued
// (device.uninstall_reason, plan M17 amendment e point 1).
const UninstallReasonOrganizationOffboarding = "organization_offboarding"

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
	claims := newResultClaims(u.cache, deviceID)
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
		if err := refuseActiveConversion(ctx, q, deviceID); err != nil {
			return err
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
			claimed, ok, err := withdrawUninstallCommand(ctx, q, u.cache, claims, deviceID, overdue, now)
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
	claims.releaseOn(ctx, err)
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
	claims := newResultClaims(u.cache, deviceID)
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
		if dev.UninstallReason != nil && *dev.UninstallReason == UninstallReasonOrganizationOffboarding {
			return problem.InvalidState.WithDetail("the uninstall belongs to the organization's deletion; only cancelling the deletion withdraws it")
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
			claimed, ok, err := withdrawUninstallCommand(ctx, q, u.cache, claims, deviceID, cmd, now)
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
	claims.releaseOn(ctx, err)
	if err == nil {
		dropWithdrawnCommand(ctx, u.cache, deviceID, withdrawn)
	}
	return out, err
}

// requestForOffboarding issues the command uninstall (mode leave) to every active device of the context's
// organization for its deletion and marks each request with the reason organization_offboarding (plan M17 decision 3,
// amendment e points 1, 2 and 5). It runs in one transaction with a constant number of statements, so a failed
// request leaves no device with an uninstall. It records no audit event: the platform administrator's
// organization.deletion_requested stands for every device. A device with an open uninstall or an open Lock or Destroy
// is skipped and counted. The commands expire at expiresAt instead of after the uninstall's default lifetime, and no
// command.issued message is queued (the action is a platform action whose outbox rows belong to the platform
// pseudo-organization): the worker's command round publishes them within one interval. Only
// Organizations.RequestDeletion calls it.
func (u *Uninstalls) requestForOffboarding(ctx context.Context, expiresAt time.Time) (issued, skipped int, err error) {
	params, err := json.Marshal(command.UninstallParams{Mode: command.UninstallLeave})
	if err != nil {
		return 0, 0, err
	}
	err = u.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		locked, err := q.LockActiveDevicesForOffboarding(ctx)
		if err != nil {
			return fmt.Errorf("lock active devices: %w", err)
		}
		now := u.now().UTC()
		cmds, err := q.InsertOffboardingUninstalls(ctx, pgstore.InsertOffboardingUninstallsParams{
			Params: params, IssuedAt: now.Truncate(time.Second), ExpiresAt: expiresAt, LockedIds: locked,
		})
		if err != nil {
			return fmt.Errorf("insert commands: %w", err)
		}
		ids := make([]uuid.UUID, len(cmds))
		for i, c := range cmds {
			ids[i] = c.ID
		}
		n, err := q.SetOffboardingUninstalls(ctx, pgstore.SetOffboardingUninstallsParams{RequestedAt: now, CommandIds: ids})
		if err != nil {
			return fmt.Errorf("set uninstall requests: %w", err)
		}
		if n != int64(len(cmds)) {
			return fmt.Errorf("app: %d uninstall requests set for %d commands", n, len(cmds))
		}
		issued, skipped = len(cmds), len(locked)-len(cmds)
		return nil
	})
	if err != nil {
		return 0, 0, err
	}
	return issued, skipped, nil
}

// cancelForOffboarding withdraws the offboarding uninstalls of the context's organization that its devices have not
// received, in one transaction with a constant number of statements and without audit events (plan M17 amendment e
// points 3 and 6: the platform administrator's organization.deletion_cancelled stands for every device). A pending
// command's result is claimed as cancelled first, as Cancel does it, so the device's later result is a conflict; a
// failed or expired command is cancelled; a delivered or succeeded one runs to completion. It returns the number of
// requests it ended. When it fails, the claims it won are released. Only Organizations.CancelDeletion calls it.
func (u *Uninstalls) cancelForOffboarding(ctx context.Context) (cancelled int, err error) {
	var withdrawn []pgstore.CancelOffboardingCommandsRow
	var claims []*resultClaims
	err = u.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		withdrawn = nil
		open, err := q.LockOffboardingUninstalls(ctx)
		if err != nil {
			return fmt.Errorf("lock offboarding uninstalls: %w", err)
		}
		var ids []uuid.UUID
		claimed := map[uuid.UUID]*resultClaims{}
		for _, o := range open {
			switch o.Status {
			case devicecommand.StatusPending:
				owner, status, err := u.cache.ClaimResult(ctx, o.DeviceID, o.CommandID, devicecommand.StatusCancelled)
				if err != nil {
					return err
				}
				if owner != o.DeviceID || status != devicecommand.StatusCancelled {
					continue
				}
				c := newResultClaims(u.cache, o.DeviceID)
				c.won(o.CommandID)
				claims = append(claims, c)
				claimed[o.CommandID] = c
				ids = append(ids, o.CommandID)
			case devicecommand.StatusFailed, devicecommand.StatusExpired:
				ids = append(ids, o.CommandID)
			}
		}
		if len(ids) == 0 {
			return nil
		}
		withdrawn, err = q.CancelOffboardingCommands(ctx, pgstore.CancelOffboardingCommandsParams{
			Ids: ids, FinishedAt: u.now().UTC(),
		})
		if err != nil {
			return fmt.Errorf("cancel commands: %w", err)
		}
		devices := make([]uuid.UUID, len(withdrawn))
		for i, w := range withdrawn {
			devices[i] = w.DeviceID
			delete(claimed, w.ID)
		}
		// A claimed command that got its result meanwhile stays, and so does the device's request.
		for _, c := range claimed {
			c.releaseOn(context.WithoutCancel(ctx), errCommandFinished())
		}
		n, err := q.ClearOffboardingUninstalls(ctx, devices)
		if err != nil {
			return fmt.Errorf("clear uninstall requests: %w", err)
		}
		if n != int64(len(devices)) {
			return fmt.Errorf("app: %d uninstall requests cleared for %d cancelled commands", n, len(devices))
		}
		return nil
	})
	// The claims are released even when the budget of the cancel ran out.
	for _, c := range claims {
		c.releaseOn(context.WithoutCancel(ctx), err)
	}
	if err != nil {
		return 0, err
	}
	for _, w := range withdrawn {
		dropWithdrawnCommand(ctx, u.cache, w.DeviceID, w.ID)
	}
	return len(withdrawn), nil
}

// withdrawUninstallCommand cancels an uninstall command without a result (pending or delivered): it claims the
// result as cancelled first, so a result the device posts afterwards is a conflict and the agent never starts the
// removal, then cancels the command. When the device's result was claimed first it returns that status and leaves
// the command as it is. withdrawn is false also when the command already has a result although the claim was won:
// the gateway publishes a result before it claims it, so the worker may have recorded it meanwhile. The caller
// decides whether either refuses its action and runs dropWithdrawnCommand after the commit. A won claim is noted in
// claims (nil: not tracked) so that the caller can release it when its transaction fails.
func withdrawUninstallCommand(ctx context.Context, q *pgstore.Queries, cache UninstallCache, claims *resultClaims,
	deviceID uuid.UUID, cmd pgstore.DeviceCommand, now time.Time) (claimed string, withdrawn bool, err error) {
	owner, status, err := cache.ClaimResult(ctx, deviceID, cmd.ID, devicecommand.StatusCancelled)
	if err != nil {
		return "", false, err
	}
	if owner != deviceID || status != devicecommand.StatusCancelled {
		return status, false, nil
	}
	claims.won(cmd.ID)
	n, err := q.WithdrawDeviceCommand(ctx, pgstore.WithdrawDeviceCommandParams{ID: cmd.ID, FinishedAt: now.UTC()})
	if err != nil {
		return "", false, err
	}
	return "", n == 1, nil
}

// resultClaims are the result claims (UninstallCache.ClaimResult) an action won inside its transaction. Valkey is
// outside the transaction: a claim would survive a rollback and turn the device's later result into a conflict, so the
// action releases them when its transaction fails (PDK-241 review 2).
type resultClaims struct {
	cache  UninstallCache
	device uuid.UUID
	ids    []uuid.UUID
}

func newResultClaims(cache UninstallCache, device uuid.UUID) *resultClaims {
	return &resultClaims{cache: cache, device: device}
}

func (c *resultClaims) won(id uuid.UUID) {
	if c != nil {
		c.ids = append(c.ids, id)
	}
}

// releaseOn takes the claims back when err (the transaction's outcome) is not nil.
func (c *resultClaims) releaseOn(ctx context.Context, err error) {
	if c == nil || err == nil {
		return
	}
	for _, id := range c.ids {
		if _, rerr := c.cache.ReleaseResult(ctx, c.device, id, devicecommand.StatusCancelled); rerr != nil {
			slog.WarnContext(ctx, "releasing the result claim of a rolled-back withdrawal failed", "device_id", c.device,
				"command_id", id, "error", rerr)
		}
	}
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

// uninstallRefusedForGood is the refusal reason of the command uninstall that can never succeed: the device rejected
// the params themselves. conversion_pending and revocation_pending clear up, so those requests stay open for the
// administrator to cancel or request again; there is no automatic retry (plan M8d amendment 2026-10-28, PDK-403).
const uninstallRefusedForGood = "invalid_params"

// terminalUninstallRefusal reports the reason of a failed command result that refuses an uninstall for good; ok is
// false for any other result.
func terminalUninstallRefusal(status string, result json.RawMessage) (string, bool) {
	if status != protocol.CommandFailed {
		return "", false
	}
	var res command.UninstallAccepted
	if json.Unmarshal(result, &res) != nil || res.Accepted || res.Reason != uninstallRefusedForGood {
		return "", false
	}
	return res.Reason, true
}

// endRefusedUninstall records the refused uninstall command and ends its open request in one transaction (audited
// once: device.uninstall_failed, actor the device). A duplicate result, or a refusal of a command that is no longer
// the device's open request (cancelled, requested again), only records the command result as usual.
func endRefusedUninstall(ctx context.Context, runner *ActionRunner, r ingest.CommandResult, result json.RawMessage,
	reason string) error {
	spec := ActionSpec{
		Code:   audit.CodeDeviceUninstallFailed,
		Actor:  &audit.Actor{Type: audit.ActorDevice, ID: r.DeviceID.String()},
		Target: &audit.Target{Type: "device", ID: r.DeviceID.String()},
		Params: map[string]any{"command_id": r.CommandID.String(), "reason": reason},
	}
	_, err := runner.RecordOnceWith(ctx, spec, func(ctx context.Context, q *pgstore.Queries, rec Recorder) (bool, error) {
		// The lock order of Request and Cancel: the device first, then its command.
		dev, err := q.LockDevice(ctx, r.DeviceID)
		if db.IsNoRows(err) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		n, err := q.FinishDeviceCommand(ctx, pgstore.FinishDeviceCommandParams{
			ID: r.CommandID, DeviceID: r.DeviceID, Status: r.Status, Result: result, FinishedAt: r.ReceivedAt,
		})
		if err != nil || n != 1 {
			return false, err
		}
		ended, err := q.EndFailedUninstall(ctx, pgstore.EndFailedUninstallParams{ID: r.DeviceID, CommandID: r.CommandID})
		if err != nil || ended != 1 {
			return false, err
		}
		rec.SetTarget(audit.Target{Type: "device", ID: r.DeviceID.String(), Display: dev.Hostname})
		rec.SetParam("hostname", dev.Hostname)
		if dev.UninstallMode != nil {
			rec.SetParam("mode", *dev.UninstallMode)
		}
		return true, nil
	})
	return err
}
