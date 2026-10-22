package app

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/pkg/command"
	"github.com/phischl/paddock-mdm/pkg/protocol"
	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
	"github.com/phischl/paddock-mdm/server/internal/domain/device"
	"github.com/phischl/paddock-mdm/server/internal/domain/devicecommand"
	"github.com/phischl/paddock-mdm/server/internal/domain/disk"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/problem"
)

// DiskConversions are the use cases of the in-place encryption (ADR 0039, plan M8e decisions 7 and 8): an
// organization administrator asks an unencrypted device to encrypt its root volume with the signed command
// encrypt_disk, and cancels the request until the device restarts — by withdrawing the undelivered command or with
// the signed command encrypt_disk_abort.
type DiskConversions struct {
	runner *ActionRunner
	org    *db.OrgPool
	cache  UninstallCache
	now    func() time.Time
}

// NewDiskConversions creates the use cases; cache withdraws an undelivered command from the gateway.
func NewDiskConversions(runner *ActionRunner, org *db.OrgPool, cache UninstallCache) *DiskConversions {
	return &DiskConversions{runner: runner, org: org, cache: cache, now: time.Now}
}

// Specs of the in-place encryption actions.
var (
	SpecDiskConversionRequest = ActionSpec{Code: audit.CodeDeviceEncryptRequested, AllowedRoles: RolesAdmin, RequiresStepUp: true}
	SpecDiskConversionCancel  = ActionSpec{Code: audit.CodeDeviceEncryptCancelled, AllowedRoles: RolesAdmin, RequiresStepUp: true}
)

// Modes of device.encrypt_cancelled (plan M8e decision 8).
const (
	ConversionCancelCommand = "command_cancelled" // the undelivered encrypt_disk command was withdrawn
	ConversionCancelAbort   = "abort_sent"        // the device was sent encrypt_disk_abort
)

// ConversionCancelledBeforeDelivery is the param conversion_cancelled of a Retire, Lock or Destroy that withdrew an
// undelivered encrypt_disk command (plan M8e §14.5 decisions 38 and 39).
const ConversionCancelledBeforeDelivery = "before_delivery"

// DiskConversionInput is an in-place encryption request.
type DiskConversionInput struct {
	ConfirmHostname string
	Reason          string
	BackupConfirmed bool
}

// Reasons of an in-place encryption request are bounded like those of an uninstall.
const (
	minConversionReason = 2
	maxConversionReason = 500
)

// reasonAlreadyEncrypted is the preflight reason the server adds for a device whose disk state is an encrypted one
// (plan M8e decision 2, gate S-IE3): the agent reports the eligibility in state not_encrypted only.
const reasonAlreadyEncrypted = "already_encrypted"

// DiskConversion is the latest in-place encryption of a device as the API shows it (plan M8e decision 10): the row
// with the status of its commands, the progress of the last health while it is encrypting (ADR 0028), and whether
// it is active (§14.5 decision 36).
type DiskConversion struct {
	pgstore.GetLatestDiskConversionRow
	// Progress is health.disk.conversion of the last check-in while the conversion is encrypting; nil otherwise.
	Progress *protocol.DiskConversion
	// Notes are the wait, the cleanup's reason and the initrd issue of the last check-in where the phase has them.
	Notes  disk.ConversionNotes
	Active bool
}

// loadDiskConversion returns the latest conversion of a device with the disk health of its last check-in; nil
// without one.
func loadDiskConversion(ctx context.Context, q *pgstore.Queries, deviceID uuid.UUID, health *protocol.DiskHealth) (*DiskConversion, error) {
	row, err := q.GetLatestDiskConversion(ctx, deviceID)
	if db.IsNoRows(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	out := &DiskConversion{GetLatestDiskConversionRow: row}
	if health != nil && row.DeviceDiskConversion.Phase == disk.PhaseEncrypting {
		out.Progress = health.Conversion
	}
	if health != nil {
		out.Notes = disk.Notes(row.DeviceDiskConversion.Phase, health.Conversion)
	}
	out.Active = disk.ConversionActive(row.DeviceDiskConversion.Phase, health, row.CompletedAt, time.Now())
	return out, nil
}

// lastDiskHealth is health.disk of the device's last check-in; nil without one.
func lastDiskHealth(ctx context.Context, q *pgstore.Queries, deviceID uuid.UUID) (*protocol.DiskHealth, error) {
	status, err := q.GetDeviceStatus(ctx, deviceID)
	if db.IsNoRows(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return diskHealth(status.Health), nil
}

// Request issues the command encrypt_disk to an active, unencrypted device whose last health reports an eligible
// layout (audited: device.encrypt_requested, with a step-up).
func (c *DiskConversions) Request(ctx context.Context, deviceID uuid.UUID, in DiskConversionInput) (pgstore.Device, error) {
	spec := SpecDiskConversionRequest
	spec.Target = &audit.Target{Type: "device", ID: deviceID.String()}
	spec.Params = map[string]any{"reason": in.Reason, "backup_confirmed": in.BackupConfirmed}
	var out pgstore.Device
	err := c.runner.RunTx(ctx, ScopeOrg, spec, func(ctx context.Context, q *pgstore.Queries, rec Recorder) error {
		dev, err := q.LockDevice(ctx, deviceID)
		if err != nil {
			return notFound(err)
		}
		rec.SetTarget(audit.Target{Type: "device", ID: deviceID.String(), Display: dev.Hostname})
		rec.SetParam("hostname", dev.Hostname)
		if n := utf8.RuneCountInString(in.Reason); n < minConversionReason || n > maxConversionReason {
			return problem.InvalidRequestUnprocessed.WithDetail("reason must have 2 to 500 characters")
		}
		if dev.State != device.StateActive {
			return problem.InvalidState.WithDetail("only active devices can be encrypted")
		}
		if in.ConfirmHostname != dev.Hostname {
			return problem.InvalidRequestUnprocessed.WithDetail("confirm_hostname does not match")
		}
		if !in.BackupConfirmed {
			return problem.InvalidRequestUnprocessed.WithDetail("backup_confirmed must be true")
		}
		health, err := lastDiskHealth(ctx, q, deviceID)
		if err != nil {
			return err
		}
		if err := requireEligible(health); err != nil {
			return err
		}
		latest, err := loadDiskConversion(ctx, q, deviceID, health)
		if err != nil {
			return err
		}
		if latest != nil && disk.Open(latest.DeviceDiskConversion.Phase) {
			return problem.InvalidState.WithDetail("a conversion is already open")
		}
		if dev.UninstallRequestedAt != nil && dev.UninstalledAt == nil {
			return problem.InvalidState.WithDetail("an uninstall is pending")
		}
		revoking, err := q.DeviceHasOpenRevocation(ctx, deviceID)
		if err != nil {
			return err
		}
		if revoking {
			return problem.InvalidState.WithDetail("a lock or destroy is pending for this device")
		}
		id := uuid.Must(uuid.NewV7())
		rec.SetParam("conversion_id", id.String())
		now := c.now()
		cmd, err := issueCommand(ctx, q, rec, deviceID, command.TypeEncryptDisk, map[string]any{"conversion_id": id.String()}, now, nil)
		if err != nil {
			return err
		}
		var requestedBy uuid.NullUUID
		if p, ok := principal.From(ctx); ok && p.Kind == principal.KindAdmin && p.ID != uuid.Nil {
			requestedBy = uuid.NullUUID{UUID: p.ID, Valid: true}
		}
		_, err = q.InsertDiskConversion(ctx, pgstore.InsertDiskConversionParams{ID: id, OrganizationID: dev.OrganizationID,
			DeviceID: deviceID, CommandID: cmd.ID, RequestedAt: now.UTC(), RequestedBy: requestedBy, Reason: in.Reason})
		if db.IsUniqueViolation(err, "device_disk_conversion_open_idx") {
			return problem.InvalidState.WithDetail("a conversion is already open")
		}
		out = dev
		return err
	})
	return out, err
}

// requireEligible refuses a device whose last health does not report state not_encrypted with an eligible layout;
// the detail names the reasons.
func requireEligible(health *protocol.DiskHealth) error {
	var reasons []string
	if health != nil && health.Conversion != nil {
		reasons = slices.Clone(health.Conversion.Reasons)
	}
	if health != nil && health.State != protocol.DiskNotEncrypted && !slices.Contains(reasons, reasonAlreadyEncrypted) {
		reasons = append(reasons, reasonAlreadyEncrypted)
	}
	if health != nil && health.State == protocol.DiskNotEncrypted && health.Conversion != nil && health.Conversion.Eligible {
		return nil
	}
	detail := "the device does not report an eligible disk layout"
	if len(reasons) > 0 {
		slices.Sort(reasons)
		detail += ": " + strings.Join(reasons, ", ")
	}
	return problem.InvalidState.WithDetail(detail)
}

// Cancel cancels the open conversion of a device before its restart (audited: device.encrypt_cancelled, with a
// step-up): an encrypt_disk command the device has not received is withdrawn and the conversion cancelled at once
// (mode command_cancelled, the mechanics of Uninstalls.Cancel); otherwise the device is sent encrypt_disk_abort
// (mode abort_sent) and the conversion keeps its phase until the device reports the abort or refuses it.
func (c *DiskConversions) Cancel(ctx context.Context, deviceID uuid.UUID, confirmHostname string) (pgstore.Device, error) {
	spec := SpecDiskConversionCancel
	spec.Target = &audit.Target{Type: "device", ID: deviceID.String()}
	var out pgstore.Device
	var withdrawn uuid.UUID
	claims := newResultClaims(c.cache, deviceID)
	err := c.runner.RunTx(ctx, ScopeOrg, spec, func(ctx context.Context, q *pgstore.Queries, rec Recorder) error {
		dev, err := q.LockDevice(ctx, deviceID)
		if err != nil {
			return notFound(err)
		}
		rec.SetTarget(audit.Target{Type: "device", ID: deviceID.String(), Display: dev.Hostname})
		rec.SetParam("hostname", dev.Hostname)
		conv, err := loadDiskConversion(ctx, q, deviceID, nil)
		if err != nil {
			return err
		}
		if conv == nil || !disk.Open(conv.DeviceDiskConversion.Phase) {
			return problem.InvalidState.WithDetail("no conversion is open")
		}
		row := conv.DeviceDiskConversion
		rec.SetParam("conversion_id", row.ID.String())
		if confirmHostname != dev.Hostname {
			return problem.InvalidRequestUnprocessed.WithDetail("confirm_hostname does not match")
		}
		now := c.now()
		switch {
		case row.Phase == disk.PhaseEncrypting:
			return problem.ConversionNotCancellable.WithDetail("the device already started the encryption; it cannot be cancelled")
		case row.Phase == disk.PhaseRequested && undelivered(conv.CommandStatus):
			rec.SetParam("mode", ConversionCancelCommand)
			rec.SetParam("command_id", row.CommandID.String())
			drop, claimed, _, err := cancelUndeliveredConversion(ctx, q, claims, deviceID, row, now)
			if err != nil {
				return err
			}
			if claimed != "" {
				return problem.InvalidState.WithDetail("the device already received the command")
			}
			if drop == uuid.Nil {
				return errCommandFinished()
			}
			withdrawn = drop
		case abortOnItsWay(conv.AbortCommandStatus):
			return problem.InvalidState.WithDetail("a cancellation is already on its way")
		default:
			rec.SetParam("mode", ConversionCancelAbort)
			abort, err := issueCommand(ctx, q, rec, deviceID, command.TypeEncryptDiskAbort,
				map[string]any{"conversion_id": row.ID.String()}, now, nil)
			if err != nil {
				return err
			}
			n, err := q.SetDiskConversionAbort(ctx, pgstore.SetDiskConversionAbortParams{ID: row.ID,
				AbortCommandID: uuid.NullUUID{UUID: abort.ID, Valid: true}})
			if err != nil {
				return err
			}
			if n != 1 {
				return problem.InvalidState.WithDetail("no conversion is open")
			}
		}
		out = dev
		return nil
	})
	claims.releaseOn(ctx, err)
	if err == nil {
		dropWithdrawnCommand(ctx, c.cache, deviceID, withdrawn)
	}
	return out, err
}

// undelivered reports whether an encrypt_disk command in status has not reached the device: pending, or ended
// without a result (failed, expired).
func undelivered(status string) bool {
	return status == devicecommand.StatusPending || status == devicecommand.StatusFailed || status == devicecommand.StatusExpired
}

// abortOnItsWay reports whether an abort command was issued and neither failed nor expired: pending, delivered, or
// succeeded while the device's disk.conversion_aborted has not arrived yet.
func abortOnItsWay(status *string) bool {
	return status != nil && *status != devicecommand.StatusFailed && *status != devicecommand.StatusExpired &&
		*status != devicecommand.StatusCancelled
}

// cancelUndeliveredConversion withdraws the undelivered encrypt_disk command of a requested conversion and cancels
// the conversion: a pending command through the result claim (withdrawUninstallCommand), a failed or expired one
// directly. It returns the command to drop from cmd:<device_id> after the commit (uuid.Nil when nothing was
// withdrawn), when the device's result was claimed first that status, and the conversion's phase under its row lock.
func cancelUndeliveredConversion(ctx context.Context, q *pgstore.Queries, claims *resultClaims, deviceID uuid.UUID,
	row pgstore.DeviceDiskConversion, now time.Time) (uuid.UUID, string, string, error) {
	cmd, phase, err := lockConversion(ctx, q, row)
	if err != nil || phase != disk.PhaseRequested {
		return uuid.Nil, "", phase, err
	}
	switch cmd.Status {
	case devicecommand.StatusPending:
		claimed, ok, err := withdrawUninstallCommand(ctx, q, claims.cache, claims, deviceID, cmd, now)
		if err != nil || claimed != "" || !ok {
			return uuid.Nil, claimed, phase, err
		}
	case devicecommand.StatusFailed, devicecommand.StatusExpired:
		n, err := q.CancelDeviceCommand(ctx, pgstore.CancelDeviceCommandParams{ID: cmd.ID, FinishedAt: now.UTC()})
		if err != nil || n != 1 {
			return uuid.Nil, "", phase, err
		}
	default:
		return uuid.Nil, "", phase, nil
	}
	n, err := q.CancelDiskConversion(ctx, pgstore.CancelDiskConversionParams{ID: row.ID, At: now.UTC()})
	if err != nil {
		return uuid.Nil, "", phase, err
	}
	if n != 1 {
		return uuid.Nil, "", phase, fmt.Errorf("cancel conversion %s: %d rows under its lock", row.ID, n)
	}
	return cmd.ID, "", disk.PhaseCancelled, nil
}

// lockConversion locks the encrypt_disk command and the conversion of a withdrawal and returns the command and the
// conversion's phase. Every path that touches a conversion locks in one order — the device row, then the
// device_command row, then the conversion row: the request, cancel, Retire, Lock and Destroy hold the device's lock
// already, the worker takes it before a command result (DeviceCommands.Finish) or a conversion event
// (applyConversionEvent). Another order deadlocks against them (PDK-241 review 2). The conversion lock also makes an
// event that moved the row meanwhile win over the withdrawal (review 1 finding 4).
func lockConversion(ctx context.Context, q *pgstore.Queries, row pgstore.DeviceDiskConversion) (pgstore.DeviceCommand, string, error) {
	cmd, err := q.LockDeviceCommand(ctx, row.CommandID)
	if err != nil {
		return cmd, "", err
	}
	phase, err := q.LockDiskConversionPhase(ctx, row.ID)
	return cmd, phase, err
}

// withdrawConversion is the in-place encryption part of a Retire, Lock or Destroy (plan M8e §14.5 decisions 38 and
// 39): they are never refused for a conversion. A requested conversion whose command has not reached the device is
// cancelled with it (params conversion_cancelled before_delivery and conversion_id on the action's one event); any
// other open conversion is left alone and recorded as conversion_id and conversion_phase. It returns the command to
// drop from cmd:<device_id> after the commit.
func withdrawConversion(ctx context.Context, q *pgstore.Queries, claims *resultClaims, rec Recorder, deviceID uuid.UUID,
	now time.Time) (uuid.UUID, error) {
	conv, err := loadDiskConversion(ctx, q, deviceID, nil)
	if err != nil || conv == nil || !disk.Open(conv.DeviceDiskConversion.Phase) {
		return uuid.Nil, err
	}
	row := conv.DeviceDiskConversion
	rec.SetParam("conversion_id", row.ID.String())
	phase := row.Phase
	if row.Phase == disk.PhaseRequested && undelivered(conv.CommandStatus) {
		drop, _, locked, err := cancelUndeliveredConversion(ctx, q, claims, deviceID, row, now)
		if err != nil {
			return uuid.Nil, err
		}
		if drop != uuid.Nil {
			rec.SetParam("conversion_cancelled", ConversionCancelledBeforeDelivery)
			return drop, nil
		}
		phase = locked
	}
	rec.SetParam("conversion_phase", phase)
	return uuid.Nil, nil
}

// refuseActiveConversion refuses an uninstall while the device's in-place encryption is active (plan M8e §14.5
// decision 36): the removal would purge the plan and the conversion key the device needs to open its root volume.
func refuseActiveConversion(ctx context.Context, q *pgstore.Queries, deviceID uuid.UUID) error {
	health, err := lastDiskHealth(ctx, q, deviceID)
	if err != nil {
		return err
	}
	conv, err := loadDiskConversion(ctx, q, deviceID, health)
	if err != nil {
		return err
	}
	phase, active := "", disk.ConversionActive("", health, nil, time.Now())
	if conv != nil {
		phase, active = conv.DeviceDiskConversion.Phase, conv.Active
	}
	switch {
	case !active:
		return nil
	case phase == disk.PhaseRequested || phase == disk.PhasePrepared:
		return problem.InvalidState.WithDetail("an in-place encryption is open; cancel it first")
	}
	return problem.InvalidState.WithDetail("the in-place encryption is unfinished; wait for its completion")
}

// recordConversionResult applies the result of an encrypt_disk or encrypt_disk_abort command to its conversion (plan
// M8e decision 9): a refused encrypt_disk ({accepted: false}) fails the conversion at stage preflight, a refused
// abort ({aborted: false}) stores the reason and leaves the phase. Results of other commands change nothing.
func recordConversionResult(ctx context.Context, q *pgstore.Queries, deviceID uuid.UUID, cmd pgstore.DeviceCommand,
	result json.RawMessage) error {
	switch cmd.Type {
	case command.TypeEncryptDisk:
		var res command.EncryptDiskAccepted
		if json.Unmarshal(result, &res) == nil && res.Accepted {
			return nil
		}
		_, err := q.RefuseDiskConversionCommand(ctx, pgstore.RefuseDiskConversionCommandParams{
			CommandID: cmd.ID, DeviceID: deviceID, Reason: boundedReason(res.Reason)})
		return err
	case command.TypeEncryptDiskAbort:
		var res command.EncryptDiskAbortResult
		if json.Unmarshal(result, &res) == nil && res.Aborted {
			return nil
		}
		_, err := q.RefuseDiskConversionAbort(ctx, pgstore.RefuseDiskConversionAbortParams{
			AbortCommandID: uuid.NullUUID{UUID: cmd.ID, Valid: true}, DeviceID: deviceID, Reason: boundedReason(res.Reason)})
		return err
	}
	return nil
}

// boundedReason is a device-reported reason for a conversion column; nil when empty or out of bounds.
func boundedReason(v any) *string {
	s, ok := boundedString(v)
	if !ok || s == "" {
		return nil
	}
	return &s
}

// conversionEvents are the device events of an in-place encryption.
var conversionEvents = []string{protocol.EventDiskConversionPrepared, protocol.EventDiskConversionStarted,
	protocol.EventDiskConversionCompleted, protocol.EventDiskConversionFailed, protocol.EventDiskConversionAborted}

// applyConversionEvent moves the conversion an event names (plan M8e decision 9, §14.10). An event for an unknown
// conversion or one of another device changes nothing and stays an audit event of the device.
func applyConversionEvent(ctx context.Context, q *pgstore.Queries, deviceID uuid.UUID, typ string, params map[string]any) error {
	id, err := uuid.Parse(fmt.Sprint(params["conversion_id"]))
	if err != nil {
		slog.WarnContext(ctx, "conversion event without a conversion ID; audited only", "device_id", deviceID, "type", typ)
		return nil
	}
	// The lock order of lockConversion: the device first. It also serializes an adoption (started) with a new request
	// (device_disk_conversion_open_idx).
	if _, err := q.LockDevice(ctx, deviceID); err != nil {
		return err
	}
	dataBytes := int64Param(params["data_bytes"])
	var n int64
	switch typ {
	case protocol.EventDiskConversionPrepared:
		var layout *string
		if l, ok := params["layout"].(string); ok && (l == "lvm" || l == "plain") {
			layout = &l
		}
		var volume uuid.NullUUID
		if v, err := uuid.Parse(fmt.Sprint(params["volume"])); err == nil {
			volume = uuid.NullUUID{UUID: v, Valid: true}
		}
		n, err = q.PrepareDiskConversion(ctx, pgstore.PrepareDiskConversionParams{ID: id, DeviceID: deviceID, Layout: layout,
			LuksUuid: volume, DataBytes: dataBytes})
	case protocol.EventDiskConversionStarted:
		n, err = q.StartDiskConversion(ctx, pgstore.StartDiskConversionParams{ID: id, DeviceID: deviceID})
	case protocol.EventDiskConversionCompleted:
		n, err = q.CompleteDiskConversion(ctx, pgstore.CompleteDiskConversionParams{ID: id, DeviceID: deviceID, DataBytes: dataBytes})
	case protocol.EventDiskConversionFailed:
		n, err = q.FailDiskConversion(ctx, pgstore.FailDiskConversionParams{ID: id, DeviceID: deviceID,
			FailureStage: boundedReason(params["stage"]), FailureReason: boundedReason(params["reason"])})
	case protocol.EventDiskConversionAborted:
		n, err = q.AbortDiskConversion(ctx, pgstore.AbortDiskConversionParams{ID: id, DeviceID: deviceID})
	}
	if err == nil && n == 0 {
		slog.InfoContext(ctx, "conversion event changes no conversion; audited only", "device_id", deviceID, "type", typ,
			"conversion_id", id)
	}
	return err
}

// int64Param is a numeric event param (eventParams stores numbers as int64); nil when absent.
func int64Param(v any) *int64 {
	n, ok := v.(int64)
	if !ok {
		return nil
	}
	return &n
}
