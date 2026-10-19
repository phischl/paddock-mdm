package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/pkg/escrow"
	"github.com/phischl/paddock-mdm/pkg/protocol"
	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
	"github.com/phischl/paddock-mdm/server/internal/domain/components"
	"github.com/phischl/paddock-mdm/server/internal/domain/device"
	"github.com/phischl/paddock-mdm/server/internal/ingest"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
)

// DeviceReports turn heartbeats and events from devices into status, quarantine and audit events (worker, plan
// M2a decisions 12 and 14). The caller's context carries a system principal of the device's organization.
type DeviceReports struct {
	runner *ActionRunner
	org    *db.OrgPool
	now    func() time.Time
}

// NewDeviceReports creates the use cases.
func NewDeviceReports(runner *ActionRunner, org *db.OrgPool) *DeviceReports {
	return &DeviceReports{runner: runner, org: org, now: time.Now}
}

// RecordStatus materializes a heartbeat into device_status; an older heartbeat never overwrites a newer one.
func (d *DeviceReports) RecordStatus(ctx context.Context, hb ingest.Heartbeat) error {
	health := hb.Health
	if len(health) == 0 {
		health = json.RawMessage(`{}`)
	}
	at := hb.ReceivedAt
	return d.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		versions := make([]int32, 0, len(hb.SchemaVersions))
		for _, v := range hb.SchemaVersions {
			versions = append(versions, int32(v)) //nolint:gosec // the gateway bounds versions to 1–1000
		}
		outdated := []string{}
		if installed := HealthComponents(health); installed != nil {
			targets, err := ComponentTargets(ctx, q)
			if err != nil {
				return err
			}
			outdated = components.Outdated(installed, targets)
		}
		if err := q.UpsertDeviceStatus(ctx, pgstore.UpsertDeviceStatusParams{
			DeviceID: hb.DeviceID, OrganizationID: hb.OrganizationID, LastContactAt: &at,
			AppliedBundleVersion: &hb.AppliedBundleVersion, AgentVersion: &hb.AgentVersion, LastSeq: hb.Seq, Health: health,
			SchemaVersions: versions, Arch: hb.Arch, ComponentsOutdated: outdated,
		}); err != nil {
			return err
		}
		if root, ok := RootVolume(diskHealth(health)); ok {
			_, err := q.SetRootHeaderVolume(ctx, pgstore.SetRootHeaderVolumeParams{Volume: root, DeviceID: hb.DeviceID})
			return err
		}
		return nil
	})
}

// HealthComponents reads health.components (plan M8d decision 52): the installed version per component, "" for one
// that is not installed; nil when the agent reported none.
func HealthComponents(health json.RawMessage) map[string]string {
	var h struct {
		Components map[string]string `json:"components"`
	}
	if json.Unmarshal(health, &h) != nil || h.Components == nil {
		return nil
	}
	out := make(map[string]string, len(components.Names))
	for _, name := range components.Names {
		if v, ok := h.Components[name]; ok {
			if s, ok := boundedString(v); ok {
				out[name] = s
			}
		}
	}
	return out
}

// ComponentTargets returns the platform's component targets by component.
func ComponentTargets(ctx context.Context, q *pgstore.Queries) (map[string]string, error) {
	rows, err := q.ListComponentTargets(ctx)
	if err != nil {
		return nil, err
	}
	out := make(map[string]string, len(rows))
	for _, r := range rows {
		out[r.Component] = r.Version
	}
	return out, nil
}

// RootVolume is the LUKS UUID of the root volume a device reports in health.disk (PDK-009).
func RootVolume(d *protocol.DiskHealth) (uuid.UUID, bool) {
	if d == nil {
		return uuid.UUID{}, false
	}
	for _, v := range d.Volumes {
		if id, err := uuid.Parse(v.UUID); v.Root && err == nil {
			return id, true
		}
	}
	return uuid.UUID{}, false
}

// QuarantineClone quarantines an active device whose sequence numbers diverged and records device.clone_suspected
// (architecture §6.4). A device that is not active any more is left alone, so a clone produces exactly one event.
func (d *DeviceReports) QuarantineClone(ctx context.Context, hb ingest.Heartbeat) (bool, error) {
	active := false
	err := d.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		dev, err := q.GetDevice(ctx, hb.DeviceID)
		active = err == nil && dev.State == device.StateActive
		return notFound(err)
	})
	if err != nil || !active {
		return false, err
	}
	spec := ActionSpec{
		Code:   audit.CodeDeviceCloneSuspected,
		Target: &audit.Target{Type: "device", ID: hb.DeviceID.String()},
		Params: map[string]any{"reported_seq": hb.ReportedSeq, "issued_seq": hb.Seq - 1},
	}
	err = d.runner.RunTx(ctx, ScopeOrg, spec, func(ctx context.Context, q *pgstore.Queries, rec Recorder) error {
		_, err := TransitionDevice(ctx, q, rec, device.ActionQuarantine, hb.DeviceID)
		return err
	})
	return err == nil, err
}

// RetireUninstalled retires an active device that reported its removal (plan M8d decision 41): device.retired with
// the system as actor and the param reason uninstalled, retired_reason uninstalled. It is recorded once, keyed on
// uninstalled_at IS NOT NULL AND state = 'active' under the device's row lock, so a redelivered or concurrent report
// records nothing.
func (d *DeviceReports) RetireUninstalled(ctx context.Context, deviceID uuid.UUID) (bool, error) {
	spec := SpecDeviceRetire
	spec.Target = &audit.Target{Type: "device", ID: deviceID.String()}
	spec.Params = map[string]any{"reason": device.RetiredUninstalled}
	return d.runner.RecordOnceWith(ctx, spec, func(ctx context.Context, q *pgstore.Queries, rec Recorder) (bool, error) {
		dev, err := q.LockDevice(ctx, deviceID)
		if err != nil {
			return false, notFound(err)
		}
		if dev.State != device.StateActive || dev.UninstalledAt == nil {
			return false, nil
		}
		if _, err := TransitionDevice(ctx, q, rec, device.ActionRetire, deviceID); err != nil {
			return false, err
		}
		reason := device.RetiredUninstalled
		return true, q.SetDeviceRetiredReason(ctx, pgstore.SetDeviceRetiredReasonParams{ID: deviceID, Reason: &reason})
	})
}

// eventCodes maps the closed set of device event types to audit codes.
var eventCodes = map[string]audit.Code{
	protocol.EventBundleApplied:        audit.CodeDeviceBundleApplied,
	protocol.EventBundleRejected:       audit.CodeDeviceBundleRejected,
	protocol.EventConfigDriftCorrected: audit.CodeDeviceConfigDriftCorrected,
	protocol.EventAgentUpdated:         audit.CodeDeviceAgentUpdated,
	protocol.EventAgentUpdateFailed:    audit.CodeDeviceAgentUpdateFailed,
	protocol.EventAgentRolledBack:      audit.CodeDeviceAgentRolledBack,
	protocol.EventAgentEventsDropped:   audit.CodeDeviceAgentEventsDropped,
	// Failed outcomes switch to device.supervisor_update_failed in eventEntry (ADR 0024 pattern).
	protocol.EventAgentSupervisorUpdated: audit.CodeDeviceSupervisorUpdated,
	protocol.EventAgentUninstalled:       audit.CodeDeviceUninstalled,

	protocol.EventLoginApplied:               audit.CodeDeviceLoginApplied,
	protocol.EventLoginApplyFailed:           audit.CodeDeviceLoginApplyFailed,
	protocol.EventUserLockApplied:            audit.CodeDeviceUserLockApplied,
	protocol.EventLoginsSuspensionApplied:    audit.CodeDeviceLoginsSuspensionApplied,
	protocol.EventSudoApplyFailed:            audit.CodeDeviceSudoApplyFailed,
	protocol.EventSudoUserUnresolved:         audit.CodeDeviceSudoUserUnresolved,
	protocol.EventTamperSudoGroupMember:      audit.CodeDeviceTamperSudoGroupMember,
	protocol.EventTamperSudoersDFile:         audit.CodeDeviceTamperSudoersDFile,
	protocol.EventTamperSudoersChanged:       audit.CodeDeviceTamperSudoersChanged,
	protocol.EventTamperProtectedFileChanged: audit.CodeDeviceTamperProtectedFileChanged,

	protocol.EventLocalAdminRotated:        audit.CodeLocalAdminRotated,
	protocol.EventLocalAdminRotationFailed: audit.CodeLocalAdminRotationFailed,
	protocol.EventLocalAdminLogin:          audit.CodeLocalAdminLogin,
	protocol.EventTamperLocalAdminChanged:  audit.CodeDeviceTamperLocalAdminChanged,

	protocol.EventTamperKeyslotChanged: audit.CodeDeviceTamperKeyslotChanged,

	protocol.EventRevocationTrustPinnedTOFU: audit.CodeDeviceRevocationTrustPinnedTOFU,
	protocol.EventRevocationRefused:         audit.CodeDeviceRevocationRefused,

	protocol.EventTamperServiceStopped: audit.CodeDeviceTamperServiceStopped,

	protocol.EventUpdatesRun: audit.CodeDeviceUpdatesRun,
}

// RecordEvent records one device event as an audit event with the device as actor, once per (device, event_seq).
// It reports whether the event was new.
func (d *DeviceReports) RecordEvent(ctx context.Context, deviceID uuid.UUID, ev protocol.Event) (bool, error) {
	if ev.Type == protocol.EventSessionLogin {
		return true, d.recordSessionLogin(ctx, deviceID, ev)
	}
	entry, ok := eventEntry(deviceID, ev)
	if !ok {
		return false, nil // the gateway admits only known types; anything else is ignored
	}
	return d.runner.RecordOnce(ctx, entry.Spec, entry.Claim)
}

// RecordEvents is RecordEvent for the events of one ingest message, session logins included, in one transaction
// (ActionRunner.RecordOnceBatch). An error means that some event could not be recorded; the others are, and a
// redelivery skips them by (device_id, event_seq).
func (d *DeviceReports) RecordEvents(ctx context.Context, deviceID uuid.UUID, events []protocol.Event) error {
	entries := make([]OnceEntry, 0, len(events))
	for _, ev := range events {
		entry, ok := eventEntry(deviceID, ev)
		if ev.Type == protocol.EventSessionLogin {
			entry, ok = sessionLoginEntry(deviceID, ev, d.now())
		}
		if ok {
			entries = append(entries, entry)
		}
	}
	if len(entries) == 0 {
		return nil
	}
	_, err := d.runner.RecordOnceBatch(ctx, entries)
	return err
}

// eventEntry is the audited action of a device event and the claim of its (device, event_seq); false for a type that
// is not audited.
func eventEntry(deviceID uuid.UUID, ev protocol.Event) (OnceEntry, bool) {
	code, ok := eventCodes[ev.Type]
	if !ok {
		return OnceEntry{}, false
	}
	params := eventParams(ev)
	// The agent carries a failed rollback in agent.update_failed so that older servers accept it (ADR 0024).
	if ev.Type == protocol.EventAgentUpdateFailed && params["outcome"] == outcomeRollbackFailed {
		code = audit.CodeDeviceAgentRollbackFailed
	}
	if ev.Type == protocol.EventAgentSupervisorUpdated && params["outcome"] != protocol.SupervisorOutcomeUpdated {
		code = audit.CodeDeviceSupervisorUpdateFailed
	}
	spec := ActionSpec{
		Code:   code,
		Actor:  &audit.Actor{Type: audit.ActorDevice, ID: deviceID.String()},
		Target: &audit.Target{Type: "device", ID: deviceID.String()},
		Params: params,
	}
	return OnceEntry{Spec: spec, Claim: func(ctx context.Context, q *pgstore.Queries) (bool, error) {
		org, err := orgOf(ctx)
		if err != nil {
			return false, err
		}
		n, err := q.InsertDeviceEventSeen(ctx, pgstore.InsertDeviceEventSeenParams{
			DeviceID: deviceID, EventSeq: ev.EventSeq, OrganizationID: org,
		})
		if err != nil || n != 1 {
			return false, err
		}
		if outcome, ok := updateOutcome(ev.Type, spec.Params); ok {
			if version, ok := spec.Params["version"].(string); ok {
				err = q.InsertAgentUpdateReport(ctx, pgstore.InsertAgentUpdateReportParams{
					DeviceID: deviceID, OrganizationID: org, Version: version, Outcome: outcome,
				})
			}
		}
		// The device's report of a requested version ends the update-now request (plan M8d decision 29) — once its
		// supervisor result arrived, when the supervisor or fleetd still have to follow (review finding 5).
		if err == nil && endsUpdateRequest(ev.Type) {
			if version, ok := spec.Params["version"].(string); ok {
				err = clearUpdateRequest(ctx, q, deviceID, ev.Type, version)
			}
		}
		// The removal report marks the device; the report consumer retires it (plan M8d decision 41).
		if ev.Type == protocol.EventAgentUninstalled && err == nil {
			err = markUninstalled(ctx, q, deviceID, ev, spec.Params)
		}
		if area := loginStateArea(ev.Type, spec.Params); area != "" && err == nil {
			err = setLoginState(ctx, q, deviceID, org, area, ev, spec.Params)
		}
		if g, ok := spec.Params["generation"].(int64); ok && ev.Type == protocol.EventLocalAdminRotated && err == nil && g > 0 && g <= 1<<31-1 {
			_, err = q.ActivateEscrowGeneration(ctx, pgstore.ActivateEscrowGenerationParams{
				DeviceID: deviceID, Kind: escrow.KindAdminPassword, Generation: int32(g), ActivatedAt: ev.OccurredAt, //nolint:gosec // bounded above
			})
		}
		return true, err
	}}, true
}

// recordSessionLogin notes that a user logged in on a device (device_user_seen, plan M3a decision 10); logins are not
// audited (privacy, volume), and a redelivered event only repeats the same upsert. A malformed event is ignored.
func (d *DeviceReports) recordSessionLogin(ctx context.Context, deviceID uuid.UUID, ev protocol.Event) error {
	entry, ok := sessionLoginEntry(deviceID, ev, d.now())
	if !ok {
		return nil
	}
	return d.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		_, err := entry.Claim(ctx, q)
		return err
	})
}

// sessionLoginEntry is the unaudited batch entry of a session login (an upsert of device_user_seen and, while the
// organization records its login history, a device_login_event row; plan M8d decision 16); false for a malformed
// event, including a username with control characters. The login time comes from the device: it is capped at the
// server's time plus protocol.MaxClockSkew, so retention can delete every row (PDK-223 review 1 finding 4). The
// setting is read in the inserting transaction under the shared login history lock, so a switch-off that commits
// first prevents the insert and one that commits later deletes the row (finding 3); a login before the switch-on, or
// older than the retention window, is not stored (finding 13).
func sessionLoginEntry(deviceID uuid.UUID, ev protocol.Event, now time.Time) (OnceEntry, bool) {
	var login protocol.SessionLogin
	if json.Unmarshal(ev.Data, &login) != nil {
		return OnceEntry{}, false
	}
	username := strings.ToLower(strings.TrimSpace(login.Username))
	if username == "" || len(username) > maxParamString || stripControls(username) != username {
		return OnceEntry{}, false
	}
	at := login.At
	if at.IsZero() || at.After(ev.OccurredAt.Add(time.Minute)) {
		at = ev.OccurredAt
	}
	if latest := now.Add(protocol.MaxClockSkew); at.IsZero() || at.After(latest) {
		at = latest
	}
	return OnceEntry{Claim: func(ctx context.Context, q *pgstore.Queries) (bool, error) {
		if err := q.UpsertDeviceUserSeen(ctx, pgstore.UpsertDeviceUserSeenParams{
			OrganizationID: mustOrg(ctx), DeviceID: deviceID, Username: username, LastSeenAt: at.UTC(),
		}); err != nil {
			return false, err
		}
		if err := q.LockLoginHistoryShared(ctx); err != nil {
			return false, err
		}
		s, err := q.GetLoginSettings(ctx)
		if err != nil || !s.LoginHistoryEnabled {
			return false, err
		}
		if (s.LoginHistoryEnabledAt != nil && at.Before(*s.LoginHistoryEnabledAt)) ||
			at.Before(now.AddDate(0, 0, -int(s.LoginHistoryDays))) {
			return false, nil
		}
		return false, q.InsertDeviceLoginEvent(ctx, pgstore.InsertDeviceLoginEventParams{
			ID: uuid.Must(uuid.NewV7()), OrganizationID: mustOrg(ctx), DeviceID: deviceID, Username: username, At: at.UTC(),
		})
	}}, true
}

// loginStateArea is the area of device_status.login_state an event updates: "login" for login.*, "sudo" for
// sudo.* (plan M3b decision 17), "local_admin" for the outcome of a rotation (plan M4a decision 17), "disk" for a
// keyslot change (plan M4b decision 14), "updates_regular" or "updates_security" for the last run of that kind (plan
// M5b decision 12), "" for every other event.
func loginStateArea(typ string, params map[string]any) string {
	if typ == protocol.EventUpdatesRun {
		switch kind := params["kind"]; kind {
		case protocol.UpdatesKindRegular, protocol.UpdatesKindSecurity:
			return "updates_" + kind.(string)
		}
		return ""
	}
	if typ == protocol.EventLocalAdminRotated || typ == protocol.EventLocalAdminRotationFailed {
		return "local_admin"
	}
	if typ == protocol.EventTamperKeyslotChanged {
		return "disk" // the last keyslot change, shown with the disk encryption (plan M4b decision 14)
	}
	area, _, _ := strings.Cut(typ, ".")
	if area == "login" || area == "sudo" {
		return area
	}
	return ""
}

// setLoginState records ev as the latest event of its area unless a newer one is recorded already.
func setLoginState(ctx context.Context, q *pgstore.Queries, deviceID, org uuid.UUID, area string, ev protocol.Event, params map[string]any) error {
	state, err := json.Marshal(map[string]any{"type": ev.Type, "occurred_at": params["occurred_at"], "params": params})
	if err != nil {
		return err
	}
	return q.SetDeviceLoginState(ctx, pgstore.SetDeviceLoginStateParams{DeviceID: deviceID, OrganizationID: org, Area: area, State: state})
}

// updateOutcomes are the agent update events the rollout evaluation counts (agent_update_report.outcome).
var updateOutcomes = map[string]string{
	protocol.EventAgentUpdated:      "updated",
	protocol.EventAgentUpdateFailed: "update_failed",
	protocol.EventAgentRolledBack:   "rolled_back",
}

// outcomeDowngradeRefused is the supervisor's outcome for a release that is not newer than the active agent
// (agent/internal/update.OutcomeDowngradeRefused).
const outcomeDowngradeRefused = "downgrade_refused"

// outcomeRollbackFailed is the supervisor's outcome for a release that failed its probation and whose flip back failed
// (agent/internal/update.OutcomeRollbackFailed, ADR 0024); it is also the agent_update_report outcome.
const outcomeRollbackFailed = "rollback_failed"

// outcomeSupervisorFailed is the agent_update_report outcome of a failed supervisor package upgrade: it counts toward
// the failure threshold of its release's rollout like a failed agent update (ADR 0037 amendment 2026-10-18, PDK-326).
const outcomeSupervisorFailed = "supervisor_failed"

// endsUpdateRequest reports whether a device event can end its update-now request: an agent update outcome or the
// supervisor package result.
func endsUpdateRequest(eventType string) bool {
	_, isUpdate := updateOutcomes[eventType]
	return isUpdate || eventType == protocol.EventAgentSupervisorUpdated
}

// clearUpdateRequest ends the device's update-now request for version. After agent.updated the request stays open
// until the device reports paddock-supervisor at that version, or while fleetd is outdated: under the manual policy only
// an open request lets the device upgrade them (ADR 0037 decision 3); the supervisor's result or the 24-hour expiry
// ends it then. A release without a supervisor package keeps the request until the expiry.
func clearUpdateRequest(ctx context.Context, q *pgstore.Queries, deviceID uuid.UUID, eventType, version string) error {
	if eventType == protocol.EventAgentUpdated {
		status, err := q.GetDeviceStatus(ctx, deviceID)
		if err != nil && !db.IsNoRows(err) {
			return err
		}
		if SupervisorBehind(status, version, false) || slices.Contains(status.ComponentsOutdated, components.Fleetd) {
			return nil
		}
	}
	_, err := q.ClearAgentUpdateRequest(ctx, pgstore.ClearAgentUpdateRequestParams{DeviceID: deviceID, Version: &version})
	return err
}

// SupervisorBehind reports whether the device's last health report names a paddock-supervisor other than version
// (the Debian form 0.1.0~alpha.1 counts as 0.1.0-alpha.1); unknown is what a device without a report counts as. The
// component target is no reference here: it follows the completed rollout only, while the supervisor package of a
// running rollout already reaches the waves (ADR 0037 amendment 2026-10-18).
func SupervisorBehind(status pgstore.DeviceStatus, version string, unknown bool) bool {
	installed, ok := HealthComponents(status.Health)[components.Supervisor]
	if !ok {
		return unknown
	}
	return strings.Replace(installed, "~", "-", 1) != version
}

// updateOutcome returns the agent_update_report outcome of an agent update event, if the rollout evaluation counts
// it. A refused downgrade never counts toward the failure rate (PDK-025): the device keeps its newer agent, so the
// release did not fail on it. A failed rollback is recorded as such, so the counts take it once with a later
// rolled_back of the same device. A supervisor upgrade that failed its local health (install_failed, rolled_back)
// counts as supervisor_failed; a rollback only because the server was unreachable (rolled_back_unreachable) does not:
// a server outage is no defect of the release (ADR 0037 amendment 2026-10-18, review 2 finding B).
func updateOutcome(eventType string, params map[string]any) (string, bool) {
	if eventType == protocol.EventAgentSupervisorUpdated {
		outcome := params["outcome"]
		return outcomeSupervisorFailed, outcome == protocol.SupervisorOutcomeInstallFailed || outcome == protocol.SupervisorOutcomeRolledBack
	}
	outcome, ok := updateOutcomes[eventType]
	if !ok || params["outcome"] == outcomeDowngradeRefused {
		return "", false
	}
	if eventType == protocol.EventAgentUpdateFailed && params["outcome"] == outcomeRollbackFailed {
		return outcomeRollbackFailed, true
	}
	return outcome, true
}

// Bounds of the device-reported values copied into audit params.
const (
	maxParamString = 256
	maxParamList   = 50
)

// eventParams copies the documented fields of an event (audit.deviceEventParams) with bounded sizes; other data a
// device sends is not recorded.
func eventParams(ev protocol.Event) map[string]any {
	params := map[string]any{"event_seq": ev.EventSeq, "occurred_at": audit.Timestamp(ev.OccurredAt).Format(time.RFC3339Nano)}
	var data map[string]any
	if json.Unmarshal(ev.Data, &data) != nil {
		return params
	}
	for _, key := range []string{"bundle_version", "changed", "count", "from_seq", "to_seq", "sessions_locked", "sessions_terminated", "generation", "upgraded"} {
		if v, ok := data[key].(float64); ok {
			params[key] = int64(v)
		}
	}
	for _, key := range []string{"reason", "resource", "from_version", "outcome", "stage", "message", "username", "group",
		"file", "quarantined_as", "sha256_before", "sha256_after", "service", "at", "field", "unit",
		"kind", "started_at", "finished_at", "result", "error", "volume", "command_id", "mode", "local_admin", "tpm"} {
		if v, ok := boundedString(data[key]); ok {
			params[key] = v
		}
	}
	for _, key := range []string{"removed", "reboot_required"} {
		if v, ok := data[key].(bool); ok {
			params[key] = v
		}
	}
	if changed, ok := data["changed"].([]any); ok { // login.applied: what changed
		params["changed"] = boundedStrings(changed)
	}
	switch v := data["version"].(type) { // a bundle version (number) or an agent version (string)
	case float64:
		params["bundle_version"] = int64(v)
	case string:
		if s, ok := boundedString(v); ok {
			params["version"] = s
		}
	}
	if ids, ok := data["resource_ids"].([]any); ok {
		params["resource_ids"] = boundedStrings(ids)
	}
	for _, key := range []string{"before", "after", "held_back"} { // keyslot kinds, packages kept back
		if kinds, ok := data[key].([]any); ok {
			params[key] = boundedStrings(kinds)
		}
	}
	if steps, ok := data["steps"].(map[string]any); ok { // agent.uninstalled
		params["steps"] = boundedSteps(steps)
	}
	if errs, ok := data["errors"].([]any); ok {
		out := []map[string]string{}
		for _, e := range errs[:min(len(errs), maxParamList)] {
			m, _ := e.(map[string]any)
			id, okID := boundedString(m["id"])
			msg, okMsg := boundedString(m["message"])
			if okID && okMsg {
				out = append(out, map[string]string{"id": id, "message": msg})
			}
		}
		params["errors"] = out
	}
	return params
}

// errUninstallResultPending: the removal report arrived before the worker recorded the command's result (separate
// queues); the event batch is retried until the result is recorded or the command expires.
var errUninstallResultPending = errors.New("uninstall report before its command result; retrying")

// markUninstalled sets device.uninstalled_at and keeps the reported outcome with the uninstall command — only for the
// device's open request whose command succeeded (review finding 2). Any other report (unsolicited, after a cancel, for
// another command) stays an audit event of the device and does not retire it.
func markUninstalled(ctx context.Context, q *pgstore.Queries, deviceID uuid.UUID, ev protocol.Event, params map[string]any) error {
	cmd, err := uuid.Parse(fmt.Sprint(params["command_id"]))
	if err != nil {
		slog.WarnContext(ctx, "removal report without a command ID; audited, device not retired", "device_id", deviceID)
		return nil
	}
	// The agent could not start the helper (plan M8d decision 39): nothing was removed, and the request ends so that
	// an administrator can request it again.
	if params["outcome"] == protocol.UninstallHelperFailed {
		_, err = q.EndFailedUninstall(ctx, pgstore.EndFailedUninstallParams{ID: deviceID, CommandID: cmd})
		return err
	}
	outcome := map[string]any{}
	for _, key := range []string{"outcome", "local_admin", "tpm"} {
		if v, ok := params[key]; ok {
			outcome[key] = v
		}
	}
	raw, err := json.Marshal(outcome)
	if err != nil {
		return err
	}
	n, err := q.MarkDeviceUninstalled(ctx, pgstore.MarkDeviceUninstalledParams{DeviceID: deviceID, CommandID: cmd,
		UninstalledAt: ev.OccurredAt, Outcome: raw})
	if err != nil || n == 1 {
		return err
	}
	pending, err := q.UninstallResultPending(ctx, pgstore.UninstallResultPendingParams{DeviceID: deviceID, CommandID: cmd})
	if err != nil {
		return err
	}
	if pending {
		return errUninstallResultPending
	}
	slog.WarnContext(ctx, "removal report without a matching uninstall request; audited, device not retired",
		"device_id", deviceID, "command_id", cmd)
	return nil
}

// boundedSteps copies at most protocol.MaxUninstallSteps bounded name → status pairs of agent.uninstalled.
func boundedSteps(steps map[string]any) map[string]string {
	names := slices.Sorted(maps.Keys(steps))
	out := map[string]string{}
	for _, name := range names[:min(len(names), protocol.MaxUninstallSteps)] {
		k, okK := boundedString(name)
		v, okV := boundedString(steps[name])
		if okK && okV {
			out[k] = v
		}
	}
	return out
}

// boundedStrings copies at most maxParamList bounded strings of a list.
func boundedStrings(list []any) []string {
	out := []string{}
	for _, v := range list[:min(len(list), maxParamList)] {
		if s, ok := boundedString(v); ok {
			out = append(out, s)
		}
	}
	return out
}

// boundedString is a device-supplied string without C0 control characters other than tab, newline and carriage
// return: PostgreSQL rejects NUL in jsonb and text, and one such event failed its whole batch (N2 review).
func boundedString(v any) (string, bool) {
	s, ok := v.(string)
	if !ok {
		return "", false
	}
	s = stripControls(s)
	return s, len(s) <= maxParamString
}

// stripControls drops the C0 control characters of s except tab, newline and carriage return.
func stripControls(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 && r != '\t' && r != '\n' && r != '\r' {
			return -1
		}
		return r
	}, s)
}
