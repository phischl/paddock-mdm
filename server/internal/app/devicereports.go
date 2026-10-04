package app

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/paddock-mdm/paddock/pkg/protocol"
	"github.com/paddock-mdm/paddock/server/internal/adapters/postgres/pgstore"
	"github.com/paddock-mdm/paddock/server/internal/domain/audit"
	"github.com/paddock-mdm/paddock/server/internal/domain/device"
	"github.com/paddock-mdm/paddock/server/internal/ingest"
	"github.com/paddock-mdm/paddock/server/internal/platform/db"
)

// DeviceReports turn heartbeats and events from devices into status, quarantine and audit events (worker, plan
// M2a decisions 12 and 14). The caller's context carries a system principal of the device's organization.
type DeviceReports struct {
	runner *ActionRunner
	org    *db.OrgPool
}

// NewDeviceReports creates the use cases.
func NewDeviceReports(runner *ActionRunner, org *db.OrgPool) *DeviceReports {
	return &DeviceReports{runner: runner, org: org}
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
		return q.UpsertDeviceStatus(ctx, pgstore.UpsertDeviceStatusParams{
			DeviceID: hb.DeviceID, OrganizationID: hb.OrganizationID, LastContactAt: &at,
			AppliedBundleVersion: &hb.AppliedBundleVersion, AgentVersion: &hb.AgentVersion, LastSeq: hb.Seq, Health: health,
			SchemaVersions: versions,
		})
	})
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

// eventCodes maps the closed set of device event types to audit codes.
var eventCodes = map[string]audit.Code{
	protocol.EventBundleApplied:        audit.CodeDeviceBundleApplied,
	protocol.EventBundleRejected:       audit.CodeDeviceBundleRejected,
	protocol.EventConfigDriftCorrected: audit.CodeDeviceConfigDriftCorrected,
	protocol.EventAgentUpdated:         audit.CodeDeviceAgentUpdated,
	protocol.EventAgentUpdateFailed:    audit.CodeDeviceAgentUpdateFailed,
	protocol.EventAgentRolledBack:      audit.CodeDeviceAgentRolledBack,
	protocol.EventAgentEventsDropped:   audit.CodeDeviceAgentEventsDropped,

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
}

// RecordEvent records one device event as an audit event with the device as actor, once per (device, event_seq).
// It reports whether the event was new.
func (d *DeviceReports) RecordEvent(ctx context.Context, deviceID uuid.UUID, ev protocol.Event) (bool, error) {
	if ev.Type == protocol.EventSessionLogin {
		return true, d.recordSessionLogin(ctx, deviceID, ev)
	}
	code, ok := eventCodes[ev.Type]
	if !ok {
		return false, nil // the gateway admits only known types; anything else is ignored
	}
	spec := ActionSpec{
		Code:   code,
		Actor:  &audit.Actor{Type: audit.ActorDevice, ID: deviceID.String()},
		Target: &audit.Target{Type: "device", ID: deviceID.String()},
		Params: eventParams(ev),
	}
	return d.runner.RecordOnce(ctx, spec, func(ctx context.Context, q *pgstore.Queries) (bool, error) {
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
		if outcome, ok := updateOutcomes[ev.Type]; ok {
			if version, ok := spec.Params["version"].(string); ok {
				err = q.InsertAgentUpdateReport(ctx, pgstore.InsertAgentUpdateReportParams{
					DeviceID: deviceID, OrganizationID: org, Version: version, Outcome: outcome,
				})
			}
		}
		if area := loginStateArea(ev.Type); area != "" && err == nil {
			err = setLoginState(ctx, q, deviceID, org, area, ev, spec.Params)
		}
		return true, err
	})
}

// recordSessionLogin notes that a user logged in on a device (device_user_seen, plan M3a decision 10); logins are not
// audited (privacy, volume), and a redelivered event only repeats the same upsert. A malformed event is ignored.
func (d *DeviceReports) recordSessionLogin(ctx context.Context, deviceID uuid.UUID, ev protocol.Event) error {
	var login protocol.SessionLogin
	if json.Unmarshal(ev.Data, &login) != nil {
		return nil
	}
	username := strings.ToLower(strings.TrimSpace(login.Username))
	if username == "" || len(username) > maxParamString {
		return nil
	}
	at := login.At
	if at.IsZero() || at.After(ev.OccurredAt.Add(time.Minute)) {
		at = ev.OccurredAt
	}
	return d.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		return q.UpsertDeviceUserSeen(ctx, pgstore.UpsertDeviceUserSeenParams{
			OrganizationID: mustOrg(ctx), DeviceID: deviceID, Username: username, LastSeenAt: at.UTC(),
		})
	})
}

// loginStateArea is the area of device_status.login_state an event updates: "login" for login.*, "sudo" for
// sudo.* (plan M3b decision 17), "" for every other event.
func loginStateArea(typ string) string {
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
	for _, key := range []string{"bundle_version", "changed", "count", "from_seq", "to_seq", "sessions_locked", "sessions_terminated"} {
		if v, ok := data[key].(float64); ok {
			params[key] = int64(v)
		}
	}
	for _, key := range []string{"reason", "resource", "from_version", "outcome", "stage", "message", "username", "group",
		"file", "quarantined_as", "sha256_before", "sha256_after"} {
		if v, ok := boundedString(data[key]); ok {
			params[key] = v
		}
	}
	if v, ok := data["removed"].(bool); ok {
		params["removed"] = v
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

func boundedString(v any) (string, bool) {
	s, ok := v.(string)
	return s, ok && len(s) <= maxParamString
}
