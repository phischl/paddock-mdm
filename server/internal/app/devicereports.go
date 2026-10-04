package app

import (
	"context"
	"encoding/json"
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
		return q.UpsertDeviceStatus(ctx, pgstore.UpsertDeviceStatusParams{
			DeviceID: hb.DeviceID, OrganizationID: hb.OrganizationID, LastContactAt: &at,
			AppliedBundleVersion: &hb.AppliedBundleVersion, AgentVersion: &hb.AgentVersion, LastSeq: hb.Seq, Health: health,
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
}

// RecordEvent records one device event as an audit event with the device as actor, once per (device, event_seq).
// It reports whether the event was new.
func (d *DeviceReports) RecordEvent(ctx context.Context, deviceID uuid.UUID, ev protocol.Event) (bool, error) {
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
		return n == 1, err
	})
}

// eventParams copies the documented fields of an event; other data a device sends is not recorded.
func eventParams(ev protocol.Event) map[string]any {
	params := map[string]any{"event_seq": ev.EventSeq, "occurred_at": audit.Timestamp(ev.OccurredAt).Format(time.RFC3339Nano)}
	var data map[string]any
	if json.Unmarshal(ev.Data, &data) != nil {
		return params
	}
	if v, ok := data["bundle_version"].(float64); ok {
		params["bundle_version"] = int64(v)
	}
	for _, key := range []string{"reason", "resource"} {
		if v, ok := data[key].(string); ok && len(v) <= 256 {
			params[key] = v
		}
	}
	return params
}
