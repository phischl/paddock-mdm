package app

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/pkg/protocol"
	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
)

// Bounds of the apply status stored from a device's report (plan M11 decision 13). A device that names more resources
// than maxStatusResources has the rest ignored: the bundle of a device has tens of resources, so the bound only
// protects the worker from a misbehaving agent.
const (
	maxStatusResources = 1000
	maxStatusID        = 256
	maxStatusMessage   = 1024
	maxStatusChange    = 256
	maxStatusChanges   = 50
)

// configStatusEvent reports whether an event type updates the device's apply status.
func configStatusEvent(eventType string) bool {
	switch eventType {
	case protocol.EventBundleApplied, protocol.EventBundleRejected, protocol.EventConfigDriftCorrected:
		return true
	}
	return false
}

// statusRow is one resource of the JSON array UpsertDeviceResourceStatuses reads.
type statusRow struct {
	ID      string   `json:"id"`
	Status  string   `json:"status"`
	Message string   `json:"message"`
	Changes []string `json:"changes"`
}

// recordConfigStatus stores what the event says about the device's apply status, in the transaction of the event
// (plan M11 decision 13): the report of the bundle version and the per-resource status. Anything the database would
// refuse is dropped here instead, so that a malformed report never fails the event batch.
func recordConfigStatus(ctx context.Context, q *pgstore.Queries, org, deviceID uuid.UUID, ev protocol.Event) error {
	var data struct {
		Version     int64              `json:"version"`
		Changed     int64              `json:"changed"`
		Mode        string             `json:"mode"`
		Reason      *string            `json:"reason"`
		Errors      []json.RawMessage  `json:"errors"`
		Resources   *[]json.RawMessage `json:"resources"`
		ResourceIDs []string           `json:"resource_ids"`
	}
	if json.Unmarshal(ev.Data, &data) != nil || data.Version <= 0 {
		return nil
	}
	at := ev.OccurredAt
	if at.IsZero() {
		return nil
	}
	if err := q.LockDeviceConfigStatus(ctx, deviceID); err != nil {
		return fmt.Errorf("lock the apply status of the device: %w", err)
	}
	if ev.Type == protocol.EventBundleRejected {
		return recordRejection(ctx, q, org, deviceID, data.Version, data.Reason, at)
	}
	// Newer wins (plan M11 decision 13): the occurred_at guards of the queries protect only rows that exist, so a late
	// older event would insert again what a newer report removed.
	newer, err := q.HasNewerAppliedBundleReport(ctx, pgstore.HasNewerAppliedBundleReportParams{DeviceID: deviceID, OccurredAt: at})
	if err != nil {
		return fmt.Errorf("check for a newer apply report: %w", err)
	}
	if ev.Type == protocol.EventConfigDriftCorrected {
		if newer {
			return nil
		}
		rows := make([]statusRow, 0, len(data.ResourceIDs))
		for _, id := range data.ResourceIDs {
			rows = append(rows, statusRow{ID: id, Status: protocol.ResourceDriftCorrected})
		}
		return upsertResourceStatuses(ctx, q, org, deviceID, data.Version, at, normalizeStatusRows(rows))
	}
	mode := protocol.BundleModeEnforce
	if data.Mode == protocol.BundleModeReportOnly {
		mode = protocol.BundleModeReportOnly
	}
	changed := int32(min(max(data.Changed, 0), 1<<31-1)) //nolint:gosec // clamped to int32 above
	if err := q.UpsertDeviceBundleReport(ctx, pgstore.UpsertDeviceBundleReportParams{
		DeviceID: deviceID, OrganizationID: org, Version: data.Version, Outcome: "applied", Mode: mode, Changed: changed,
		ErrorCount: int32(min(len(data.Errors), 1<<31-1)), //nolint:gosec // clamped to int32 above
		OccurredAt: at,
	}); err != nil {
		return err
	}
	if newer {
		return nil
	}
	if data.Resources != nil {
		rows := make([]statusRow, 0, len(*data.Resources))
		for _, raw := range *data.Resources {
			var r statusRow
			if json.Unmarshal(raw, &r) != nil {
				continue
			}
			switch r.Status {
			case protocol.ResourceApplied, protocol.ResourceFailed, protocol.ResourcePending:
				rows = append(rows, r)
			}
		}
		rows = normalizeStatusRows(rows)
		if err := q.DeleteDeviceResourceStatusNotIn(ctx, pgstore.DeleteDeviceResourceStatusNotInParams{
			DeviceID: deviceID, ResourceIds: statusIDs(rows), OccurredAt: at,
		}); err != nil {
			return err
		}
		return upsertResourceStatuses(ctx, q, org, deviceID, data.Version, at, rows)
	}
	// An agent without per-resource outcomes (before plan M11) reports only its failures.
	rows := make([]statusRow, 0, len(data.Errors))
	for _, raw := range data.Errors {
		var e struct {
			ID      string `json:"id"`
			Message string `json:"message"`
		}
		if json.Unmarshal(raw, &e) == nil {
			rows = append(rows, statusRow{ID: e.ID, Status: protocol.ResourceFailed, Message: e.Message})
		}
	}
	rows = normalizeStatusRows(rows)
	if err := q.DeleteFailedDeviceResourceStatusNotIn(ctx, pgstore.DeleteFailedDeviceResourceStatusNotInParams{
		DeviceID: deviceID, ResourceIds: statusIDs(rows), OccurredAt: at,
	}); err != nil {
		return err
	}
	return upsertResourceStatuses(ctx, q, org, deviceID, data.Version, at, rows)
}

// recordRejection stores the device's rejection of a bundle version. The event carries no mode, so the report takes
// the mode of the device's last applied report before it, enforce when there is none (the agent's default).
func recordRejection(ctx context.Context, q *pgstore.Queries, org, deviceID uuid.UUID, version int64, why *string, at time.Time) error {
	var reason *string
	if why != nil {
		r := boundText(*why, maxParamString)
		reason = &r
	}
	mode, err := q.GetLatestAppliedBundleMode(ctx, pgstore.GetLatestAppliedBundleModeParams{DeviceID: deviceID, OccurredAt: at})
	switch {
	case db.IsNoRows(err):
		mode = protocol.BundleModeEnforce
	case err != nil:
		return fmt.Errorf("read the mode of the last applied report: %w", err)
	}
	return q.UpsertDeviceBundleReport(ctx, pgstore.UpsertDeviceBundleReportParams{
		DeviceID: deviceID, OrganizationID: org, Version: version, Outcome: "rejected", Mode: mode, Reason: reason, OccurredAt: at,
	})
}

// upsertResourceStatuses stores normalized rows.
func upsertResourceStatuses(ctx context.Context, q *pgstore.Queries, org, deviceID uuid.UUID, version int64, at time.Time, rows []statusRow) error {
	if len(rows) == 0 {
		return nil
	}
	raw, err := json.Marshal(rows)
	if err != nil {
		return err
	}
	return q.UpsertDeviceResourceStatuses(ctx, pgstore.UpsertDeviceResourceStatusesParams{
		DeviceID: deviceID, OrganizationID: org, BundleVersion: version, OccurredAt: at, Rows: raw,
	})
}

// normalizeStatusRows bounds the values, drops entries without an ID and keeps the last entry of a resource: one
// statement cannot upsert a resource twice.
func normalizeStatusRows(rows []statusRow) []statusRow {
	index := map[string]int{}
	out := make([]statusRow, 0, len(rows))
	for _, r := range rows {
		r.ID = boundText(r.ID, maxStatusID)
		if r.ID == "" {
			continue
		}
		r.Message = boundText(r.Message, maxStatusMessage)
		changes := make([]string, 0, min(len(r.Changes), maxStatusChanges))
		for _, c := range r.Changes[:min(len(r.Changes), maxStatusChanges)] {
			changes = append(changes, boundText(c, maxStatusChange))
		}
		r.Changes = changes
		if i, ok := index[r.ID]; ok {
			out[i] = r
			continue
		}
		if len(out) == maxStatusResources {
			continue
		}
		index[r.ID] = len(out)
		out = append(out, r)
	}
	return out
}

// statusIDs lists the resource IDs of the rows; never nil, because a nil list reaches the database as NULL.
func statusIDs(rows []statusRow) []string {
	ids := make([]string, 0, len(rows))
	for _, r := range rows {
		ids = append(ids, r.ID)
	}
	return ids
}

// boundText strips control characters and cuts s to at most limit bytes at a character boundary.
func boundText(s string, limit int) string {
	s = stripControls(s)
	if len(s) <= limit {
		return s
	}
	s = s[:limit]
	for !utf8.ValidString(s) {
		s = s[:len(s)-1]
	}
	return s
}
