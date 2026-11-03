package app

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"slices"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/pkg/protocol"
	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/domain/device"
	"github.com/phischl/paddock-mdm/server/internal/domain/software"
	"github.com/phischl/paddock-mdm/server/internal/ingest"
)

// Bounds of the software status stored from a heartbeat (plan M13a §3.4), the column limits of
// device_software_status. A package or digest that is too long is dropped, never cut: two cut values could merge.
const (
	maxSoftwareDigest  = 128
	maxSoftwarePackage = 255
	maxSoftwareVersion = 128
	maxSoftwareReason  = 64
	maxSoftwareError   = 200
)

// softwareStatusRow is one item of the JSON array UpsertDeviceSoftwareStatus reads.
type softwareStatusRow struct {
	ID      string `json:"id"`
	Package string `json:"package"`
	Intent  string `json:"intent"`
	State   string `json:"state"`
	Version string `json:"version"`
	Reason  string `json:"reason"`
	Error   string `json:"error"`
}

// recordSoftwareStatus stores health.software of a heartbeat in the transaction of the status upsert (plan M13a
// §3.4): with items it replaces the device's rows (an empty list prunes them, an absent or null one is no report and
// keeps them, PDK-701), with a digest it stores the digest. The device's next report
// replaces the rows, so only the newest report counts: a heartbeat older than the one the status upsert kept
// (lastContactAt, read after that upsert under its row lock) and a device that is not active change nothing, as a
// clone or a retried heartbeat would otherwise write old state back. Anything the database would refuse is dropped
// here, so that a malformed report never fails the heartbeat.
func recordSoftwareStatus(ctx context.Context, q *pgstore.Queries, hb ingest.Heartbeat, health json.RawMessage, lastContactAt *time.Time) error {
	var h struct {
		Software *struct {
			Digest    string             `json:"digest"`
			Items     *[]json.RawMessage `json:"items"`
			Truncated bool               `json:"truncated"`
		} `json:"software"`
	}
	if err := json.Unmarshal(health, &h); err != nil {
		// A software part of the wrong shape is dropped as a whole; the device id is the only thing worth logging.
		slog.WarnContext(ctx, "software part of a health payload dropped: malformed", "device_id", hb.DeviceID)
		return nil
	}
	if h.Software == nil {
		return nil
	}
	if lastContactAt != nil && lastContactAt.After(hb.ReceivedAt) {
		return nil
	}
	dev, err := q.GetDevice(ctx, hb.DeviceID)
	if err != nil {
		return notFound(err)
	}
	if dev.State != device.StateActive {
		return nil
	}
	if items := h.Software.Items; items != nil {
		if err := replaceSoftwareStatus(ctx, q, hb, *items); err != nil {
			return err
		}
		if err := q.SetDeviceSoftwareTruncated(ctx, pgstore.SetDeviceSoftwareTruncatedParams{DeviceID: hb.DeviceID, Truncated: h.Software.Truncated}); err != nil {
			return fmt.Errorf("store whether the software report is truncated: %w", err)
		}
	}
	if digest := h.Software.Digest; digest != "" && len(digest) <= maxSoftwareDigest {
		if err := q.SetDeviceSoftwareDigest(ctx, pgstore.SetDeviceSoftwareDigestParams{DeviceID: hb.DeviceID, Digest: stripControls(digest)}); err != nil {
			return fmt.Errorf("store the software digest: %w", err)
		}
	}
	return nil
}

// replaceSoftwareStatus makes the items the device's rows: entries the report no longer names are deleted, the rest
// upserted. A report that names items but none a row can be made of (a misbehaving agent) leaves the rows alone
// instead of wiping them.
func replaceSoftwareStatus(ctx context.Context, q *pgstore.Queries, hb ingest.Heartbeat, items []json.RawMessage) error {
	rows := normalizeSoftwareRows(items)
	if len(items) > 0 && len(rows) == 0 {
		return nil
	}
	ids := make([]uuid.UUID, 0, len(rows))
	for _, r := range rows {
		ids = append(ids, uuid.MustParse(r.ID))
	}
	if err := q.DeleteDeviceSoftwareStatusNotIn(ctx, pgstore.DeleteDeviceSoftwareStatusNotInParams{
		DeviceID: hb.DeviceID, EntryIds: ids, ReportedAt: hb.ReceivedAt,
	}); err != nil {
		return fmt.Errorf("delete the software status the report dropped: %w", err)
	}
	if len(rows) == 0 {
		return nil
	}
	raw, err := json.Marshal(rows)
	if err != nil {
		return err
	}
	if err := q.UpsertDeviceSoftwareStatus(ctx, pgstore.UpsertDeviceSoftwareStatusParams{
		DeviceID: hb.DeviceID, OrganizationID: hb.OrganizationID, ReportedAt: hb.ReceivedAt, Rows: raw,
	}); err != nil {
		return fmt.Errorf("store the software status: %w", err)
	}
	return nil
}

// reportedIntents are the intents a device reports.
var reportedIntents = []string{software.IntentRequired, software.IntentUninstall, software.IntentHold, software.IntentForbid}

// normalizeSoftwareRows reads the first protocol.MaxSoftwareItems items, drops those that are malformed, have an ID that
// is not a UUID, an empty or too long package or an unknown intent or state, bounds the free text and keeps the last
// item of an entry: one statement cannot upsert a row twice.
func normalizeSoftwareRows(items []json.RawMessage) []softwareStatusRow {
	index := map[string]int{}
	out := make([]softwareStatusRow, 0, min(len(items), protocol.MaxSoftwareItems))
	for _, raw := range items[:min(len(items), protocol.MaxSoftwareItems)] {
		var it protocol.SoftwareItem
		if json.Unmarshal(raw, &it) != nil {
			continue
		}
		id, err := uuid.Parse(it.CatalogEntryID)
		pkg := stripControls(it.Package)
		if err != nil || pkg == "" || len(pkg) > maxSoftwarePackage ||
			!slices.Contains(reportedIntents, it.Intent) || !slices.Contains(protocol.SoftwareStates, it.State) {
			continue
		}
		row := softwareStatusRow{
			ID: id.String(), Package: pkg, Intent: it.Intent, State: it.State, Version: boundText(it.Version, maxSoftwareVersion),
			Reason: boundText(it.Reason, maxSoftwareReason), Error: boundText(it.Error, maxSoftwareError),
		}
		if i, ok := index[row.ID]; ok {
			out[i] = row
			continue
		}
		index[row.ID] = len(out)
		out = append(out, row)
	}
	return out
}
