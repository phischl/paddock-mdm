package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/problem"
)

// Views of a device's inventory that InventoryViewed records (plan M10 decision 19).
const (
	InventoryViewSoftware        = "software"
	InventoryViewVulnerabilities = "vulnerabilities"
)

// SpecAuditSearched records a search of the audit log (plan M10 decision 19).
var SpecAuditSearched = ActionSpec{Code: audit.CodeAuditSearched, AllowedRoles: RolesAudit}

// SpecInventoryViewed records a view of a device's software or vulnerabilities (plan M10 decision 19).
var SpecInventoryViewed = ActionSpec{Code: audit.CodeDeviceInventoryViewed, AllowedRoles: RolesRead}

// ReadAudit records reads of the audit log and of device inventory, at most once per actor and window and only while
// the organization's privacy settings switch them on (ADR 0032 §4, plan M10 §3.4).
type ReadAudit struct {
	runner *ActionRunner
	now    func() time.Time
}

// NewReadAudit creates the use cases.
func NewReadAudit(runner *ActionRunner) *ReadAudit {
	return &ReadAudit{runner: runner, now: time.Now}
}

// AuditSearched records the search q of the audit log as audit.searched, once per actor, clock hour and set of
// filters, while audit_search_recorded is on. It records the filters of the effective range, never the search text.
// While recording is on, a refused search is recorded as failure and refused: invalid is the input error the handler
// found (or nil), and a range the list refuses is refused here. A role that may not read the audit log is recorded as
// denied and refused.
func (r *ReadAudit) AuditSearched(ctx context.Context, q AuditQuery, invalid error) (bool, error) {
	now := r.now()
	enabled := func(ctx context.Context, qs *pgstore.Queries) (bool, error) {
		s, err := LoadPrivacySettings(ctx, qs)
		return s.AuditSearchRecorded, err
	}
	return r.runner.RecordReadOnce(ctx, SpecAuditSearched, enabled, func(ctx context.Context, qs *pgstore.Queries, rec Recorder) (bool, error) {
		if invalid != nil {
			return false, invalid
		}
		from, to, err := q.effectiveRange(now)
		if err != nil {
			return false, err
		}
		f, err := newSearchFilters(ctx, qs, q)
		if err != nil {
			return false, err
		}
		window := now.UTC().Truncate(time.Hour)
		filterKey, err := f.key()
		if err != nil {
			return false, err
		}
		if fresh, err := claimReadWindow(ctx, qs, audit.CodeAuditSearched, filterKey, window); err != nil || !fresh {
			return false, err
		}
		rec.SetParam("from", audit.Timestamp(from).Format(time.RFC3339Nano))
		rec.SetParam("to", audit.Timestamp(to).Format(time.RFC3339Nano))
		if f.CodesUnknown > 0 {
			rec.SetParam("codes_unknown", f.CodesUnknown)
		}
		for key, values := range map[string][]string{"codes": f.Codes, "outcomes": f.Outcomes, "actor_types": f.ActorTypes} {
			if len(values) > 0 {
				rec.SetParam(key, values)
			}
		}
		if f.TargetID != "" {
			rec.SetParam("target_id", f.TargetID)
		}
		if f.TargetIDUsed {
			rec.SetParam("target_id_used", true)
		}
		rec.SetParam("q_used", f.QUsed)
		rec.SetParam("window_start", window.Format(time.RFC3339))
		return true, nil
	})
}

// searchFilters are the filters of an audit search as recorded, and as the window keys them. The range is the
// requested one (empty for a default end), so a search with the default range keeps its key within the hour while
// its effective range moves with the clock. The search text is not part of it: its events must not tell two texts
// apart (plan M10 amendment 2026-10-30, PDK-139 round 2).
type searchFilters struct {
	From         string   `json:"from"`
	To           string   `json:"to"`
	Codes        []string `json:"codes"`
	CodesUnknown int      `json:"codes_unknown"`
	Outcomes     []string `json:"outcomes"`
	ActorTypes   []string `json:"actor_types"`
	TargetID     string   `json:"target_id"`
	TargetIDUsed bool     `json:"target_id_used"`
	QUsed        bool     `json:"q_used"`
}

// newSearchFilters normalizes the filters of q (sorted, without duplicates). The target is kept only when it is a
// device of the caller's organization: an ID of another organization's object, sent by whoever, must not enter this
// organization's audit trail, so it is recorded as target_id_used only.
func newSearchFilters(ctx context.Context, qs *pgstore.Queries, q AuditQuery) (searchFilters, error) {
	f := searchFilters{
		Outcomes: normalizedSet(q.Outcomes), ActorTypes: normalizedSet(q.ActorTypes), QUsed: q.Page.QPattern != nil,
	}
	f.Codes, f.CodesUnknown = registeredCodes(normalizedSet(q.Codes))
	if q.From != nil {
		f.From = audit.Timestamp(*q.From).Format(time.RFC3339Nano)
	}
	if q.To != nil {
		f.To = audit.Timestamp(*q.To).Format(time.RFC3339Nano)
	}
	if q.TargetID != nil {
		_, err := qs.GetDevice(ctx, *q.TargetID)
		switch {
		case db.IsNoRows(err):
			f.TargetIDUsed = true
		case err != nil:
			return f, fmt.Errorf("resolve audit search target: %w", err)
		default:
			f.TargetID = q.TargetID.String()
		}
	}
	return f, nil
}

// key is the window key of the filters: a hash, so the key column holds neither filter values nor their length.
func (f searchFilters) key() (string, error) {
	b, err := json.Marshal(f)
	if err != nil {
		return "", fmt.Errorf("audit search filters: %w", err)
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

func normalizedSet(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	return slices.Compact(slices.Sorted(slices.Values(values)))
}

// registeredCodes keeps the codes of the registry and counts the others: the code filter is free text, and free text
// must not reach the audit trail any more than the search text does (only q_used is recorded).
func registeredCodes(codes []string) (known []string, unknown int) {
	for _, c := range codes {
		if _, ok := audit.Lookup(audit.Code(c)); ok {
			known = append(known, c)
		} else {
			unknown++
		}
	}
	return known, unknown
}

// InventoryViewed records the view (InventoryViewSoftware or InventoryViewVulnerabilities) of the device's inventory
// as device.inventory_viewed, once per actor, device and UTC day, while inventory_view_recorded is on. While recording
// is on, a refused view is recorded as failure and refused: invalid is the input error the handler found (or nil),
// and a missing or foreign device is not_found. The device is the event's target only once it resolved within the
// caller's organization; otherwise only target_id_used is recorded, so another organization's device ID never enters
// this organization's audit trail.
func (r *ReadAudit) InventoryViewed(ctx context.Context, deviceID uuid.UUID, view string, invalid error) (bool, error) {
	now := r.now()
	enabled := func(ctx context.Context, qs *pgstore.Queries) (bool, error) {
		s, err := LoadPrivacySettings(ctx, qs)
		return s.InventoryViewRecorded, err
	}
	return r.runner.RecordReadOnce(ctx, SpecInventoryViewed, enabled, func(ctx context.Context, qs *pgstore.Queries, rec Recorder) (bool, error) {
		rec.SetParam("view", view)
		if invalid != nil {
			rec.SetParam("target_id_used", true)
			return false, invalid
		}
		dev, err := qs.GetDevice(ctx, deviceID)
		if err != nil {
			rec.SetParam("target_id_used", true)
			if db.IsNoRows(err) {
				return false, problem.NotFound
			}
			return false, fmt.Errorf("device of the inventory view: %w", err)
		}
		rec.SetTarget(audit.Target{Type: "device", ID: deviceID.String(), Display: dev.Hostname})
		rec.SetParam("hostname", dev.Hostname)
		window := now.UTC().Truncate(24 * time.Hour)
		if fresh, err := claimReadWindow(ctx, qs, audit.CodeDeviceInventoryViewed, deviceID.String(), window); err != nil || !fresh {
			return false, err
		}
		rec.SetParam("window_start", window.Format(time.RFC3339))
		return true, nil
	})
}

// claimReadWindow claims the window key of the context's principal; key is the device of an inventory view or the
// filter hash of an audit search. The actor is the principal: its account, or its API token when it authenticated
// with one (plan M10 amendment A5), so a portal and an MCP session of the same account share their windows.
func claimReadWindow(ctx context.Context, q *pgstore.Queries, code audit.Code, key string, window time.Time) (bool, error) {
	p, _ := principal.From(ctx)
	actor := p.ID
	if p.APITokenID != uuid.Nil {
		actor = p.APITokenID
	}
	_, err := q.ClaimReadAuditWindow(ctx, pgstore.ClaimReadAuditWindowParams{
		OrganizationID: p.OrganizationID, ActorID: actor.String(), Code: string(code), TargetID: key, WindowStart: window,
	})
	if db.IsNoRows(err) {
		return false, nil
	}
	return err == nil, err
}
