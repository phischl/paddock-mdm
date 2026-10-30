package app

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/principal"
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

// AuditSearched records the search q of the audit log as audit.searched, once per actor and clock hour, while
// audit_search_recorded is on. It records the filters of the effective range, never the search text; a query whose
// range the list refuses records nothing. A role that may not read the audit log is recorded as denied and refused.
func (r *ReadAudit) AuditSearched(ctx context.Context, q AuditQuery) (bool, error) {
	now := r.now()
	return r.runner.RecordReadOnce(ctx, SpecAuditSearched, func(ctx context.Context, qs *pgstore.Queries, rec Recorder) (bool, error) {
		s, err := LoadPrivacySettings(ctx, qs)
		if err != nil || !s.AuditSearchRecorded {
			return false, err
		}
		from, to, err := q.effectiveRange(now)
		if err != nil {
			return false, nil
		}
		window := now.UTC().Truncate(time.Hour)
		if fresh, err := claimReadWindow(ctx, qs, audit.CodeAuditSearched, "", window); err != nil || !fresh {
			return false, err
		}
		rec.SetParam("from", audit.Timestamp(from).Format(time.RFC3339Nano))
		rec.SetParam("to", audit.Timestamp(to).Format(time.RFC3339Nano))
		codes, unknown := registeredCodes(q.Codes)
		if unknown > 0 {
			rec.SetParam("codes_unknown", unknown)
		}
		for key, values := range map[string][]string{"codes": codes, "outcomes": q.Outcomes, "actor_types": q.ActorTypes} {
			if len(values) > 0 {
				rec.SetParam(key, values)
			}
		}
		if q.TargetID != nil {
			rec.SetParam("target_id", q.TargetID.String())
		}
		rec.SetParam("q_used", q.Page.QPattern != nil)
		rec.SetParam("window_start", window.Format(time.RFC3339))
		return true, nil
	})
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
// as device.inventory_viewed, once per actor, device and UTC day, while inventory_view_recorded is on. A missing or
// foreign device records nothing; the list answers not_found.
func (r *ReadAudit) InventoryViewed(ctx context.Context, deviceID uuid.UUID, view string) (bool, error) {
	now := r.now()
	return r.runner.RecordReadOnce(ctx, SpecInventoryViewed, func(ctx context.Context, qs *pgstore.Queries, rec Recorder) (bool, error) {
		s, err := LoadPrivacySettings(ctx, qs)
		if err != nil || !s.InventoryViewRecorded {
			return false, err
		}
		dev, err := qs.GetDevice(ctx, deviceID)
		if db.IsNoRows(err) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		window := now.UTC().Truncate(24 * time.Hour)
		if fresh, err := claimReadWindow(ctx, qs, audit.CodeDeviceInventoryViewed, deviceID.String(), window); err != nil || !fresh {
			return false, err
		}
		rec.SetTarget(audit.Target{Type: "device", ID: deviceID.String(), Display: dev.Hostname})
		rec.SetParam("hostname", dev.Hostname)
		rec.SetParam("view", view)
		rec.SetParam("window_start", window.Format(time.RFC3339))
		return true, nil
	})
}

// claimReadWindow claims the window of the context's principal: its account, or its API token when it authenticated
// with one (plan M10 amendment A5), so a portal and an MCP session of the same account share their windows.
func claimReadWindow(ctx context.Context, q *pgstore.Queries, code audit.Code, target string, window time.Time) (bool, error) {
	p, _ := principal.From(ctx)
	actor := p.ID
	if p.APITokenID != uuid.Nil {
		actor = p.APITokenID
	}
	_, err := q.ClaimReadAuditWindow(ctx, pgstore.ClaimReadAuditWindowParams{
		OrganizationID: p.OrganizationID, ActorID: actor.String(), Code: string(code), TargetID: target, WindowStart: window,
	})
	if db.IsNoRows(err) {
		return false, nil
	}
	return err == nil, err
}
