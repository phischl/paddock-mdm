package app

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/adapters/auditpg/auditstore"
	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/problem"
)

// AuditLog reads the audit index of the caller's organization (read-only role, RLS). The organization pool
// resolves the hostnames of the devices a page's events concern (plan M7c decision 30); the stored events are
// never modified.
type AuditLog struct {
	reader *db.AuditReader
	org    *db.OrgPool
	now    func() time.Time
}

// NewAuditLog creates the use case.
func NewAuditLog(reader *db.AuditReader, org *db.OrgPool) *AuditLog {
	return &AuditLog{reader: reader, org: org, now: time.Now}
}

// Range limits of the audit query (plan M0 §6.6).
const (
	DefaultAuditRange = 7 * 24 * time.Hour
	MaxAuditRange     = 92 * 24 * time.Hour
)

// AuditQuery filters the audit log. Nil filter slices match everything.
type AuditQuery struct {
	From, To   *time.Time
	Codes      []string
	Outcomes   []string
	ActorTypes []string
	// TargetID selects the events of one target (for example a device), exact match on target.id.
	TargetID *uuid.UUID
	Page     ListPage
	// Now is the clock the default range ends resolve against; zero means the use case's clock. A request sets it once
	// so its recording and its list search the same range (PDK-139).
	Now time.Time
}

// AuditDevice is the device an event concerns; Hostname is nil when the organization has no such device.
type AuditDevice struct {
	ID       uuid.UUID
	Hostname *string
}

// AuditListed is one page of events with the devices they concern, keyed by event_id (read-time enrichment).
type AuditListed struct {
	Items   []auditstore.AuditEvent
	Devices map[uuid.UUID]AuditDevice
	Count   int
}

// effectiveRange is the range the query searches at now (or at f.Now when set): to defaults to now, from to DefaultAuditRange before to; an
// empty or reversed range and one longer than MaxAuditRange are refused.
func (f AuditQuery) effectiveRange(now time.Time) (from, to time.Time, err error) {
	if !f.Now.IsZero() {
		now = f.Now
	}
	to = now
	if f.To != nil {
		to = *f.To
	}
	from = to.Add(-DefaultAuditRange)
	if f.From != nil {
		from = *f.From
	}
	if !from.Before(to) {
		return from, to, problem.InvalidRequest.WithDetail("from must be before to")
	}
	if to.Sub(from) > MaxAuditRange {
		return from, to, problem.RangeTooLarge.WithDetail("the range may span at most 92 days")
	}
	return from, to, nil
}

// List returns one page of events and the capped number of matches (ADR 0018).
func (l *AuditLog) List(ctx context.Context, f AuditQuery) (AuditListed, error) {
	var out AuditListed
	if _, err := RequireOrg(ctx, RolesAudit); err != nil {
		return out, err
	}
	from, to, err := f.effectiveRange(l.now())
	if err != nil {
		return out, err
	}
	var targetID *string
	if f.TargetID != nil {
		id := f.TargetID.String()
		targetID = &id
	}
	err = l.reader.InOrg(ctx, func(ctx context.Context, q *auditstore.Queries) error {
		n, err := q.CountAuditEvents(ctx, auditstore.CountAuditEventsParams{
			FromTime: from, ToTime: to, Codes: f.Codes, Outcomes: f.Outcomes, ActorTypes: f.ActorTypes, TargetID: targetID,
			QPattern: f.Page.QPattern, CountLimit: countLimit,
		})
		if err != nil {
			return fmt.Errorf("count audit events: %w", err)
		}
		out.Count = int(n)
		out.Items, err = q.ListAuditEvents(ctx, auditstore.ListAuditEventsParams{
			FromTime: from, ToTime: to, Codes: f.Codes, Outcomes: f.Outcomes, ActorTypes: f.ActorTypes, TargetID: targetID,
			QPattern: f.Page.QPattern, Sort: f.Page.Sort, SkipRows: f.Page.Offset, MaxRows: f.Page.Limit,
		})
		if err != nil {
			return fmt.Errorf("list audit events: %w", err)
		}
		return nil
	})
	if err != nil {
		return out, err
	}
	out.Devices, err = l.resolveDevices(ctx, out.Items)
	return out, err
}

// eventDeviceID is the device an event concerns: a target of type device, else params.device_id; uuid.Nil without.
func eventDeviceID(e auditstore.AuditEvent) uuid.UUID {
	var target struct {
		Type string `json:"type"`
		ID   string `json:"id"`
	}
	if len(e.Target) > 0 && json.Unmarshal(e.Target, &target) == nil && target.Type == "device" {
		if id, err := uuid.Parse(target.ID); err == nil {
			return id
		}
	}
	var params struct {
		DeviceID string `json:"device_id"`
	}
	if json.Unmarshal(e.Params, &params) == nil && params.DeviceID != "" {
		if id, err := uuid.Parse(params.DeviceID); err == nil {
			return id
		}
	}
	return uuid.Nil
}

// resolveDevices looks up the hostnames of the devices the events concern in one organization query; RLS bounds
// the result to the caller's organization, so a foreign or deleted device keeps a nil hostname.
func (l *AuditLog) resolveDevices(ctx context.Context, events []auditstore.AuditEvent) (map[uuid.UUID]AuditDevice, error) {
	devices := map[uuid.UUID]AuditDevice{}
	ids := map[uuid.UUID]bool{}
	for _, e := range events {
		if id := eventDeviceID(e); id != uuid.Nil {
			devices[e.EventID] = AuditDevice{ID: id}
			ids[id] = true
		}
	}
	if len(ids) == 0 {
		return devices, nil
	}
	lookup := make([]uuid.UUID, 0, len(ids))
	for id := range ids {
		lookup = append(lookup, id)
	}
	hostnames := map[uuid.UUID]string{}
	err := l.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		rows, err := q.ListDeviceHostnames(ctx, lookup)
		if err != nil {
			return fmt.Errorf("list device hostnames: %w", err)
		}
		for _, r := range rows {
			hostnames[r.ID] = r.Hostname
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	for eventID, d := range devices {
		if h, ok := hostnames[d.ID]; ok {
			d.Hostname = &h
			devices[eventID] = d
		}
	}
	return devices, nil
}
