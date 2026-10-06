package app

import (
	"context"
	"fmt"
	"time"

	"github.com/phischl/paddock-mdm/server/internal/adapters/auditpg/auditstore"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/problem"
)

// AuditLog reads the audit index of the caller's organization (read-only role, RLS).
type AuditLog struct {
	reader *db.AuditReader
	now    func() time.Time
}

// NewAuditLog creates the use case.
func NewAuditLog(reader *db.AuditReader) *AuditLog { return &AuditLog{reader: reader, now: time.Now} }

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
	Page       ListPage
}

// List returns one page of events and the capped number of matches (ADR 0018).
func (l *AuditLog) List(ctx context.Context, f AuditQuery) (Listed[auditstore.AuditEvent], error) {
	var out Listed[auditstore.AuditEvent]
	if _, err := RequireOrg(ctx, RolesAudit); err != nil {
		return out, err
	}
	to := l.now()
	if f.To != nil {
		to = *f.To
	}
	from := to.Add(-DefaultAuditRange)
	if f.From != nil {
		from = *f.From
	}
	if !from.Before(to) {
		return out, problem.InvalidRequest.WithDetail("from must be before to")
	}
	if to.Sub(from) > MaxAuditRange {
		return out, problem.RangeTooLarge.WithDetail("the range may span at most 92 days")
	}
	err := l.reader.InOrg(ctx, func(ctx context.Context, q *auditstore.Queries) error {
		n, err := q.CountAuditEvents(ctx, auditstore.CountAuditEventsParams{
			FromTime: from, ToTime: to, Codes: f.Codes, Outcomes: f.Outcomes, ActorTypes: f.ActorTypes,
			QPattern: f.Page.QPattern, CountLimit: countLimit,
		})
		if err != nil {
			return fmt.Errorf("count audit events: %w", err)
		}
		out.Count = int(n)
		out.Items, err = q.ListAuditEvents(ctx, auditstore.ListAuditEventsParams{
			FromTime: from, ToTime: to, Codes: f.Codes, Outcomes: f.Outcomes, ActorTypes: f.ActorTypes,
			QPattern: f.Page.QPattern, Sort: f.Page.Sort, SkipRows: f.Page.Offset, MaxRows: f.Page.Limit,
		})
		if err != nil {
			return fmt.Errorf("list audit events: %w", err)
		}
		return nil
	})
	return out, err
}
