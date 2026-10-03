package app

import (
	"context"
	"time"

	"github.com/paddock-mdm/paddock/server/internal/adapters/auditpg/auditstore"
	"github.com/paddock-mdm/paddock/server/internal/platform/db"
	"github.com/paddock-mdm/paddock/server/internal/problem"
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

// AuditQuery filters the audit log.
type AuditQuery struct {
	From, To *time.Time
	Code     *string
	Cursor   *string
	Limit    *int
}

// AuditPage is one page of events.
type AuditPage struct {
	Items      []auditstore.AuditEvent
	NextCursor *string
}

// List returns events ordered by occurred_at, event_id descending.
func (l *AuditLog) List(ctx context.Context, f AuditQuery) (AuditPage, error) {
	if _, err := RequireOrg(ctx, RolesAudit); err != nil {
		return AuditPage{}, err
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
		return AuditPage{}, problem.InvalidRequest.WithDetail("from must be before to")
	}
	if to.Sub(from) > MaxAuditRange {
		return AuditPage{}, problem.RangeTooLarge.WithDetail("the range may span at most 92 days")
	}
	cursor, err := DecodeCursor(f.Cursor)
	if err != nil {
		return AuditPage{}, err
	}
	n, err := PageLimit(f.Limit)
	if err != nil {
		return AuditPage{}, err
	}
	var page AuditPage
	err = l.reader.InOrg(ctx, func(ctx context.Context, q *auditstore.Queries) error {
		params := auditstore.ListAuditEventsParams{FromTime: from, ToTime: to, Code: f.Code, MaxRows: n + 1}
		if cursor.Valid {
			at, err := q.GetAuditEventTime(ctx, cursor.UUID)
			if db.IsNoRows(err) {
				return problem.InvalidRequest.WithDetail("invalid cursor")
			}
			if err != nil {
				return err
			}
			params.CursorTime, params.CursorID = &at, cursor
		}
		rows, err := q.ListAuditEvents(ctx, params)
		if err != nil {
			return err
		}
		if len(rows) > int(n) {
			rows = rows[:n]
			c := EncodeCursor(rows[len(rows)-1].EventID)
			page.NextCursor = &c
		}
		page.Items = rows
		return nil
	})
	return page, err
}
