package env

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/paddock-mdm/paddock/test/acceptance/internal/stack"
)

// AuditEvent is an event as the admin API returns it.
type AuditEvent struct {
	EventID       string         `json:"event_id"`
	Code          string         `json:"code"`
	Outcome       string         `json:"outcome"`
	ErrorCode     string         `json:"error_code"`
	CorrelationID string         `json:"correlation_id"`
	Params        map[string]any `json:"params"`
	Actor         struct {
		Type    string `json:"type"`
		Display string `json:"display"`
		StepUp  bool   `json:"step_up"`
	} `json:"actor"`
	Target *struct {
		Type string `json:"type"`
		ID   string `json:"id"`
	} `json:"target"`
}

// AuditEvents returns all events of the last 7 days visible to the portal session, newest first (at most the
// 10 000 the list contract can page through).
func (p *Portal) AuditEvents(ctx context.Context, code string) ([]AuditEvent, error) {
	var all []AuditEvent
	for page := 1; ; page++ {
		q := url.Values{"page_size": {"100"}, "page": {strconv.Itoa(page)}}
		if code != "" {
			q.Set("code", code)
		}
		res, err := p.Do(ctx, http.MethodGet, "/api/v1/audit-events?"+q.Encode(), nil)
		if err != nil {
			return nil, err
		}
		if res.Status != http.StatusOK {
			return nil, fmt.Errorf("audit-events: HTTP %d: %s", res.Status, res.Body)
		}
		var body struct {
			Items    []AuditEvent `json:"items"`
			Total    int          `json:"total"`
			PageSize int          `json:"page_size"`
		}
		if err := res.JSON(&body); err != nil {
			return nil, err
		}
		all = append(all, body.Items...)
		if page*body.PageSize >= body.Total {
			return all, nil
		}
	}
}

// EventsFor filters events by correlation ID.
func EventsFor(events []AuditEvent, correlationID string) []AuditEvent {
	var out []AuditEvent
	for _, e := range events {
		if e.CorrelationID == correlationID {
			out = append(out, e)
		}
	}
	return out
}

// AuditIndex reads the audit index directly as paddock_audit_reader (any organization, including the platform
// pseudo-organization, which no portal session can read).
type AuditIndex struct{ pool *pgxpool.Pool }

// NewAuditIndex connects to the audit database through the development port mapping.
func NewAuditIndex(ctx context.Context) (*AuditIndex, error) {
	dsn, err := stack.AuditIndexDSN()
	if err != nil {
		return nil, err
	}
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, err
	}
	return &AuditIndex{pool: pool}, nil
}

// Close closes the pool.
func (a *AuditIndex) Close() { a.pool.Close() }

// IndexEvent is an index row.
type IndexEvent struct {
	EventID       uuid.UUID
	Code          string
	Outcome       string
	CorrelationID string
	ObjectKey     string
	Params        map[string]any
	ActorDisplay  string
}

// Events returns the events of org matching where (a SQL condition on audit_event with $1 as argument).
func (a *AuditIndex) Events(ctx context.Context, org uuid.UUID, where string, arg any) ([]IndexEvent, error) {
	var out []IndexEvent
	err := pgx.BeginFunc(ctx, a.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "SELECT set_config('paddock.org_id', $1, true)", org.String()); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT event_id, code, outcome, correlation_id, object_key, params, coalesce(actor->>'display', '')
			FROM audit_event WHERE `+where+` ORDER BY occurred_at`, arg)
		if err != nil {
			return err
		}
		out, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (IndexEvent, error) {
			var e IndexEvent
			var params []byte
			if err := r.Scan(&e.EventID, &e.Code, &e.Outcome, &e.CorrelationID, &e.ObjectKey, &params, &e.ActorDisplay); err != nil {
				return e, err
			}
			return e, json.Unmarshal(params, &e.Params)
		})
		return err
	})
	return out, err
}
