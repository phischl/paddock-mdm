// Package auditwriter is the audit-writer role: it consumes audit events, writes the index (paddock_audit) and
// WORM objects (Object Lock COMPLIANCE), and seals a signed daily hash chain per organization (architecture §14).
package auditwriter

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"time"

	"github.com/google/uuid"
	"github.com/klauspost/compress/zstd"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/paddock-mdm/paddock/server/internal/adapters/auditpg/auditstore"
	"github.com/paddock-mdm/paddock/server/internal/domain/audit"
	"github.com/paddock-mdm/paddock/server/internal/platform/db"
	"github.com/paddock-mdm/paddock/server/internal/platform/objectstore"
)

// MinRetentionDays is the default retention of the audit bucket (rustfs-audit-bootstrap.sh). Shorter per-object
// retention is rejected at startup.
const MinRetentionDays = 400

var metricWritten = promauto.NewCounter(prometheus.CounterOpts{
	Name: "paddock_audit_events_written_total", Help: "Audit events written to the index and the WORM store.",
})

// ObjectStore is the subset of objectstore.Store the writer needs.
type ObjectStore interface {
	PutLocked(ctx context.Context, key, contentType string, body []byte, retainUntil time.Time) error
	Get(ctx context.Context, key string) ([]byte, error)
}

var _ ObjectStore = (*objectstore.Store)(nil)

// Writer writes batches of events.
type Writer struct {
	pool          *db.AuditWriterPool
	store         ObjectStore
	retentionDays int
	now           func() time.Time
}

// NewWriter creates a writer. retentionDays below MinRetentionDays is an error.
func NewWriter(pool *db.AuditWriterPool, store ObjectStore, retentionDays int) (*Writer, error) {
	if retentionDays < MinRetentionDays {
		return nil, fmt.Errorf("auditwriter: retention %d days is below the bucket default of %d days", retentionDays, MinRetentionDays)
	}
	return &Writer{pool: pool, store: store, retentionDays: retentionDays, now: time.Now}, nil
}

// RetainUntil is the retention date of everything recorded for day.
func (w *Writer) RetainUntil(day time.Time) time.Time {
	return dayOf(day).AddDate(0, 0, w.retentionDays)
}

// Validate checks the invariants of an incoming event.
func Validate(ev audit.Event) error {
	switch {
	case ev.Schema != audit.Schema:
		return fmt.Errorf("unknown schema %q", ev.Schema)
	case ev.EventID == uuid.Nil:
		return errors.New("missing event_id")
	case ev.Code == "":
		return errors.New("missing code")
	case ev.OccurredAt.IsZero():
		return errors.New("missing occurred_at")
	case ev.Outcome != audit.OutcomeSuccess && ev.Outcome != audit.OutcomeFailure &&
		ev.Outcome != audit.OutcomeDenied && ev.Outcome != audit.OutcomeUnknown:
		return fmt.Errorf("invalid outcome %q", ev.Outcome)
	case ev.Source == "" || ev.Actor.Type == "" || ev.CorrelationID == "":
		return errors.New("missing source, actor or correlation_id")
	}
	return nil
}

type groupKey struct {
	org  uuid.UUID
	hour time.Time
}

// WriteBatch writes events grouped by (organization, UTC hour), one transaction per group: ensure partition →
// insert ON CONFLICT DO NOTHING → write only the newly inserted events as one WORM object → insert audit_object →
// commit. It returns the number of newly written events. Duplicates (redelivery, relay restarts) are skipped.
func (w *Writer) WriteBatch(ctx context.Context, events []audit.Event) (int, error) {
	groups := map[groupKey][]audit.Event{}
	for _, ev := range events {
		ev.OccurredAt = audit.Timestamp(ev.OccurredAt)
		k := groupKey{org: ev.OrganizationID, hour: ev.OccurredAt.Truncate(time.Hour)}
		groups[k] = append(groups[k], ev)
	}
	keys := make([]groupKey, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if !keys[i].hour.Equal(keys[j].hour) {
			return keys[i].hour.Before(keys[j].hour)
		}
		return keys[i].org.String() < keys[j].org.String()
	})
	written := 0
	for _, k := range keys {
		n, err := w.writeGroup(ctx, k, groups[k])
		if err != nil {
			return written, err
		}
		written += n
	}
	return written, nil
}

func (w *Writer) writeGroup(ctx context.Context, k groupKey, events []audit.Event) (int, error) {
	sortEvents(events)
	events = dedupe(events)
	recordedAt := audit.Timestamp(w.now())
	written := 0
	err := w.pool.InWriter(ctx, func(ctx context.Context, q *auditstore.Queries) error {
		written = 0
		if err := q.EnsureAuditPartition(ctx, k.hour); err != nil {
			return err
		}
		fresh, err := w.withoutExisting(ctx, q, events)
		if err != nil {
			return err
		}
		if len(fresh) == 0 {
			return nil
		}
		key := ObjectKey(k.org, k.hour, fresh[0].EventID)
		var inserted []audit.Event
		for _, ev := range fresh {
			ev.RecordedAt = recordedAt
			row, err := indexRow(ev, key)
			if err != nil {
				return err
			}
			if _, err := q.InsertAuditEvent(ctx, row); err != nil {
				if db.IsNoRows(err) { // a concurrent writer inserted it first
					continue
				}
				return err
			}
			inserted = append(inserted, ev)
		}
		if len(inserted) == 0 {
			return nil
		}
		body, err := encodeObject(inserted)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(body)
		day := dayOf(k.hour)
		if err := w.store.PutLocked(ctx, key, "application/zstd", body, w.RetainUntil(day)); err != nil {
			return fmt.Errorf("auditwriter: put %s: %w", key, err)
		}
		if err := q.InsertAuditObject(ctx, auditstore.InsertAuditObjectParams{
			ObjectKey: key, OrganizationID: k.org, Day: day, EventCount: int32(len(inserted)), Sha256: sum[:], //nolint:gosec // batch size ≤ 500
		}); err != nil {
			return err
		}
		written = len(inserted)
		return nil
	})
	if err != nil {
		return 0, err
	}
	if written > 0 {
		metricWritten.Add(float64(written))
		slog.InfoContext(ctx, "audit object written", "organization_id", k.org, "hour", k.hour, "events", written)
	}
	return written, nil
}

// withoutExisting drops events already in the index, so the object key is derived from a new event.
func (w *Writer) withoutExisting(ctx context.Context, q *auditstore.Queries, events []audit.Event) ([]audit.Event, error) {
	out := make([]audit.Event, 0, len(events))
	for _, ev := range events {
		_, err := q.GetAuditEventTime(ctx, ev.EventID)
		switch {
		case err == nil:
			continue
		case db.IsNoRows(err):
			out = append(out, ev)
		default:
			return nil, err
		}
	}
	return out, nil
}

// ObjectKey is org/<organization_id>/<YYYY>/<MM>/<DD>/<HH>-<first event_id>.jsonl.zst.
func ObjectKey(org uuid.UUID, hour time.Time, first uuid.UUID) string {
	h := hour.UTC()
	return fmt.Sprintf("org/%s/%04d/%02d/%02d/%02d-%s.jsonl.zst", org, h.Year(), int(h.Month()), h.Day(), h.Hour(), first)
}

// ManifestKey is org/<organization_id>/manifests/<YYYY-MM-DD>.json.
func ManifestKey(org uuid.UUID, day time.Time) string {
	return fmt.Sprintf("org/%s/manifests/%s.json", org, day.UTC().Format(time.DateOnly))
}

func dayOf(t time.Time) time.Time {
	t = t.UTC()
	return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC)
}

func sortEvents(events []audit.Event) {
	sort.SliceStable(events, func(i, j int) bool {
		if !events[i].OccurredAt.Equal(events[j].OccurredAt) {
			return events[i].OccurredAt.Before(events[j].OccurredAt)
		}
		return events[i].EventID.String() < events[j].EventID.String()
	})
}

func dedupe(events []audit.Event) []audit.Event {
	seen := map[uuid.UUID]bool{}
	out := events[:0]
	for _, ev := range events {
		if !seen[ev.EventID] {
			seen[ev.EventID] = true
			out = append(out, ev)
		}
	}
	return out
}

func indexRow(ev audit.Event, key string) (auditstore.InsertAuditEventParams, error) {
	actor, err := json.Marshal(ev.Actor)
	if err != nil {
		return auditstore.InsertAuditEventParams{}, err
	}
	var target json.RawMessage
	if ev.Target != nil {
		if target, err = json.Marshal(ev.Target); err != nil {
			return auditstore.InsertAuditEventParams{}, err
		}
	}
	params := ev.Params
	if params == nil {
		params = map[string]any{}
	}
	if ev.ErrorCode != "" {
		// The index has no error_code column; it is part of the params stored with the event.
		params = cloneWith(params, "error_code", ev.ErrorCode)
	}
	p, err := json.Marshal(params)
	if err != nil {
		return auditstore.InsertAuditEventParams{}, err
	}
	return auditstore.InsertAuditEventParams{
		EventID: ev.EventID, OrganizationID: ev.OrganizationID, OccurredAt: ev.OccurredAt, RecordedAt: ev.RecordedAt,
		Code: string(ev.Code), Outcome: string(ev.Outcome), Source: ev.Source, Actor: actor, Target: target,
		Params: p, CorrelationID: ev.CorrelationID, ObjectKey: key,
	}, nil
}

func cloneWith(m map[string]any, k string, v any) map[string]any {
	out := make(map[string]any, len(m)+1)
	for kk, vv := range m {
		out[kk] = vv
	}
	out[k] = v
	return out
}

// encodeObject renders events as JSON lines and compresses them with zstd.
func encodeObject(events []audit.Event) ([]byte, error) {
	var raw bytes.Buffer
	enc := json.NewEncoder(&raw)
	for _, ev := range events {
		if err := enc.Encode(ev); err != nil {
			return nil, err
		}
	}
	zw, err := zstd.NewWriter(nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = zw.Close() }()
	return zw.EncodeAll(raw.Bytes(), nil), nil
}

// DecodeObject decompresses and parses a WORM object.
func DecodeObject(body []byte) ([]audit.Event, error) {
	zr, err := zstd.NewReader(nil)
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	raw, err := zr.DecodeAll(body, nil)
	if err != nil {
		return nil, err
	}
	var out []audit.Event
	dec := json.NewDecoder(bytes.NewReader(raw))
	for dec.More() {
		var ev audit.Event
		if err := dec.Decode(&ev); err != nil {
			return nil, err
		}
		out = append(out, ev)
	}
	return out, nil
}
