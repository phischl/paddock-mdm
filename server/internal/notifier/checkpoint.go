package notifier

import (
	"context"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
	"github.com/phischl/paddock-mdm/server/internal/domain/outbound"
)

// serveCheckpoints sends the checkpoints of the scope's sealed days after last_checkpoint_day that are due, in day
// order, each numbered in forward_seq (plan M12 decision 20). Nothing is sent while a delivery is pending, a replay
// runs or the destination waits for its backoff; a failure is retried like a batch.
func (e *Engine) serveCheckpoints(ctx context.Context, dr *destRound) error {
	if !dr.d.Checkpoints || dr.st.Pending != uuid.Nil || dr.st.ReplayFrom > 0 ||
		(dr.st.NextAttemptAt != nil && dr.st.NextAttemptAt.After(e.now())) {
		return nil
	}
	// Days sealed before the destination existed are never sent: the initial cursor is the day before its creation.
	after := utcDay(dr.d.CreatedAt).AddDate(0, 0, -1)
	if dr.st.LastCheckpointDay != nil {
		after = utcDay(*dr.st.LastCheckpointDay)
	}
	manifests, err := e.index.ManifestsAfter(ctx, dr.sc, after, MaxDeliveriesPerRound)
	if err != nil || len(manifests) == 0 {
		return wrap("sealed days", err)
	}
	forwardedUntil, err := e.forwardedUntil(ctx, dr)
	if err != nil {
		return err
	}
	start := e.now()
	for _, m := range manifests {
		if forwardedUntil.Before(m.Day.AddDate(0, 0, 1)) || e.now().Sub(start) >= DestinationBudget {
			return nil
		}
		count, err := e.index.CountRecordedOn(ctx, dr.sc, m.Day)
		if err != nil {
			return fmt.Errorf("count events of %s: %w", m.Day.Format(time.DateOnly), err)
		}
		b := batch{id: e.newID(), checkpoint: true, seq: dr.st.ForwardSeq + 1, day: m.Day, eventCount: count}
		if err := e.store.CreateCheckpoint(ctx, dr.sc, dr.d.ID, NewCheckpoint{
			ID: b.id, ForwardSeq: b.seq, Day: b.day, EventCount: b.eventCount,
		}); err != nil {
			return fmt.Errorf("create checkpoint: %w", err)
		}
		dr.st.ForwardSeq, dr.st.Pending, dr.st.PendingFrom = b.seq, b.id, b.seq
		ok, err := e.deliverCheckpoint(ctx, dr, b)
		if err != nil || !ok || dr.st.NextAttemptAt != nil {
			return err
		}
	}
	return nil
}

// forwardedUntil is the recording time up to which the destination has forwarded every matching event: the far future
// when it is caught up (the cursor is the scope's latest, or no event after it matches), else the earliest recording
// time of the matching events in the scanned window after the cursor, or, when the window matches nothing, the later
// of the recording times of the event at the cursor (plan M12 decision 20) and of the window's last event. A day D is
// due when this is at or after D + 1 day.
func (e *Engine) forwardedUntil(ctx context.Context, dr *destRound) (time.Time, error) {
	caughtUp := time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC)
	latest, err := e.index.Latest(ctx, dr.sc)
	if err != nil {
		return time.Time{}, fmt.Errorf("latest commit sequence: %w", err)
	}
	if dr.st.Cursor >= latest {
		return caughtUp, nil
	}
	var until time.Time
	ev, found, err := e.index.EventAt(ctx, dr.sc, dr.st.Cursor)
	if err != nil {
		return time.Time{}, fmt.Errorf("event at the cursor: %w", err)
	}
	if found {
		until = ev.Event.RecordedAt
	}
	// The cursor stays at the last delivered event while the events after it match nothing (cut moves it only past a
	// full window), so the first undelivered matching event bounds what was forwarded.
	events, err := e.index.After(ctx, dr.sc, dr.st.Cursor, ScanWindow)
	if err != nil {
		return time.Time{}, fmt.Errorf("scan index: %w", err)
	}
	// recorded_at is the audit-writer's transaction time, and two replicas can commit an event of day D after one of
	// D + 1: the earliest undelivered matching event bounds what was forwarded, not the first in commit order.
	var earliest *time.Time
	for _, ev := range events {
		if outbound.Matches(dr.d.Filter, dr.d.Codes, ev.Event) && (earliest == nil || ev.Event.RecordedAt.Before(*earliest)) {
			earliest = &ev.Event.RecordedAt
		}
	}
	if earliest != nil {
		return *earliest, nil
	}
	if len(events) < ScanWindow {
		return caughtUp, nil
	}
	// Past a window without a match only the commit order is known; the skew between replicas (one transaction) is
	// far below the day boundary this bound is compared with.
	return later(until, events[len(events)-1].Event.RecordedAt), nil
}

func later(a, b time.Time) time.Time {
	if b.After(a) {
		return b
	}
	return a
}

// checkpointMessage is the checkpoint of day with the manifest of the audit database, numbered seq.
func (e *Engine) checkpointMessage(ctx context.Context, dr *destRound, id uuid.UUID, seq int64, day time.Time,
	count int) (outbound.Message, error) {
	ms, err := e.index.ManifestsAfter(ctx, dr.sc, day.AddDate(0, 0, -1), 1)
	if err != nil {
		return outbound.Message{}, fmt.Errorf("manifest: %w", err)
	}
	if len(ms) == 0 || !ms[0].Day.Equal(utcDay(day)) {
		return outbound.Message{}, fmt.Errorf("no manifest of %s", day.Format(time.DateOnly))
	}
	m := outbound.Checkpoint(day.Format(time.DateOnly), count, hex.EncodeToString(ms[0].SHA256), ms[0].Signature,
		ms[0].KeyVersion)
	base := e.message(dr, outbound.KindCheckpoint, id)
	m.DeliveryID, m.DestinationID, m.OrganizationID, m.Organization, m.SentAt =
		base.DeliveryID, base.DestinationID, base.OrganizationID, base.Organization, base.SentAt
	m.ForwardSeq = &outbound.SeqRange{From: seq, To: seq}
	return m, nil
}

// deliverCheckpoint sends a checkpoint and records notification.checkpoint_sent; it reports whether it succeeded.
func (e *Engine) deliverCheckpoint(ctx context.Context, dr *destRound, b batch) (bool, error) {
	m, err := e.checkpointMessage(ctx, dr, b.id, b.seq, b.day, b.eventCount)
	if err != nil {
		return false, e.internal(ctx, dr, err, b.seq)
	}
	derr := dr.transport.Deliver(ctx, dr.d, m)
	e.metrics.delivery(dr.d.Type, derr == nil)
	if derr != nil {
		return false, e.failed(ctx, dr, b.id, b.seq, derr)
	}
	day := b.day
	if err := e.succeededWith(ctx, dr, Success{Delivery: b.id, Pending: b.id, CheckpointDay: &day, Record: &Record{
		Code: audit.CodeNotificationCheckpointSent, Params: map[string]any{
			"destination_id": dr.d.ID.String(), "day": m.Day, "event_count": b.eventCount, "forward_seq": b.seq,
		},
	}}, map[string]any{"forward_from": b.seq, "forward_to": b.seq}); err != nil {
		return false, err
	}
	dr.st.Pending, dr.st.PendingFrom, dr.st.LastCheckpointDay = uuid.Nil, 0, &day
	return true, nil
}

// wrap adds what to a non-nil error.
func wrap(what string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", what, err)
}
