package notifier

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
	"github.com/phischl/paddock-mdm/server/internal/domain/outbound"
)

// errReplayEmpty marks a stored events batch without recorded events.
var errReplayEmpty = errors.New("stored batch has no events")

// replayNext re-sends the next stored delivery of a requested replay with its original delivery ID and numbers and
// records notification.replayed (plan M12 decision 21). sent is false after a failure (the replay continues at the same
// delivery after the backoff) and when nothing was left to send, which ends the replay.
func (e *Engine) replayNext(ctx context.Context, dr *destRound) (sent bool, err error) {
	from := dr.st.ReplayFrom
	stored, err := e.store.ReplayDeliveries(ctx, dr.sc, dr.d.ID, from, 2)
	if err != nil {
		return false, e.internal(ctx, dr, fmt.Errorf("replay deliveries: %w", err), from)
	}
	adv := ReplayAdvance{Destination: dr.d.ID, Name: dr.d.Name, From: from}
	if len(stored) == 0 {
		adv.At = e.now()
		applied, err := e.store.Replayed(ctx, dr.sc, adv)
		if err != nil {
			return false, fmt.Errorf("end replay: %w", err)
		}
		if !applied {
			return false, errStale
		}
		dr.st.ReplayFrom, dr.st.NextAttemptAt = 0, nil
		return false, nil
	}
	b := stored[0]
	if len(stored) > 1 {
		adv.Next = stored[1].From
	}
	m, missing, err := e.replayMessage(ctx, dr, b)
	if err != nil {
		return false, e.internal(ctx, dr, err, from)
	}
	derr := dr.transport.Deliver(ctx, dr.d, m)
	e.metrics.delivery(dr.d.Type, derr == nil)
	if derr != nil {
		return false, e.failed(ctx, dr, b.ID, b.From, derr)
	}
	now := e.now()
	adv.Delivery, adv.At, adv.NextAttemptAt = b.ID, now, e.digestNext(dr, now)
	adv.Record = &Record{Code: audit.CodeNotificationReplayed, Params: map[string]any{
		"destination_id": dr.d.ID.String(), "forward_from": b.From, "forward_to": b.To,
		"original_delivery_id": b.ID.String(), "missing": missing,
	}}
	adv.Resume = e.resumeRecord(dr, now, map[string]any{"forward_from": b.From, "forward_to": b.To})
	applied, err := e.store.Replayed(ctx, dr.sc, adv)
	if err != nil {
		return false, fmt.Errorf("record replay: %w", err)
	}
	if !applied {
		return false, errStale
	}
	dr.delivered = true
	dr.st.ReplayFrom = adv.Next
	dr.st.ConsecutiveFailures, dr.st.FirstFailureAt, dr.st.NextAttemptAt = 0, nil, adv.NextAttemptAt
	dr.st.Status, dr.st.StalledSince = StatusActive, nil
	return true, nil
}

// replayMessage rebuilds a stored delivery: a checkpoint from its day and count, an events batch from its recorded
// events re-read from the index, where an event the retention purged is sent as missing. missing counts those.
func (e *Engine) replayMessage(ctx context.Context, dr *destRound, b PendingBatch) (outbound.Message, int, error) {
	if b.Kind == outbound.KindCheckpoint {
		m, err := e.checkpointMessage(ctx, dr, b.ID, b.From, b.Day, b.EventCount)
		return m, 0, err
	}
	if len(b.Refs) == 0 {
		return outbound.Message{}, 0, fmt.Errorf("delivery %s: %w", b.ID, errReplayEmpty)
	}
	first, last := b.Refs[0].CommitSeq, b.Refs[len(b.Refs)-1].CommitSeq
	events, err := e.index.After(ctx, dr.sc, first-1, int(last-first+1))
	if err != nil {
		return outbound.Message{}, 0, fmt.Errorf("replayed events: %w", err)
	}
	byID := make(map[uuid.UUID]IndexedEvent, len(events))
	for _, ev := range events {
		byID[ev.Event.EventID] = ev
	}
	m := e.message(dr, outbound.KindEvents, b.ID)
	m.ForwardSeq = &outbound.SeqRange{From: b.From, To: b.To}
	m.Events = make([]outbound.MessageEvent, 0, len(b.Refs))
	missing := 0
	for _, ref := range b.Refs {
		ev, ok := byID[ref.EventID]
		if !ok {
			missing++
			m.Events = append(m.Events, outbound.MessageEvent{ForwardSeq: ref.ForwardSeq, EventID: ref.EventID, Missing: true})
			continue
		}
		me, err := e.messageEvent(ctx, dr, ev)
		if err != nil {
			return outbound.Message{}, 0, err
		}
		me.ForwardSeq = ref.ForwardSeq
		m.Events = append(m.Events, me)
	}
	return m, missing, nil
}
