package uninstall

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	"github.com/phischl/paddock-mdm/agent/internal/spool"
	"github.com/phischl/paddock-mdm/pkg/protocol"
)

// ReportFor is how long the helper retries the final report (plan M8d decision 40 step 10).
const ReportFor = 30 * time.Minute

// report sends the events the agent left in its spool and then agent.uninstalled with the next event sequence
// number, retrying with a doubling back-off (15 s up to 5 min) until ReportFor passed. It reports whether the server
// accepted the final event.
func (h *Helper) report(ctx context.Context, plan Plan, data protocol.AgentUninstalled) bool {
	if h.Send == nil {
		slog.ErrorContext(ctx, "no identity to report the removal with")
		return false
	}
	pending, err := spool.New(h.path("/var/lib/paddock/spool/events.jsonl"), spool.DefaultCap, nil).Pending()
	if err != nil {
		slog.WarnContext(ctx, "reading the event spool failed; reporting the removal only", "error", err)
		pending = nil
	}
	raw, err := json.Marshal(data)
	if err != nil {
		return false
	}
	seq := plan.EventSeqBase
	if h.EventSeq != nil {
		seq = max(seq, h.EventSeq())
	}
	for _, ev := range pending {
		seq = max(seq, ev.EventSeq)
	}
	final := protocol.Event{EventSeq: seq + 1, Type: protocol.EventAgentUninstalled, OccurredAt: h.Now().UTC(), Data: raw}
	batches := batch(pending)
	batches = append(batches, []protocol.Event{final})
	deadline := h.Now().Add(h.ReportFor)
	delay := 15 * time.Second
	for len(batches) > 0 {
		err := h.Send(ctx, batches[0])
		if err == nil {
			batches = batches[1:]
			continue
		}
		if !h.Now().Add(delay).Before(deadline) {
			slog.ErrorContext(ctx, "reporting the removal failed; giving up", "error", err)
			return false
		}
		slog.WarnContext(ctx, "reporting the removal failed; retrying", "error", err, "retry_in", delay)
		if h.Sleep(ctx, delay) != nil {
			return false
		}
		delay = min(2*delay, 5*time.Minute)
	}
	return true
}

func batch(events []protocol.Event) [][]protocol.Event {
	var out [][]protocol.Event
	for len(events) > 0 {
		n := min(len(events), protocol.MaxEventsPerBatch)
		out = append(out, events[:n])
		events = events[n:]
	}
	return out
}
