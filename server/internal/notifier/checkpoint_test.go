package notifier

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
	"github.com/phischl/paddock-mdm/server/internal/domain/outbound"
)

// dayD is the sealed recording day of the checkpoint tests; the harness's clock moves around it.
var dayD = time.Date(2026, 10, 30, 0, 0, 0, 0, time.UTC)

// checkpointing adds a webhook with checkpoints, created at created.
func (h *harness) checkpointing(created time.Time) *Row {
	r := h.webhook(h.org, State{})
	r.Destination.Checkpoints, r.Destination.CreatedAt = true, created
	return r
}

// appendAt adds n matching events recorded at at.
func (h *harness) appendAt(at time.Time, n int) []IndexedEvent {
	saved := h.now
	h.now = at
	defer func() { h.now = saved }()
	return h.index.append(h.org, tamper, n)
}

// sentKinds lists the kinds of every message sent so far, in order.
func (h *harness) sentKinds() []string {
	out := make([]string, len(h.tr.sent))
	for i, s := range h.tr.sent {
		out[i] = s.msg.Kind
	}
	return out
}

// TestCheckpointAfterTheDay: with day D sealed and the cursor's event recorded on D+1, exactly one checkpoint for D
// follows the events, carrying the index's count of D and the manifest's hex SHA-256, signature and key version,
// numbered next in forward_seq; later rounds send it no more.
func TestCheckpointAfterTheDay(t *testing.T) {
	h := newHarness(t)
	h.e.cfg.Batch = 1
	d := h.checkpointing(dayD.Add(-36 * time.Hour))
	h.appendAt(dayD.Add(9*time.Hour), 3)
	h.appendAt(dayD.Add(30*time.Hour), MaxDeliveriesPerRound+5)
	m := h.index.seal(h.org, dayD)
	h.round()
	if n := len(h.tr.kinds(outbound.KindEvents)); n != MaxDeliveriesPerRound {
		t.Fatalf("%d event batches, want %d (the cursor is not caught up)", n, MaxDeliveriesPerRound)
	}
	cps := h.tr.kinds(outbound.KindCheckpoint)
	if len(cps) != 1 {
		t.Fatalf("%d checkpoints, want 1", len(cps))
	}
	cp := cps[0]
	if kinds := h.sentKinds(); kinds[len(kinds)-1] != outbound.KindCheckpoint {
		t.Errorf("the checkpoint is not after the events: %v", kinds)
	}
	if cp.Day != "2026-10-30" || cp.EventCount != 3 || cp.ManifestSHA256 != "abcd1e" || cp.Signature != m.Signature ||
		cp.KeyVersion != 1 || cp.ForwardSeq == nil || cp.ForwardSeq.From != MaxDeliveriesPerRound+1 ||
		cp.ForwardSeq.To != MaxDeliveriesPerRound+1 || cp.DeliveryID == "" || cp.Organization != "acme" {
		t.Fatalf("checkpoint %+v", cp)
	}
	st := h.state(d)
	if st.LastCheckpointDay == nil || !st.LastCheckpointDay.Equal(dayD) || st.Pending != uuid.Nil ||
		st.ForwardSeq != MaxDeliveriesPerRound+1 {
		t.Fatalf("state %+v", st)
	}
	recs := h.store.recordsOf(audit.CodeNotificationCheckpointSent)
	if len(recs) != 1 || recs[0].Params["day"] != "2026-10-30" || recs[0].Params["event_count"] != 3 ||
		recs[0].Params["forward_seq"] != int64(MaxDeliveriesPerRound+1) ||
		recs[0].Params["destination_id"] != d.Destination.ID.String() {
		t.Fatalf("checkpoint records %+v", recs)
	}
	h.round()
	h.round()
	if n := len(h.tr.kinds(outbound.KindCheckpoint)); n != 1 {
		t.Fatalf("%d checkpoints after more rounds, want 1", n)
	}
	events := h.tr.kinds(outbound.KindEvents)
	if next := events[MaxDeliveriesPerRound]; next.ForwardSeq.From != MaxDeliveriesPerRound+2 {
		t.Errorf("the events after the checkpoint start at %d", next.ForwardSeq.From)
	}
}

// TestCheckpointNotDueInsideTheDay: while the cursor's event is still recorded on D and newer matching events wait,
// nothing is sent; once the destination caught up, the checkpoint follows.
func TestCheckpointNotDueInsideTheDay(t *testing.T) {
	h := newHarness(t)
	h.e.cfg.Batch = 1
	h.checkpointing(dayD.Add(-36 * time.Hour))
	h.appendAt(dayD.Add(9*time.Hour), MaxDeliveriesPerRound+2)
	h.appendAt(dayD.Add(30*time.Hour), 1)
	h.index.seal(h.org, dayD)
	h.round()
	if n := len(h.tr.kinds(outbound.KindCheckpoint)); n != 0 {
		t.Fatalf("%d checkpoints while the cursor is inside the day", n)
	}
	h.round()
	cps := h.tr.kinds(outbound.KindCheckpoint)
	if len(cps) != 1 || cps[0].EventCount != MaxDeliveriesPerRound+2 || cps[0].ForwardSeq.From != MaxDeliveriesPerRound+4 {
		t.Fatalf("checkpoints after catching up %+v", cps)
	}
}

// TestCheckpointAfterNonMatchingEvents: events after the cursor that match nothing do not hold the checkpoint back.
func TestCheckpointAfterNonMatchingEvents(t *testing.T) {
	h := newHarness(t)
	h.checkpointing(dayD.Add(-36 * time.Hour))
	h.appendAt(dayD.Add(9*time.Hour), 2)
	h.now = dayD.Add(30 * time.Hour)
	h.index.append(h.org, audit.CodeDeviceEnrolled, 3)
	h.index.seal(h.org, dayD)
	h.round()
	if cps := h.tr.kinds(outbound.KindCheckpoint); len(cps) != 1 || cps[0].EventCount != 2 {
		t.Fatalf("checkpoints %+v", cps)
	}
}

// TestCheckpointSkipsDaysBeforeCreation: days sealed before the destination was created are never sent; later days
// follow in day order, and a destination without checkpoints receives none.
func TestCheckpointSkipsDaysBeforeCreation(t *testing.T) {
	h := newHarness(t)
	d := h.checkpointing(dayD.Add(-12 * time.Hour))
	plain := h.webhook(h.org, State{})
	h.index.seal(h.org, dayD.AddDate(0, 0, -2))
	h.index.seal(h.org, dayD.AddDate(0, 0, -1))
	h.index.seal(h.org, dayD)
	h.now = dayD.Add(40 * time.Hour)
	h.round()
	var days []string
	for _, s := range h.tr.sent {
		if s.msg.Kind == outbound.KindCheckpoint {
			if s.dest.ID == plain.Destination.ID {
				t.Fatal("a destination without checkpoints received one")
			}
			days = append(days, s.msg.Day)
		}
	}
	if strings.Join(days, ",") != "2026-10-29,2026-10-30" {
		t.Fatalf("checkpoint days %v, want 2026-10-29,2026-10-30", days)
	}
	if st := h.state(d); st.ForwardSeq != 2 || !st.LastCheckpointDay.Equal(dayD) {
		t.Fatalf("state %+v", st)
	}
}

// failKind fails every delivery of one kind while fail is set.
type failKind struct {
	*fakeTransport
	kind string
	fail bool
	mu   sync.Mutex
}

func (f *failKind) Deliver(ctx context.Context, d Destination, m outbound.Message) error {
	f.mu.Lock()
	fail := f.fail && m.Kind == f.kind
	f.mu.Unlock()
	if err := f.fakeTransport.Deliver(ctx, d, m); err != nil || !fail {
		return err
	}
	return &DeliveryError{Class: "http_503"}
}

// TestCheckpointRetried: a failed checkpoint stays pending, backs off and is retried with the same delivery ID and
// number before anything else; it is recorded once, on success.
func TestCheckpointRetried(t *testing.T) {
	h := newHarness(t)
	tr := &failKind{fakeTransport: h.tr, kind: outbound.KindCheckpoint, fail: true}
	h.e.transports[outbound.TypeWebhook] = tr
	d := h.checkpointing(dayD.Add(-36 * time.Hour))
	h.appendAt(dayD.Add(9*time.Hour), 2)
	h.index.seal(h.org, dayD)
	h.round()
	st := h.state(d)
	if st.Pending == uuid.Nil || st.PendingFrom != 3 || st.ConsecutiveFailures != 1 || st.NextAttemptAt == nil ||
		st.LastCheckpointDay != nil {
		t.Fatalf("state after the failure %+v", st)
	}
	h.appendAt(h.now, 1)
	h.round()
	if n := len(h.tr.kinds(outbound.KindCheckpoint)); n != 1 {
		t.Fatalf("%d checkpoint attempts during the backoff", n)
	}
	tr.fail = false
	h.now = *st.NextAttemptAt
	h.round()
	cps := h.tr.kinds(outbound.KindCheckpoint)
	if len(cps) != 2 || cps[1].DeliveryID != cps[0].DeliveryID || cps[1].ForwardSeq.From != 3 {
		t.Fatalf("retried checkpoints %+v", cps)
	}
	if kinds := h.sentKinds(); kinds[len(kinds)-1] != outbound.KindEvents ||
		h.tr.kinds(outbound.KindEvents)[1].ForwardSeq.From != 4 {
		t.Errorf("the new event does not follow the checkpoint: %v", kinds)
	}
	if n := len(h.store.recordsOf(audit.CodeNotificationCheckpointSent)); n != 1 {
		t.Errorf("%d checkpoint records", n)
	}
}

// TestReplay: a replay from N re-sends every stored batch that reaches N with its original delivery ID and numbers,
// records notification.replayed per batch, and then continues at the cursor.
func TestReplay(t *testing.T) {
	h := newHarness(t)
	h.e.cfg.Batch = 2
	d := h.webhook(h.org, State{})
	h.index.append(h.org, tamper, 6)
	h.round()
	original := h.tr.kinds(outbound.KindEvents)
	if len(original) != 3 {
		t.Fatalf("%d batches", len(original))
	}
	h.store.rows[d.Destination.ID].State.ReplayFrom = 4
	h.index.append(h.org, tamper, 2)
	h.now = h.now.Add(time.Minute)
	h.round()
	sent := h.tr.kinds(outbound.KindEvents)[3:]
	if len(sent) != 3 {
		t.Fatalf("%d deliveries after the replay request, want 3", len(sent))
	}
	for i, want := range original[1:] {
		if sent[i].DeliveryID != want.DeliveryID || !equalIDs(eventIDs(sent[i]), eventIDs(want)) {
			t.Fatalf("replayed batch %d is not the stored one", i)
		}
	}
	assertContiguous(t, sent[0], 3, 4)
	assertContiguous(t, sent[1], 5, 6)
	assertContiguous(t, sent[2], 7, 8)
	recs := h.store.recordsOf(audit.CodeNotificationReplayed)
	if len(recs) != 2 || recs[0].Params["original_delivery_id"] != original[1].DeliveryID ||
		recs[0].Params["forward_from"] != int64(3) || recs[1].Params["forward_to"] != int64(6) ||
		recs[1].Params["missing"] != 0 {
		t.Fatalf("replayed records %+v", recs)
	}
	if st := h.state(d); st.ReplayFrom != 0 || st.Cursor != 8 || st.ForwardSeq != 8 {
		t.Fatalf("state %+v", st)
	}
	if n := len(h.store.recordsOf(audit.CodeNotificationDelivered)); n != 4 {
		t.Errorf("%d delivered records, want 4 (a replay is not a new delivery)", n)
	}
}

// TestReplayMissingEvents: an event the index retention purged is sent as {forward_seq, event_id, missing: true}
// in its place and counted in the record.
func TestReplayMissingEvents(t *testing.T) {
	h := newHarness(t)
	d := h.webhook(h.org, State{})
	evs := h.index.append(h.org, tamper, 3)
	h.round()
	h.index.purge(h.org, evs[1].Event.EventID)
	h.store.rows[d.Destination.ID].State.ReplayFrom = 1
	h.round()
	sent := h.tr.kinds(outbound.KindEvents)
	if len(sent) != 2 {
		t.Fatalf("%d deliveries", len(sent))
	}
	got := sent[1].Events
	if len(got) != 3 || got[0].Missing || !got[1].Missing || got[1].EventID != evs[1].Event.EventID || got[1].ForwardSeq != 2 {
		t.Fatalf("replayed events %+v", got)
	}
	raw, err := json.Marshal(got[1])
	if err != nil || string(raw) != `{"forward_seq":2,"event_id":"`+evs[1].Event.EventID.String()+`","missing":true}` {
		t.Fatalf("missing event encodes as %s (%v)", raw, err)
	}
	if recs := h.store.recordsOf(audit.CodeNotificationReplayed); len(recs) != 1 || recs[0].Params["missing"] != 1 {
		t.Fatalf("replayed records %+v", recs)
	}
}

// TestReplayRetried: a failed replay keeps replay_from and retries the same stored batch after the backoff; no new
// events are numbered meanwhile.
func TestReplayRetried(t *testing.T) {
	h := newHarness(t)
	d := h.webhook(h.org, State{})
	h.index.append(h.org, tamper, 2)
	h.round()
	h.store.rows[d.Destination.ID].State.ReplayFrom = 1
	h.index.append(h.org, tamper, 1)
	h.tr.fail = &DeliveryError{Class: "http_500"}
	h.round()
	st := h.state(d)
	if st.ReplayFrom != 1 || st.ConsecutiveFailures != 1 || st.ForwardSeq != 2 || st.NextAttemptAt == nil {
		t.Fatalf("state after the failed replay %+v", st)
	}
	h.tr.fail = nil
	h.now = *st.NextAttemptAt
	h.round()
	sent := h.tr.kinds(outbound.KindEvents)
	if len(sent) != 4 || sent[2].DeliveryID != sent[0].DeliveryID || sent[1].DeliveryID != sent[0].DeliveryID {
		t.Fatalf("deliveries %d", len(sent))
	}
	assertContiguous(t, sent[3], 3, 3)
	if n := len(h.store.recordsOf(audit.CodeNotificationReplayed)); n != 1 {
		t.Errorf("%d replayed records", n)
	}
}

// TestReplayCheckpoint: a checkpoint in the replayed range is sent again with its ID, number and day.
func TestReplayCheckpoint(t *testing.T) {
	h := newHarness(t)
	d := h.checkpointing(dayD.Add(-36 * time.Hour))
	h.appendAt(dayD.Add(9*time.Hour), 1)
	h.index.seal(h.org, dayD)
	h.round()
	h.store.rows[d.Destination.ID].State.ReplayFrom = 2
	h.round()
	cps := h.tr.kinds(outbound.KindCheckpoint)
	if len(cps) != 2 || cps[1].DeliveryID != cps[0].DeliveryID || cps[1].Day != "2026-10-30" ||
		cps[1].ForwardSeq.From != 2 || cps[1].EventCount != 1 {
		t.Fatalf("checkpoints %+v", cps)
	}
	if recs := h.store.recordsOf(audit.CodeNotificationReplayed); len(recs) != 1 || recs[0].Params["forward_from"] != int64(2) {
		t.Fatalf("replayed records %+v", recs)
	}
	if n := len(h.store.recordsOf(audit.CodeNotificationCheckpointSent)); n != 1 {
		t.Errorf("%d checkpoint_sent records, want 1", n)
	}
}

// TestReplayBeyondStored: a replay that reaches no delivered batch ends without sending anything.
func TestReplayBeyondStored(t *testing.T) {
	h := newHarness(t)
	d := h.webhook(h.org, State{})
	h.store.rows[d.Destination.ID].State.ReplayFrom = 5
	h.round()
	if st := h.state(d); st.ReplayFrom != 0 || len(h.tr.kinds(outbound.KindEvents)) != 0 {
		t.Fatalf("state %+v", st)
	}
}

// TestReplayAbandonedBySkip: a replayed delivery the receiver always refuses stalls the destination and holds back new
// events; a skip request (enabling with skip) ends the replay, and new events continue the numbering without a gap.
func TestReplayAbandonedBySkip(t *testing.T) {
	h := newHarness(t)
	d := h.webhook(h.org, State{})
	h.index.append(h.org, tamper, 2)
	h.round()
	h.store.rows[d.Destination.ID].State.ReplayFrom = 1
	h.index.append(h.org, tamper, 1)
	h.tr.fail = &DeliveryError{Class: "http_422"}
	start := h.now
	for h.now.Sub(start) < 3*time.Minute {
		h.round()
		h.now = h.now.Add(5 * time.Second)
		if st := h.state(d); st.NextAttemptAt != nil && st.NextAttemptAt.After(h.now) {
			h.now = *st.NextAttemptAt
		}
	}
	if st := h.state(d); st.Status != StatusStalled || st.ReplayFrom != 1 || st.ForwardSeq != 2 {
		t.Fatalf("state while the replay fails %+v", st)
	}
	if n := len(h.store.recordsOf(audit.CodeNotificationDestinationStalled)); n != 1 {
		t.Fatalf("%d stalled records, want 1", n)
	}

	h.tr.fail = nil
	h.store.rows[d.Destination.ID].State.StartAtLatest = true
	h.index.append(h.org, tamper, 2)
	before, stale := len(h.tr.kinds(outbound.KindEvents)), h.store.stale
	h.round()
	// The round that resolves the skip must not re-send the abandoned replay: such a delivery would never be recorded
	// as notification.replayed, because replay_from is already cleared when the notifier tries to record it.
	if n := len(h.tr.kinds(outbound.KindEvents)) - before; n != 0 || h.store.stale != stale {
		t.Fatalf("skip round sent %d event deliveries, stale %d->%d", n, stale, h.store.stale)
	}
	h.index.append(h.org, tamper, 1)
	h.now = h.now.Add(time.Minute)
	h.round()
	st := h.state(d)
	if st.ReplayFrom != 0 || st.ForwardSeq != 3 || st.Status != StatusActive {
		t.Fatalf("state after the skip %+v", st)
	}
	sent := h.tr.kinds(outbound.KindEvents)
	assertContiguous(t, sent[len(sent)-1], 3, 3)
	if n := len(h.store.recordsOf(audit.CodeNotificationReplayed)); n != 0 {
		t.Errorf("%d replayed records for an abandoned replay", n)
	}
}

// emailing adds an e-mail destination with a digest interval of five minutes and the harness transport.
func (h *harness) emailing(checkpoints bool, created time.Time) *Row {
	h.e.transports[outbound.TypeEmail] = h.tr
	return h.store.add(h.org, Destination{ID: uuid.Must(uuid.NewV7()), Type: outbound.TypeEmail, Name: "secops",
		Filter: outbound.FilterSecurity, Recipients: []string{"a@example.org"}, EmailMinInterval: 5 * time.Minute,
		Checkpoints: checkpoints, CreatedAt: created}, State{})
}

// TestReplayEmailDigest: a replay of an e-mail destination re-sends one stored delivery per email_min_interval_s
// (plan M9 decision 28), not a round's worth at once.
func TestReplayEmailDigest(t *testing.T) {
	h := newHarness(t)
	h.e.cfg.Batch = 2
	d := h.emailing(false, h.now)
	h.index.append(h.org, tamper, 4)
	h.round()
	h.now = h.now.Add(5 * time.Minute)
	h.round()
	if n := len(h.tr.kinds(outbound.KindEvents)); n != 2 {
		t.Fatalf("%d deliveries before the replay, want 2", n)
	}
	h.now = h.now.Add(5 * time.Minute)
	h.store.rows[d.Destination.ID].State.ReplayFrom = 1
	h.round()
	if n := len(h.tr.kinds(outbound.KindEvents)); n != 3 {
		t.Fatalf("%d deliveries after the first replay round, want 3", n)
	}
	if st := h.state(d); st.ReplayFrom != 3 || st.NextAttemptAt == nil || !st.NextAttemptAt.Equal(h.now.Add(5*time.Minute)) {
		t.Fatalf("state after the first replayed message %+v", st)
	}
	h.now = h.now.Add(4 * time.Minute)
	h.round()
	if n := len(h.tr.kinds(outbound.KindEvents)); n != 3 {
		t.Fatalf("%d deliveries within the interval, want 3", n)
	}
	h.now = h.now.Add(time.Minute)
	h.round()
	sent := h.tr.kinds(outbound.KindEvents)
	if len(sent) != 4 {
		t.Fatalf("%d deliveries after the interval, want 4", len(sent))
	}
	assertContiguous(t, sent[3], 3, 4)
	if n := len(h.store.recordsOf(audit.CodeNotificationReplayed)); n != 2 {
		t.Errorf("%d replayed records, want 2", n)
	}
	h.now = h.now.Add(5 * time.Minute)
	h.round()
	if st := h.state(d); st.ReplayFrom != 0 || len(h.tr.sent) != 4 {
		t.Fatalf("state after the replay %+v, %d messages", st, len(h.tr.sent))
	}
}

// TestCheckpointEmailDigest: a checkpoint e-mail counts as a message of the digest: it waits for the interval after
// the events and holds the next events back for the interval.
func TestCheckpointEmailDigest(t *testing.T) {
	h := newHarness(t)
	d := h.emailing(true, dayD.Add(-36*time.Hour))
	h.appendAt(dayD.Add(9*time.Hour), 2)
	h.index.seal(h.org, dayD)
	h.now = dayD.Add(30 * time.Hour)
	h.round()
	if kinds := h.sentKinds(); len(kinds) != 1 || kinds[0] != outbound.KindEvents {
		t.Fatalf("first round sent %v, want one events message", kinds)
	}
	h.now = h.now.Add(5 * time.Minute)
	h.round()
	if kinds := h.sentKinds(); len(kinds) != 2 || kinds[1] != outbound.KindCheckpoint {
		t.Fatalf("second round sent %v, want the checkpoint", kinds)
	}
	if st := h.state(d); st.NextAttemptAt == nil || !st.NextAttemptAt.Equal(h.now.Add(5*time.Minute)) {
		t.Fatalf("state after the checkpoint %+v", st)
	}
	h.index.append(h.org, tamper, 1)
	h.now = h.now.Add(4 * time.Minute)
	h.round()
	if n := len(h.tr.sent); n != 2 {
		t.Fatalf("%d messages within the interval after the checkpoint, want 2", n)
	}
	h.now = h.now.Add(time.Minute)
	h.round()
	if kinds := h.sentKinds(); len(kinds) != 3 || kinds[2] != outbound.KindEvents {
		t.Fatalf("after the interval %v", kinds)
	}
}

// TestCheckpointRecordedOutOfCommitOrder: an event of day D committed after the cursor's event of D + 1 (two audit
// writers) holds the checkpoint of D back until it is delivered.
func TestCheckpointRecordedOutOfCommitOrder(t *testing.T) {
	h := newHarness(t)
	h.e.cfg.Batch = 1
	h.checkpointing(dayD.Add(-36 * time.Hour))
	h.appendAt(dayD.Add(9*time.Hour), MaxDeliveriesPerRound-1)
	h.appendAt(dayD.Add(30*time.Hour), 1)
	late := h.appendAt(dayD.Add(23*time.Hour), 1)
	h.index.seal(h.org, dayD)
	h.round()
	if n := len(h.tr.kinds(outbound.KindCheckpoint)); n != 0 {
		t.Fatalf("%d checkpoints while an event of the day is undelivered", n)
	}
	h.round()
	kinds := h.sentKinds()
	cps := h.tr.kinds(outbound.KindCheckpoint)
	if len(cps) != 1 || kinds[len(kinds)-1] != outbound.KindCheckpoint || cps[0].EventCount != MaxDeliveriesPerRound {
		t.Fatalf("after delivering the late event %v, checkpoints %+v", kinds, cps)
	}
	last := h.tr.kinds(outbound.KindEvents)
	if ids := eventIDs(last[len(last)-1]); len(ids) != 1 || ids[0] != late[0].Event.EventID {
		t.Fatalf("last events message %v, want the late event", ids)
	}
}
