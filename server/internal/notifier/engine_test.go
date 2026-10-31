package notifier

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
	"github.com/phischl/paddock-mdm/server/internal/domain/outbound"
)

const tamper = audit.CodeDeviceTamperSudoersDFile

type harness struct {
	t       *testing.T
	e       *Engine
	store   *fakeStore
	index   *fakeIndex
	tr      *fakeTransport
	leader  *fakeLeader
	now     time.Time
	org     uuid.UUID
	metrics *Metrics
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	h := &harness{t: t, store: newFakeStore(), tr: &fakeTransport{}, leader: &fakeLeader{},
		now: time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC), org: uuid.Must(uuid.NewV7())}
	h.index = &fakeIndex{events: map[uuid.UUID][]IndexedEvent{}, clock: func() time.Time { return h.now }}
	h.store.orgs = []uuid.UUID{h.org}
	h.store.slugs[h.org] = "acme"
	h.metrics = NewMetrics(prometheus.NewRegistry())
	h.e = NewEngine(Config{PollInterval: 5 * time.Second, StallAfter: time.Minute, Batch: 100,
		PublicAdminURL: "https://admin.example"}, h.leader, h.store, h.index, fakeKeys{},
		map[outbound.Type]Transport{outbound.TypeWebhook: h.tr}, h.metrics)
	h.e.now = func() time.Time { return h.now }
	return h
}

func (h *harness) webhook(org uuid.UUID, st State) *Row {
	return h.store.add(org, Destination{ID: uuid.Must(uuid.NewV7()), Type: outbound.TypeWebhook, Name: "siem",
		Filter: outbound.FilterSecurity}, st)
}

func (h *harness) round() {
	h.t.Helper()
	if err := h.e.Round(context.Background()); err != nil {
		h.t.Fatalf("round: %v", err)
	}
}

func (h *harness) state(r *Row) State { return h.store.rows[r.Destination.ID].State }

func eventIDs(m outbound.Message) []uuid.UUID {
	out := make([]uuid.UUID, len(m.Events))
	for i, e := range m.Events {
		out[i] = e.Event.EventID
	}
	return out
}

func assertContiguous(t *testing.T, m outbound.Message, from, to int64) {
	t.Helper()
	if m.ForwardSeq == nil || m.ForwardSeq.From != from || m.ForwardSeq.To != to || len(m.Events) != int(to-from+1) {
		t.Fatalf("forward_seq %+v with %d events, want %d–%d", m.ForwardSeq, len(m.Events), from, to)
	}
	for i, e := range m.Events {
		if e.ForwardSeq != from+int64(i) {
			t.Fatalf("event %d has forward_seq %d, want %d", i, e.ForwardSeq, from+int64(i))
		}
	}
}

// TestBatchCut: 150 matching events leave as 100 + 50 with contiguous forward sequence numbers from 1, each batch
// recorded once as notification.delivered, and the cursor ends after the last event.
func TestBatchCut(t *testing.T) {
	h := newHarness(t)
	d := h.webhook(h.org, State{})
	h.index.append(h.org, tamper, 150)
	h.round()
	sent := h.tr.kinds(outbound.KindEvents)
	if len(sent) != 2 {
		t.Fatalf("%d deliveries, want 2", len(sent))
	}
	assertContiguous(t, sent[0], 1, 100)
	assertContiguous(t, sent[1], 101, 150)
	if sent[0].Organization != "acme" || sent[0].OrganizationID != h.org.String() || sent[0].Schema != outbound.MessageSchema {
		t.Errorf("envelope %+v", sent[0])
	}
	if st := h.state(d); st.Cursor != 150 || st.ForwardSeq != 150 || st.Pending != uuid.Nil {
		t.Errorf("state %+v", st)
	}
	recs := h.store.recordsOf(audit.CodeNotificationDelivered)
	if len(recs) != 2 || recs[0].Params["forward_from"] != int64(1) || recs[0].Params["forward_to"] != int64(100) ||
		recs[1].Params["count"] != 50 || recs[1].Params["attempts"] != 1 || recs[1].Params["resumed"] != false {
		t.Errorf("delivered records %+v", recs)
	}

	t.Run("batch size from the configuration", func(t *testing.T) {
		h := newHarness(t)
		h.e.cfg.Batch = 7
		h.webhook(h.org, State{})
		h.index.append(h.org, tamper, 10)
		h.round()
		sent := h.tr.kinds(outbound.KindEvents)
		if len(sent) != 2 {
			t.Fatalf("%d deliveries, want 2", len(sent))
		}
		assertContiguous(t, sent[0], 1, 7)
		assertContiguous(t, sent[1], 8, 10)
	})
}

// TestFailedBatchRetried: a failed batch keeps the cursor and is retried with the same forward sequence numbers and
// events, also when newer events arrived meanwhile; the cursor advances only after the success.
func TestFailedBatchRetried(t *testing.T) {
	h := newHarness(t)
	d := h.webhook(h.org, State{})
	h.index.append(h.org, tamper, 3)
	h.tr.fail = &DeliveryError{Class: "http_500"}
	h.round()
	first := h.tr.kinds(outbound.KindEvents)
	if len(first) != 1 {
		t.Fatalf("%d attempts, want 1 (no second batch after a failure)", len(first))
	}
	st := h.state(d)
	if st.Cursor != 0 || st.Pending == uuid.Nil || st.ConsecutiveFailures != 1 {
		t.Fatalf("state after failure %+v", st)
	}
	if got := h.store.deliveries[st.Pending].lastError; got != "http_500" {
		t.Errorf("last_error %q", got)
	}
	h.index.append(h.org, tamper, 2)
	h.tr.fail = nil
	h.now = h.now.Add(5 * time.Second)
	h.round()
	sent := h.tr.kinds(outbound.KindEvents)
	if len(sent) != 3 {
		t.Fatalf("%d messages, want 3", len(sent))
	}
	assertContiguous(t, sent[1], 1, 3)
	if sent[1].DeliveryID != first[0].DeliveryID || !equalIDs(eventIDs(sent[1]), eventIDs(first[0])) {
		t.Error("the retry is not the same batch")
	}
	assertContiguous(t, sent[2], 4, 5)
	if st := h.state(d); st.Cursor != 5 || st.ConsecutiveFailures != 0 || st.Pending != uuid.Nil {
		t.Errorf("state %+v", st)
	}
	if recs := h.store.recordsOf(audit.CodeNotificationDelivered); len(recs) != 2 || recs[0].Params["attempts"] != 2 {
		t.Errorf("delivered records %+v", recs)
	}
}

func equalIDs(a, b []uuid.UUID) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestBackoff: 5 s doubling, capped at 10 minutes; no attempt before next_attempt_at.
func TestBackoff(t *testing.T) {
	for n, want := range map[int]time.Duration{1: 5 * time.Second, 2: 10 * time.Second, 3: 20 * time.Second,
		7: 320 * time.Second, 8: 10 * time.Minute, 30: 10 * time.Minute, 1000: 10 * time.Minute} {
		if got := Backoff(n); got != want {
			t.Errorf("Backoff(%d) = %v, want %v", n, got, want)
		}
	}
	h := newHarness(t)
	d := h.webhook(h.org, State{})
	h.index.append(h.org, tamper, 1)
	h.tr.fail = &DeliveryError{Class: "dial"}
	h.round()
	if st := h.state(d); st.NextAttemptAt == nil || !st.NextAttemptAt.Equal(h.now.Add(5*time.Second)) {
		t.Fatalf("next attempt %v", st.NextAttemptAt)
	}
	h.now = h.now.Add(4 * time.Second)
	h.round()
	if len(h.tr.sent) != 1 {
		t.Fatalf("attempt before the backoff ended (%d)", len(h.tr.sent))
	}
	h.now = h.now.Add(time.Second)
	h.round()
	if st := h.state(d); len(h.tr.sent) != 2 || !st.NextAttemptAt.Equal(h.now.Add(10*time.Second)) {
		t.Fatalf("second attempt %d, next %v", len(h.tr.sent), st.NextAttemptAt)
	}
}

// TestStallAndResume: failing longer than the threshold stalls once; the success after it records the delivery with
// resumed and destination_resumed once.
func TestStallAndResume(t *testing.T) {
	h := newHarness(t)
	d := h.webhook(h.org, State{})
	h.index.append(h.org, tamper, 2)
	h.tr.fail = &DeliveryError{Class: "http_500"}
	start := h.now
	for h.now.Sub(start) < 3*time.Minute {
		h.round()
		h.now = h.now.Add(5 * time.Second)
		if st := h.state(d); st.NextAttemptAt != nil && st.NextAttemptAt.After(h.now) {
			h.now = *st.NextAttemptAt
		}
	}
	stalled := h.store.recordsOf(audit.CodeNotificationDestinationStalled)
	if len(stalled) != 1 {
		t.Fatalf("%d stalled records, want 1", len(stalled))
	}
	if p := stalled[0].Params; p["last_error"] != "http_500" || p["forward_seq"] != int64(1) || p["since_s"].(int64) < 60 {
		t.Errorf("stalled params %+v", p)
	}
	st := h.state(d)
	if st.Status != StatusStalled || st.StalledSince == nil || st.Cursor != 0 {
		t.Fatalf("state %+v", st)
	}
	if v := testutil.ToFloat64(h.metrics.stalled.WithLabelValues(d.Destination.ID.String(), "webhook")); v != 1 {
		t.Errorf("stalled gauge %v", v)
	}
	since := *st.StalledSince
	h.tr.fail = nil
	h.now = *st.NextAttemptAt
	h.round()
	h.round()
	resumed := h.store.recordsOf(audit.CodeNotificationDestinationResumed)
	if len(resumed) != 1 || resumed[0].Params["stalled_for_s"] != int64(h.now.Sub(since).Seconds()) ||
		resumed[0].Params["forward_from"] != int64(1) || resumed[0].Params["forward_to"] != int64(2) {
		t.Fatalf("resumed records %+v", resumed)
	}
	delivered := h.store.recordsOf(audit.CodeNotificationDelivered)
	if len(delivered) != 1 || delivered[0].Params["resumed"] != true {
		t.Fatalf("delivered %+v", delivered)
	}
	if st := h.state(d); st.Status != StatusActive || st.Cursor != 2 {
		t.Errorf("state %+v", st)
	}
	if v := testutil.ToFloat64(h.metrics.stalled.WithLabelValues(d.Destination.ID.String(), "webhook")); v != 0 {
		t.Errorf("stalled gauge %v", v)
	}
	if v := testutil.ToFloat64(h.metrics.deliveries.WithLabelValues("webhook", "success")); v != 1 {
		t.Errorf("success counter %v", v)
	}
}

// TestHeartbeat: only after the interval without a delivery or heartbeat.
func TestHeartbeat(t *testing.T) {
	h := newHarness(t)
	d := h.webhook(h.org, State{})
	h.store.rows[d.Destination.ID].Destination.HeartbeatInterval = time.Minute
	h.round()
	beats := h.tr.kinds(outbound.KindHeartbeat)
	if len(beats) != 1 || beats[0].ForwardSeq == nil || beats[0].ForwardSeq.Last == nil || *beats[0].ForwardSeq.Last != 0 ||
		beats[0].Cursor == nil || beats[0].Events == nil || len(beats[0].Events) != 0 {
		t.Fatalf("first heartbeat %+v", beats)
	}
	h.now = h.now.Add(30 * time.Second)
	h.round()
	if n := len(h.tr.kinds(outbound.KindHeartbeat)); n != 1 {
		t.Fatalf("%d heartbeats within the interval", n)
	}
	h.now = h.now.Add(31 * time.Second)
	h.index.append(h.org, tamper, 1)
	h.round()
	if n := len(h.tr.kinds(outbound.KindHeartbeat)); n != 1 {
		t.Fatalf("heartbeat in a round with a delivery (%d)", n)
	}
	h.now = h.now.Add(59 * time.Second)
	h.round()
	if n := len(h.tr.kinds(outbound.KindHeartbeat)); n != 1 {
		t.Fatalf("heartbeat within the interval after a delivery (%d)", n)
	}
	h.now = h.now.Add(2 * time.Second)
	h.round()
	beats = h.tr.kinds(outbound.KindHeartbeat)
	if len(beats) != 2 || *beats[1].ForwardSeq.Last != 1 || *beats[1].Cursor != 1 {
		t.Fatalf("heartbeats %+v", beats)
	}
	if len(h.store.recordsOf(audit.CodeNotificationDelivered)) != 1 {
		t.Error("a heartbeat was recorded as delivered")
	}
}

// TestNonMatchingWindow: 500 events that match nothing move the cursor without a delivery and the scan continues in
// the same round; fewer than a window stay unread until the window fills.
func TestNonMatchingWindow(t *testing.T) {
	if outbound.IsSecurityCode(audit.CodeDeviceEnrolled) {
		t.Fatal("device.enrolled is a security code; pick another non-matching code")
	}
	h := newHarness(t)
	d := h.webhook(h.org, State{})
	h.index.append(h.org, audit.CodeDeviceEnrolled, 499)
	h.round()
	if st := h.state(d); st.Cursor != 0 || len(h.tr.sent) != 0 {
		t.Fatalf("cursor %d, %d messages after 499 non-matching events", st.Cursor, len(h.tr.sent))
	}
	h.index.append(h.org, audit.CodeDeviceEnrolled, 1)
	h.round()
	if st := h.state(d); st.Cursor != 500 || len(h.tr.sent) != 0 {
		t.Fatalf("cursor %d, %d messages after 500 non-matching events", st.Cursor, len(h.tr.sent))
	}
	h.index.append(h.org, audit.CodeDeviceEnrolled, 500)
	match := h.index.append(h.org, tamper, 1)
	h.round()
	sent := h.tr.kinds(outbound.KindEvents)
	if st := h.state(d); len(sent) != 1 || sent[0].Events[0].Event.EventID != match[0].Event.EventID ||
		sent[0].Events[0].CommitSeq != 1001 || st.Cursor != 1001 {
		t.Fatalf("cursor %d, sent %d", st.Cursor, len(sent))
	}
	assertContiguous(t, sent[0], 1, 1)
}

// TestStartAtLatest: a new destination (or one enabled with skip) starts after the newest event and never delivers
// an event at or below it; the cursor never decreases.
func TestStartAtLatest(t *testing.T) {
	h := newHarness(t)
	d := h.webhook(h.org, State{StartAtLatest: true})
	h.index.append(h.org, tamper, 10)
	h.round()
	if st := h.state(d); st.Cursor != 10 || st.StartAtLatest || len(h.tr.sent) != 0 {
		t.Fatalf("state %+v, %d messages", st, len(h.tr.sent))
	}
	added := h.index.append(h.org, tamper, 1)
	h.round()
	sent := h.tr.kinds(outbound.KindEvents)
	if len(sent) != 1 || len(sent[0].Events) != 1 || sent[0].Events[0].Event.EventID != added[0].Event.EventID {
		t.Fatalf("sent %+v", sent)
	}
	assertContiguous(t, sent[0], 1, 1)
}

// TestStartAtLatestDropsPending: a skip request while a batch is pending drops that batch as skipped (not a failure)
// and continues after the newest event.
func TestStartAtLatestDropsPending(t *testing.T) {
	h := newHarness(t)
	d := h.webhook(h.org, State{})
	h.index.append(h.org, tamper, 3)
	h.tr.fail = &DeliveryError{Class: "http_503"}
	h.round()
	pending := h.state(d).Pending
	if pending == uuid.Nil {
		t.Fatal("no pending batch")
	}
	h.index.append(h.org, tamper, 2)
	h.store.rows[d.Destination.ID].State.StartAtLatest = true
	h.tr.fail = nil
	h.now = h.now.Add(10 * time.Second)
	h.round()
	st := h.state(d)
	if st.Pending != uuid.Nil || st.Cursor != 5 || st.ConsecutiveFailures != 1 || len(h.tr.sent) != 1 {
		t.Fatalf("state %+v, %d messages", st, len(h.tr.sent))
	}
	if got := h.store.deliveries[pending]; got.lastError != "skipped" || got.attempts != 1 || got.delivered {
		t.Errorf("dropped batch %+v", got)
	}
	added := h.index.append(h.org, tamper, 1)
	h.round()
	sent := h.tr.kinds(outbound.KindEvents)
	if len(sent) != 2 || sent[1].Events[0].Event.EventID != added[0].Event.EventID {
		t.Fatalf("sent %d", len(sent))
	}
	assertContiguous(t, sent[1], 4, 4)
}

// TestTestDelivery: a requested test is delivered once and recorded as notification.test_sent with its result; it
// changes no failure state.
func TestTestDelivery(t *testing.T) {
	h := newHarness(t)
	d := h.webhook(h.org, State{})
	id := h.store.requestTest(d.Destination.ID, "alice")
	h.round()
	tests := h.tr.kinds(outbound.KindTest)
	if len(tests) != 1 || tests[0].DeliveryID != id.String() || tests[0].Events == nil || len(tests[0].Events) != 0 {
		t.Fatalf("test messages %+v", tests)
	}
	recs := h.store.recordsOf(audit.CodeNotificationTestSent)
	if len(recs) != 1 || recs[0].Failure != nil || recs[0].Params["requested_by"] != "alice" ||
		recs[0].Params["destination_id"] != d.Destination.ID.String() {
		t.Fatalf("records %+v", recs)
	}
	h.round()
	if len(h.tr.kinds(outbound.KindTest)) != 1 {
		t.Fatal("test delivered twice")
	}

	h.store.requestTest(d.Destination.ID, "bob")
	h.tr.fail = &DeliveryError{Class: "redirect"}
	h.round()
	recs = h.store.recordsOf(audit.CodeNotificationTestSent)
	if len(recs) != 2 || recs[1].Failure == nil || recs[1].Params["error"] != "redirect" {
		t.Fatalf("failed test record %+v", recs)
	}
	if st := h.state(d); st.ConsecutiveFailures != 0 || st.NextAttemptAt != nil {
		t.Errorf("a failed test changed the failure state: %+v", st)
	}
	h.round()
	if n := len(h.tr.kinds(outbound.KindTest)); n != 2 {
		t.Errorf("a failed test was attempted again (%d)", n)
	}
}

// TestScopeIsolation (gate N7 in miniature): each destination receives only the events of its own scope.
func TestScopeIsolation(t *testing.T) {
	h := newHarness(t)
	other := uuid.Must(uuid.NewV7())
	h.store.orgs = append(h.store.orgs, other)
	h.store.slugs[other] = "globex"
	a := h.webhook(h.org, State{})
	b := h.webhook(other, State{})
	p := h.webhook(audit.PlatformOrganizationID, State{})
	h.store.rows[p.Destination.ID].Destination.Filter = outbound.FilterAll
	inA := h.index.append(h.org, tamper, 2)
	inB := h.index.append(other, tamper, 3)
	inP := h.index.append(audit.PlatformOrganizationID, audit.CodeAgentRolloutHalted, 1)
	h.round()
	got := map[uuid.UUID][]outbound.Message{}
	for _, s := range h.tr.sent {
		got[s.dest.ID] = append(got[s.dest.ID], s.msg)
	}
	for _, c := range []struct {
		row    *Row
		events []IndexedEvent
		slug   string
		org    uuid.UUID
	}{{a, inA, "acme", h.org}, {b, inB, "globex", other}, {p, inP, outbound.PlatformOrganization, audit.PlatformOrganizationID}} {
		msgs := got[c.row.Destination.ID]
		if len(msgs) != 1 || msgs[0].Organization != c.slug || msgs[0].OrganizationID != c.org.String() {
			t.Fatalf("%s: messages %+v", c.slug, msgs)
		}
		want := make([]uuid.UUID, len(c.events))
		for i, e := range c.events {
			want[i] = e.Event.EventID
		}
		if !equalIDs(eventIDs(msgs[0]), want) {
			t.Errorf("%s received foreign events", c.slug)
		}
	}
	for _, s := range h.tr.sent {
		if s.dest.URL != "https://sink.example/"+s.dest.ID.String() || string(s.dest.Secret) != "whsec-"+s.dest.ID.String() {
			t.Errorf("destination %s got another destination's URL or secret", s.dest.ID)
		}
	}
}

// TestLinksAndPseudonyms: device targets carry a portal link; with pseudonymize_users the actor's name is replaced
// before sending, and a pending lookup is resolved with the organization's key.
func TestLinksAndPseudonyms(t *testing.T) {
	h := newHarness(t)
	d := h.webhook(h.org, State{})
	h.store.rows[d.Destination.ID].Destination.Pseudonymize = true
	h.store.rows[d.Destination.ID].Destination.Filter = outbound.FilterAll
	h.store.pkey[h.org] = "pkey:" + h.org.String()
	ev := h.index.append(h.org, tamper, 1)
	device := uuid.Must(uuid.NewV7())
	h.index.events[h.org][0].Event.Target = &audit.Target{Type: "device", ID: device.String(), Display: "lt-01"}
	h.index.events[h.org][0].Event.Actor = audit.Actor{Type: audit.ActorAdmin, Display: "Alice", ID: "x", IP: "10.0.0.1"}
	key := []byte("pseudonym-key-" + h.org.String())
	h.store.names = []string{"alice", "bob"}
	lookup := uuid.Must(uuid.NewV7())
	h.store.lookups[lookup] = &Lookup{ID: lookup, Pseudonym: outbound.Pseudonym(key, "bob")}
	missing := uuid.Must(uuid.NewV7())
	h.store.lookups[missing] = &Lookup{ID: missing, Pseudonym: "u_000000000000000000000000"}
	h.round()
	sent := h.tr.kinds(outbound.KindEvents)
	if len(sent) != 1 {
		t.Fatalf("%d messages", len(sent))
	}
	me := sent[0].Events[0]
	if me.Event.EventID != ev[0].Event.EventID || me.Links == nil || me.Links.Device != "https://admin.example/devices/"+device.String() {
		t.Errorf("links %+v", me.Links)
	}
	if me.Event.Actor.Display != outbound.Pseudonym(key, "Alice") || me.Event.Actor.ID != "" || me.Event.Actor.IP != "" {
		t.Errorf("actor not pseudonymized: %+v", me.Event.Actor)
	}
	if h.store.resolved[lookup] != "bob" || h.store.resolved[missing] != "" {
		t.Errorf("lookups %+v", h.store.resolved)
	}
	if _, ok := h.store.resolved[missing]; !ok {
		t.Error("an unmatched lookup was not answered")
	}
}

// TestLeaderLock: a replica without the lock serves nothing.
func TestLeaderLock(t *testing.T) {
	h := newHarness(t)
	h.leader.busy = true
	h.webhook(h.org, State{})
	h.index.append(h.org, tamper, 1)
	h.round()
	if len(h.tr.sent) != 0 {
		t.Fatal("delivered without the lock")
	}
}

// TestErrorClass: only a closed class word is ever recorded.
func TestErrorClass(t *testing.T) {
	for err, want := range map[error]string{
		&DeliveryError{Class: "http_500"}:               "http_500",
		&DeliveryError{Class: "https://user:pw@host/x"}: "dial",
		context.DeadlineExceeded:                        "dial",
		&DeliveryError{Class: "redirect"}:               "redirect",
	} {
		if got := ErrorClass(err); got != want {
			t.Errorf("ErrorClass(%v) = %q, want %q", err, got, want)
		}
	}
}

// blockingTransport holds every delivery to one destination until release is closed and passes the others on.
type blockingTransport struct {
	blocked uuid.UUID
	release chan struct{}
	next    *fakeTransport
}

func (b blockingTransport) Deliver(ctx context.Context, d Destination, m outbound.Message) error {
	if d.ID == b.blocked {
		<-b.release
	}
	return b.next.Deliver(ctx, d, m)
}

// TestIndependentDestinations: a receiver that does not answer does not hold up another destination's delivery.
func TestIndependentDestinations(t *testing.T) {
	h := newHarness(t)
	slow := h.webhook(h.org, State{})
	fast := h.webhook(h.org, State{})
	release := make(chan struct{})
	h.e.transports[outbound.TypeWebhook] = blockingTransport{blocked: slow.Destination.ID, release: release, next: h.tr}
	h.index.append(h.org, tamper, 1)
	done := make(chan error, 1)
	go func() { done <- h.e.Round(context.Background()) }()
	deadline := time.After(5 * time.Second)
	for {
		h.tr.mu.Lock()
		n := len(h.tr.sent)
		h.tr.mu.Unlock()
		if n == 1 {
			break
		}
		select {
		case <-deadline:
			close(release)
			t.Fatal("the fast destination waited for the blocked one")
		case <-time.After(10 * time.Millisecond):
		}
	}
	h.tr.mu.Lock()
	first := h.tr.sent[0].dest.ID
	h.tr.mu.Unlock()
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if first != fast.Destination.ID || len(h.tr.sent) != 2 {
		t.Fatalf("first delivery to %s, %d deliveries", first, len(h.tr.sent))
	}
}

// syncClock is a clock that transports may advance from the engine's goroutines.
type syncClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *syncClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *syncClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// slowTransport takes 30 s of the clock for every delivery to one destination.
type slowTransport struct {
	slow  uuid.UUID
	clock *syncClock
	next  *fakeTransport
}

func (s slowTransport) Deliver(ctx context.Context, d Destination, m outbound.Message) error {
	if d.ID == s.slow {
		s.clock.Advance(30 * time.Second)
	}
	return s.next.Deliver(ctx, d, m)
}

// TestDestinationBudget: a slow receiver gets at most DestinationBudget of a round and continues in the next; another
// organization's destination is delivered in the same round.
func TestDestinationBudget(t *testing.T) {
	h := newHarness(t)
	clock := &syncClock{now: h.now}
	h.e.now = clock.Now
	h.index.clock = clock.Now
	h.e.cfg.Batch = 10
	other := uuid.Must(uuid.NewV7())
	h.store.orgs = append(h.store.orgs, other)
	slow := h.webhook(h.org, State{})
	fast := h.webhook(other, State{})
	h.e.transports[outbound.TypeWebhook] = slowTransport{slow: slow.Destination.ID, clock: clock, next: h.tr}
	h.index.append(h.org, tamper, 50)
	h.index.append(other, tamper, 1)
	h.round()
	count := func(id uuid.UUID) int {
		n := 0
		for _, s := range h.tr.sent {
			if s.dest.ID == id {
				n++
			}
		}
		return n
	}
	if n := count(slow.Destination.ID); n != 2 {
		t.Fatalf("%d deliveries to the slow receiver in one round, want 2 (60 s budget)", n)
	}
	if n := count(fast.Destination.ID); n != 1 {
		t.Fatalf("the other organization's destination got %d deliveries in the round", n)
	}
	h.round()
	if n := count(slow.Destination.ID); n != 4 {
		t.Fatalf("%d deliveries after the second round, want 4", n)
	}
	if st := h.state(slow); st.Cursor != 40 || st.ForwardSeq != 40 {
		t.Errorf("slow state %+v", st)
	}
}

// TestInternalFailureStalls: a ciphertext that does not decrypt and an unreadable pending batch are failures of class
// internal: backoff, then the stall with its event; nothing is sent.
func TestInternalFailureStalls(t *testing.T) {
	for _, c := range []struct {
		name  string
		setup func(h *harness, r *Row)
	}{
		{"decrypt denied", func(h *harness, r *Row) { r.URLCiphertext = "denied" }},
		{"pending batch unreadable", func(h *harness, r *Row) {
			h.store.pendingErr = errors.New("connection reset")
			r.State.Pending = uuid.Must(uuid.NewV7())
			r.State.ForwardSeq = 4
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			h := newHarness(t)
			d := h.webhook(h.org, State{})
			c.setup(h, h.store.rows[d.Destination.ID])
			h.index.append(h.org, tamper, 1)
			start := h.now
			for h.now.Sub(start) < 2*time.Minute {
				_ = h.e.Round(context.Background())
				if st := h.state(d); st.NextAttemptAt != nil {
					h.now = *st.NextAttemptAt
				} else {
					h.now = h.now.Add(5 * time.Second)
				}
			}
			if len(h.tr.sent) != 0 {
				t.Fatalf("%d messages sent", len(h.tr.sent))
			}
			st := h.state(d)
			stalled := h.store.recordsOf(audit.CodeNotificationDestinationStalled)
			if st.Status != StatusStalled || st.ConsecutiveFailures < 3 || len(stalled) != 1 ||
				stalled[0].Params["last_error"] != "internal" {
				t.Fatalf("state %+v, stalled %+v", st, stalled)
			}
			if v := testutil.ToFloat64(h.metrics.stalled.WithLabelValues(d.Destination.ID.String(), "webhook")); v != 1 {
				t.Errorf("stalled gauge %v", v)
			}
		})
	}
}

// TestLagRisesDuringBackoff: the lag is the age of the oldest undelivered event's commit and keeps rising while the
// destination waits for its backoff, also for an engine that has just started.
func TestLagRisesDuringBackoff(t *testing.T) {
	h := newHarness(t)
	d := h.webhook(h.org, State{})
	lag := func() float64 { return testutil.ToFloat64(h.metrics.lag.WithLabelValues(d.Destination.ID.String())) }
	h.index.append(h.org, tamper, 1)
	h.now = h.now.Add(2 * time.Second)
	h.tr.fail = &DeliveryError{Class: "http_503"}
	h.round()
	if v := lag(); v != 2 {
		t.Fatalf("lag after the failure %v, want 2", v)
	}
	h.now = h.now.Add(3 * time.Second)
	h.round()
	if v := lag(); v != 5 {
		t.Fatalf("lag during the backoff %v, want 5", v)
	}
	h.e.oldest = map[uuid.UUID]time.Time{}
	h.now = h.now.Add(4 * time.Second)
	h.round()
	if v := lag(); v != 9 {
		t.Fatalf("lag after a restart during the backoff %v, want 9", v)
	}
	h.tr.fail = nil
	h.now = h.now.Add(10 * time.Second)
	h.round()
	if v := lag(); v != 0 {
		t.Fatalf("lag after the delivery %v, want 0", v)
	}
}

// staleTransport drops the destination's pending batch while the delivery is under way, as a skip request resolved
// by another round would.
type staleTransport struct {
	store *fakeStore
	fail  error
	next  *fakeTransport
}

func (s staleTransport) Deliver(ctx context.Context, d Destination, m outbound.Message) error {
	s.store.mu.Lock()
	s.store.rows[d.ID].State.Pending = uuid.Nil
	s.store.mu.Unlock()
	if err := s.next.Deliver(ctx, d, m); err != nil {
		return err
	}
	return s.fail
}

// TestStaleStateChange: a success or failure whose pending batch is gone changes nothing and records nothing, so
// notification.delivered and the stall exist at most once.
func TestStaleStateChange(t *testing.T) {
	for _, fail := range []error{nil, &DeliveryError{Class: "http_500"}} {
		h := newHarness(t)
		h.e.cfg.StallAfter = time.Nanosecond
		d := h.webhook(h.org, State{FirstFailureAt: &h.now, ConsecutiveFailures: 3})
		h.e.transports[outbound.TypeWebhook] = staleTransport{store: h.store, fail: fail, next: h.tr}
		h.index.append(h.org, tamper, 1)
		h.now = h.now.Add(time.Second)
		if err := h.e.Round(context.Background()); err != nil {
			t.Fatalf("round: %v", err)
		}
		if h.store.stale != 1 || len(h.store.records) != 0 || len(h.tr.sent) != 1 {
			t.Fatalf("fail %v: %d stale, records %+v, %d sent", fail, h.store.stale, h.store.records, len(h.tr.sent))
		}
		if st := h.state(d); st.Cursor != 0 || st.ConsecutiveFailures != 3 || st.Status != StatusActive {
			t.Fatalf("fail %v: state changed %+v", fail, st)
		}
	}
}
