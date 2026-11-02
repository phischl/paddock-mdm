package acceptance

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/pkg/protocol"
	"github.com/phischl/paddock-mdm/test/acceptance/internal/env"
	"github.com/phischl/paddock-mdm/test/acceptance/internal/sink"
)

const (
	tamperCode = "device.tamper_sudoers_d_file"
	// deliveryTimeout is the bound of gate N3: an event reaches the sink within 60 s.
	deliveryTimeout = 60 * time.Second
)

// envelope is the received paddock.notification.v1 message (plan M9 §6.4).
type envelope struct {
	Schema         string `json:"schema"`
	Kind           string `json:"kind"`
	DeliveryID     string `json:"delivery_id"`
	DestinationID  string `json:"destination_id"`
	OrganizationID string `json:"organization_id"`
	Organization   string `json:"organization"`
	ForwardSeq     *struct {
		From int64 `json:"from"`
		To   int64 `json:"to"`
	} `json:"forward_seq"`
	Events []struct {
		ForwardSeq int64 `json:"forward_seq"`
		CommitSeq  int64 `json:"commit_seq"`
		Links      *struct {
			Device string `json:"device"`
		} `json:"links"`
		Event struct {
			Schema         string `json:"schema"`
			EventID        string `json:"event_id"`
			OrganizationID string `json:"organization_id"`
			Code           string `json:"code"`
			Target         *struct {
				Type string `json:"type"`
				ID   string `json:"id"`
			} `json:"target"`
		} `json:"event"`
	} `json:"events"`
	request sink.Request
}

// envelopes decodes the received requests of one kind, in arrival order.
func envelopes(t *testing.T, reqs []sink.Request, kind string) []envelope {
	t.Helper()
	var out []envelope
	for _, r := range reqs {
		var e envelope
		if err := json.Unmarshal(r.Body, &e); err != nil {
			t.Fatalf("sink received a body that is not JSON: %v %q", err, r.Body)
		}
		if e.Kind == kind {
			e.request = r
			out = append(out, e)
		}
	}
	return out
}

func eventsOf(t *testing.T, reqs []sink.Request) []envelope {
	t.Helper()
	return envelopes(t, reqs, "events")
}

// hasTarget reports whether any received events message carries an event whose target is id.
func hasTarget(t *testing.T, reqs []sink.Request, id string) bool {
	t.Helper()
	for _, e := range eventsOf(t, reqs) {
		for _, ev := range e.Events {
			if ev.Event.Target != nil && ev.Event.Target.ID == id {
				return true
			}
		}
	}
	return false
}

// verifySignature checks the headers of plan M9 §6.4 and the HMAC with the secret shown at creation.
func verifySignature(t *testing.T, r sink.Request, secret, destination string) {
	t.Helper()
	ts := r.Header.Get("X-Paddock-Timestamp")
	sec, err := strconv.ParseInt(ts, 10, 64)
	if err != nil || time.Since(time.Unix(sec, 0)).Abs() > 5*time.Minute {
		t.Fatalf("X-Paddock-Timestamp %q", ts)
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(ts + "." + string(r.Body)))
	if want := "v1=" + hex.EncodeToString(mac.Sum(nil)); r.Header.Get("X-Paddock-Signature") != want {
		t.Fatalf("X-Paddock-Signature %q does not verify with the destination's secret", r.Header.Get("X-Paddock-Signature"))
	}
	var e envelope
	_ = json.Unmarshal(r.Body, &e)
	if r.Header.Get("X-Paddock-Delivery") != e.DeliveryID || e.DeliveryID == "" ||
		r.Header.Get("X-Paddock-Destination") != destination || e.DestinationID != destination ||
		r.Header.Get("Content-Type") != "application/json" || !strings.HasPrefix(r.Header.Get("User-Agent"), "paddock-notifier/") {
		t.Fatalf("headers %v for delivery %s of destination %s", r.Header, e.DeliveryID, destination)
	}
}

type destinationState struct {
	State struct {
		Status    string  `json:"status"`
		Cursor    int64   `json:"cursor_commit_seq"`
		Forward   int64   `json:"forward_seq"`
		LastError *string `json:"last_error"`
		LastTest  *struct {
			OK    bool    `json:"ok"`
			Error *string `json:"error"`
		} `json:"last_test"`
	} `json:"state"`
}

// waitDestinationState polls GET path until cond holds.
func waitDestinationState(t *testing.T, p *env.Portal, path string, timeout time.Duration, what string,
	cond func(destinationState) bool) destinationState {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		res := call(t, p, http.MethodGet, path, nil)
		expectStatus(t, res, http.StatusOK, "")
		var d destinationState
		if err := res.JSON(&d); err != nil {
			t.Fatal(err)
		}
		if cond(d) {
			return d
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s: %s not reached within %s: %s", path, what, timeout, res.Body)
		}
		time.Sleep(time.Second)
	}
}

// waitStarted waits until the notifier moved a new destination to the scope's newest event (start_at_latest); events
// recorded before are never delivered to it.
func waitStarted(t *testing.T, p *env.Portal, path string) destinationState {
	t.Helper()
	return waitDestinationState(t, p, path, time.Minute, "the start at the newest event",
		func(d destinationState) bool { return d.State.Cursor > 0 })
}

// tamperDestination creates a webhook destination on url for the tamper code only, so that no other event of the
// organization (its own creation, other gates' leftovers) takes a forward sequence number.
func tamperDestination(t *testing.T, u stepper, url string) (notificationDestination, string) {
	t.Helper()
	body := webhookBody(destinationName("n"), url)
	body["filter_mode"], body["codes"] = "custom", []string{tamperCode}
	d, _ := createDestination(t, u, orgDestinations, body)
	path := orgDestinations + "/" + d.ID
	waitStarted(t, u.Portal, path)
	return d, path
}

// TestNotificationsWebhook is gate N3 (plan M9 §9): a tamper event reaches the sink within 60 s as one signed envelope
// starting at forward_seq 1, recorded once as notification.delivered; 150 events leave as 100 + 50 with contiguous
// numbers and no event twice.
func TestNotificationsWebhook(t *testing.T) {
	admin := adminUser(t, "n3")
	as := adminStepper(admin)
	org := orgOf(t, admin.Portal)
	d := activeDevice(t, admin.Portal, "", "n3-"+uniqueSuffix())
	s := sink.Start(t)
	dest, _ := tamperDestination(t, as, s.URL())

	sendSudoersEvent(t, d, 1, "n3-evil")
	got := s.Wait(t, deliveryTimeout, "the tamper event", func(r []sink.Request) bool { return len(eventsOf(t, r)) > 0 })
	msgs := eventsOf(t, got)
	if len(msgs) != 1 {
		t.Fatalf("%d events messages, want 1", len(msgs))
	}
	m := msgs[0]
	verifySignature(t, m.request, *dest.Secret, dest.ID)
	if m.Schema != "paddock.notification.v1" || m.OrganizationID != org.String() || m.ForwardSeq == nil ||
		m.ForwardSeq.From != 1 || m.ForwardSeq.To != 1 || len(m.Events) != 1 {
		t.Fatalf("envelope %s", m.request.Body)
	}
	ev := m.Events[0]
	if ev.ForwardSeq != 1 || ev.CommitSeq <= 0 || ev.Event.Code != tamperCode || ev.Event.Schema != "paddock.audit.v1" ||
		ev.Event.Target == nil || ev.Event.Target.ID != d.DeviceID || ev.Links == nil ||
		!strings.HasSuffix(ev.Links.Device, "/devices/"+d.DeviceID) {
		t.Fatalf("event %s", m.request.Body)
	}
	delivered := expectOneIndexEvent(t, auditIndex(t), org, "code = 'notification.delivered' AND target->>'id' = $1", dest.ID,
		"notification.delivered", "success", time.Minute)
	if delivered.Params["forward_from"] != float64(1) || delivered.Params["forward_to"] != float64(1) ||
		delivered.Params["count"] != float64(1) || delivered.Params["kind"] != "events" {
		t.Fatalf("delivered params %v", delivered.Params)
	}

	t.Run("150 events as 100 + 50", func(t *testing.T) {
		s2 := sink.Start(t)
		dest2, path := tamperDestination(t, as, s2.URL())
		// Disabled while the events are indexed, so that the first scan after enabling sees all 150 at once.
		admin.stepUp(t)
		res := call(t, admin.Portal, http.MethodPut, path, map[string]any{"name": dest2.Name, "enabled": false,
			"filter_mode": "custom", "codes": []string{tamperCode}})
		expectStatus(t, res, http.StatusOK, "")
		events := make([]protocol.Event, 150)
		for i := range events {
			data, _ := json.Marshal(map[string]string{"file": "n3-batch", "quarantined_as": "/var/lib/paddock/quarantine/n3"})
			events[i] = protocol.Event{EventSeq: int64(i + 2), Type: protocol.EventTamperSudoersDFile, OccurredAt: time.Now(), Data: data}
		}
		sent, err := d.SendEvents(testContext(t, time.Minute), events)
		if err != nil || sent.Status != http.StatusAccepted {
			t.Fatalf("events: %v HTTP %d %s", err, sent.Status, sent.Body)
		}
		idx := auditIndex(t)
		deadline := time.Now().Add(2 * time.Minute)
		for {
			indexed, err := idx.Events(testContext(t, time.Minute), org, "code = '"+tamperCode+"' AND target->>'id' = $1", d.DeviceID)
			if err != nil {
				t.Fatal(err)
			}
			if len(indexed) == 151 {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("%d of 151 tamper events indexed", len(indexed))
			}
			time.Sleep(time.Second)
		}
		admin.stepUp(t)
		res = call(t, admin.Portal, http.MethodPut, path, map[string]any{"name": dest2.Name, "enabled": true,
			"filter_mode": "custom", "codes": []string{tamperCode}, "cursor": "continue"})
		expectStatus(t, res, http.StatusOK, "")
		got := s2.Wait(t, deliveryTimeout, "150 events", func(r []sink.Request) bool {
			n := 0
			for _, e := range eventsOf(t, r) {
				n += len(e.Events)
			}
			return n >= 150
		})
		msgs := eventsOf(t, got)
		if len(msgs) != 2 || msgs[0].ForwardSeq.From != 1 || msgs[0].ForwardSeq.To != 100 || len(msgs[0].Events) != 100 ||
			msgs[1].ForwardSeq.From != 101 || msgs[1].ForwardSeq.To != 150 || len(msgs[1].Events) != 50 {
			t.Fatalf("%d messages: want 1–100 and 101–150", len(msgs))
		}
		seen := map[string]bool{}
		next := int64(1)
		for _, m := range msgs {
			verifySignature(t, m.request, *dest2.Secret, dest2.ID)
			for _, ev := range m.Events {
				if ev.ForwardSeq != next || seen[ev.Event.EventID] || ev.Event.Target == nil || ev.Event.Target.ID != d.DeviceID {
					t.Fatalf("event %d: forward_seq %d, twice %t", next, ev.ForwardSeq, seen[ev.Event.EventID])
				}
				seen[ev.Event.EventID] = true
				next++
			}
		}
	})
}

// TestNotificationsStall is gate N4 (plan M9 §9): while the sink answers 500 the batch is retried with growing
// intervals and the cursor stays; after PADDOCK_NOTIFY_STALL_AFTER (1 minute on the development stack) the destination
// is stalled, recorded once; when the sink recovers the same batch arrives, the resumption is recorded once and the
// destination is active again.
func TestNotificationsStall(t *testing.T) {
	admin := adminUser(t, "n4")
	as := adminStepper(admin)
	org := orgOf(t, admin.Portal)
	d := activeDevice(t, admin.Portal, "", "n4-"+uniqueSuffix())
	s := sink.Start(t)
	dest, path := tamperDestination(t, as, s.URL())
	cursor := waitStarted(t, admin.Portal, path).State.Cursor
	s.Respond(http.StatusInternalServerError)
	sendSudoersEvent(t, d, 1, "n4-a")
	sendSudoersEvent(t, d, 2, "n4-b")

	stalled := waitDestinationState(t, admin.Portal, path, 3*time.Minute, "status stalled",
		func(d destinationState) bool { return d.State.Status == "stalled" })
	if stalled.State.Cursor != cursor || stalled.State.LastError == nil || *stalled.State.LastError != "http_500" {
		t.Fatalf("stalled state %+v (cursor before %d)", stalled.State, cursor)
	}
	failed := eventsOf(t, s.Requests())
	if len(failed) < 3 {
		t.Fatalf("%d attempts before the stall", len(failed))
	}
	for i, m := range failed {
		if m.DeliveryID != failed[0].DeliveryID || m.ForwardSeq == nil || m.ForwardSeq.From != failed[0].ForwardSeq.From ||
			m.ForwardSeq.To != failed[0].ForwardSeq.To {
			t.Fatalf("attempt %d is not the same batch: %s", i, m.request.Body)
		}
		if i >= 2 {
			prev, gap := failed[i-1].request.Received.Sub(failed[i-2].request.Received), m.request.Received.Sub(failed[i-1].request.Received)
			if gap < prev {
				t.Errorf("attempt %d after %s, the one before after %s: the interval did not grow", i, gap, prev)
			}
		}
	}
	idx := auditIndex(t)
	stall := expectOneIndexEvent(t, idx, org, "code = 'notification.destination_stalled' AND target->>'id' = $1", dest.ID,
		"notification.destination_stalled", "success", time.Minute)
	if stall.Params["last_error"] != "http_500" || stall.Params["forward_seq"] != float64(failed[0].ForwardSeq.From) {
		t.Fatalf("stalled params %v", stall.Params)
	}

	s.Respond(http.StatusNoContent)
	active := waitDestinationState(t, admin.Portal, path, 5*time.Minute, "status active again",
		func(d destinationState) bool { return d.State.Status == "active" && d.State.Cursor > cursor })
	if active.State.LastError != nil {
		t.Errorf("last_error after the recovery: %v", *active.State.LastError)
	}
	all := eventsOf(t, s.Requests())
	last := all[len(all)-1]
	if last.DeliveryID != failed[0].DeliveryID || last.ForwardSeq.From != failed[0].ForwardSeq.From ||
		last.ForwardSeq.To != failed[0].ForwardSeq.To || len(last.Events) != 2 {
		t.Fatalf("delivered batch %s, want the pending one %s", last.request.Body, failed[0].request.Body)
	}
	verifySignature(t, last.request, *dest.Secret, dest.ID)
	expectOneIndexEvent(t, idx, org, "code = 'notification.destination_resumed' AND target->>'id' = $1", dest.ID,
		"notification.destination_resumed", "success", time.Minute)
	resumed := expectOneIndexEvent(t, idx, org, "code = 'notification.delivered' AND target->>'id' = $1", dest.ID,
		"notification.delivered", "success", time.Minute)
	if resumed.Params["resumed"] != true || resumed.Params["attempts"] != float64(len(all)) {
		t.Fatalf("delivered params %v after %d attempts", resumed.Params, len(all))
	}
	expectOneIndexEvent(t, idx, org, "code = 'notification.destination_stalled' AND target->>'id' = $1", dest.ID,
		"notification.destination_stalled", "success", time.Minute)
}

// TestNotificationsRedirect is the delivery part of gate N5 (plan M9 §9): a sink answering 302 is a failed delivery
// with last_error redirect, recorded as notification.test_sent failure, and the signing secret appears in no index
// event.
func TestNotificationsRedirect(t *testing.T) {
	admin := adminUser(t, "n5r")
	as := adminStepper(admin)
	org := orgOf(t, admin.Portal)
	s := sink.Start(t)
	s.Respond(http.StatusFound)
	dest, path := tamperDestination(t, as, s.URL())
	admin.stepUp(t)
	res := call(t, admin.Portal, http.MethodPost, path+"/test", nil)
	expectStatus(t, res, http.StatusAccepted, "")
	st := waitDestinationState(t, admin.Portal, path, deliveryTimeout, "the test result",
		func(d destinationState) bool { return d.State.LastTest != nil })
	if st.State.LastTest.OK || st.State.LastTest.Error == nil || *st.State.LastTest.Error != "redirect" {
		t.Fatalf("test result %+v", st.State.LastTest)
	}
	tests := envelopes(t, s.Requests(), "test")
	if len(tests) != 1 || len(tests[0].Events) != 0 {
		t.Fatalf("%d test messages", len(tests))
	}
	verifySignature(t, tests[0].request, *dest.Secret, dest.ID)
	sent := expectOneIndexEvent(t, auditIndex(t), org, "code = 'notification.test_sent' AND target->>'id' = $1", dest.ID,
		"notification.test_sent", "failure", time.Minute)
	if sent.Params["error"] != "redirect" || sent.Params["requested_by"] == nil {
		t.Fatalf("test_sent params %v", sent.Params)
	}
	leaked, err := auditIndex(t).Events(testContext(t, time.Minute), org, "position($1 in params::text) > 0", *dest.Secret)
	if err != nil || len(leaked) != 0 {
		t.Fatalf("index events carrying the secret: %v %v", leaked, err)
	}
}

// TestNotificationsIsolation is gate N7 (plan M9 §9): destinations of organizations A and B and of the platform each
// receive only the events of their own scope.
func TestNotificationsIsolation(t *testing.T) {
	a := adminUser(t, "n7a")
	b := steppedUpTempUser(t, "n7b", env.RoleGroup("globex", "admins"))
	root := rootStepper(t)
	orgA, orgB := orgOf(t, a.Portal), orgOf(t, b.Portal)
	type scope struct {
		name, collection, org string
		u                     stepper
		s                     *sink.Sink
		dest                  notificationDestination
	}
	scopes := []*scope{
		{name: "A", collection: orgDestinations, org: orgA.String(), u: adminStepper(a)},
		{name: "B", collection: orgDestinations, org: orgB.String(), u: adminStepper(b)},
		{name: "platform", collection: platformDestinations, org: uuid.Nil.String(), u: root},
	}
	for _, sc := range scopes {
		sc.s = sink.Start(t)
		body := webhookBody(destinationName("n7"), sc.s.URL())
		body["filter_mode"] = "all"
		sc.dest, _ = createDestination(t, sc.u, sc.collection, body)
		waitStarted(t, sc.u.Portal, sc.collection+"/"+sc.dest.ID)
	}
	groupA, groupB := namedGroup(t, a.Portal, "n7a"), namedGroup(t, b.Portal, "n7b")
	second, _ := createDestination(t, root, platformDestinations, webhookBody(destinationName("n7p"), scopes[2].s.URL()))
	for _, w := range []struct {
		sc     *scope
		target string
	}{{scopes[0], groupA}, {scopes[1], groupB}, {scopes[2], second.ID}} {
		w.sc.s.Wait(t, deliveryTimeout, "the event of scope "+w.sc.name, func(r []sink.Request) bool { return hasTarget(t, r, w.target) })
	}
	for _, sc := range scopes {
		for _, m := range eventsOf(t, sc.s.Requests()) {
			if m.OrganizationID != sc.org || m.DestinationID != sc.dest.ID {
				t.Fatalf("scope %s received a message of %s for %s", sc.name, m.OrganizationID, m.DestinationID)
			}
			for _, ev := range m.Events {
				if ev.Event.OrganizationID != sc.org {
					t.Fatalf("scope %s received event %s (%s) of organization %s", sc.name, ev.Event.EventID, ev.Event.Code,
						ev.Event.OrganizationID)
				}
			}
		}
	}
	if m := eventsOf(t, scopes[2].s.Requests()); m[0].Organization != "platform" {
		t.Fatalf("platform envelope organization %q", m[0].Organization)
	}
	expectStatus(t, call(t, b.Portal, http.MethodGet, orgDestinations+"/"+scopes[0].dest.ID, nil), http.StatusNotFound, "not_found")
}
