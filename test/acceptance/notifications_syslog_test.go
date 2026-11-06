package acceptance

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/test/acceptance/internal/stack"
	"github.com/phischl/paddock-mdm/test/acceptance/internal/syslogsink"
)

// syslogEventBody is the MSG of a forwarded event (ADR 0031 amendment 2026-11-04 item 2).
type syslogEventBody struct {
	Schema     string `json:"schema"`
	ForwardSeq int64  `json:"forward_seq"`
	CommitSeq  int64  `json:"commit_seq"`
	DeliveryID string `json:"delivery_id"`
	Event      struct {
		EventID        string `json:"event_id"`
		OrganizationID string `json:"organization_id"`
		Code           string `json:"code"`
		Target         *struct {
			ID string `json:"id"`
		} `json:"target"`
	} `json:"event"`
}

// syslogControlBody is the MSG of a heartbeat, test or checkpoint message: the paddock.notification.v1 envelope.
type syslogControlBody struct {
	Schema        string `json:"schema"`
	Kind          string `json:"kind"`
	DeliveryID    string `json:"delivery_id"`
	DestinationID string `json:"destination_id"`
	ForwardSeq    *struct {
		From int64  `json:"from"`
		To   int64  `json:"to"`
		Last *int64 `json:"last"`
	} `json:"forward_seq"`
	Day            string `json:"day"`
	EventCount     int    `json:"event_count"`
	ManifestSHA256 string `json:"manifest_sha256"`
	Signature      string `json:"signature"`
	KeyVersion     int    `json:"key_version"`
}

// syslogDestinationBody creates a syslog destination for the tamper code only that targets s, so that no other event
// of the organization takes a forward sequence number.
func syslogDestinationBody(name string, s *syslogsink.Sink, trustSink, checkpoints bool, heartbeatS int) map[string]any {
	body := map[string]any{
		"type": "syslog", "name": name, "enabled": true, "filter_mode": "custom", "codes": []string{tamperCode},
		"syslog_host": s.Host(), "syslog_port": s.Port(), "syslog_server_name": s.ServerName(), "checkpoints": checkpoints,
	}
	if trustSink {
		body["syslog_ca_pem"] = s.CAPEM()
	}
	if heartbeatS > 0 {
		body["heartbeat_interval_s"] = heartbeatS
	}
	return body
}

// syslogEvents decodes the event messages (every message whose MSGID is not a paddock.* control id) in arrival order.
func syslogEvents(t *testing.T, msgs []syslogsink.Message) []syslogEventBody {
	t.Helper()
	var out []syslogEventBody
	for _, m := range msgs {
		if strings.HasPrefix(m.MsgID, "paddock.") {
			continue
		}
		var b syslogEventBody
		if err := json.Unmarshal(m.Body, &b); err != nil {
			t.Fatalf("syslog event body %q: %v", m.Body, err)
		}
		if b.Schema != "paddock.audit.v1" || m.MsgID != b.Event.Code || m.AppName != "paddock" || m.PRI/8 != 16 {
			t.Fatalf("syslog event %+v: schema %q, MSGID %q for code %q", m, b.Schema, m.MsgID, b.Event.Code)
		}
		out = append(out, b)
	}
	return out
}

// syslogControls decodes the messages with MSGID msgID in arrival order.
func syslogControls(t *testing.T, msgs []syslogsink.Message, msgID string) []syslogControlBody {
	t.Helper()
	var out []syslogControlBody
	for _, m := range msgs {
		if m.MsgID != msgID {
			continue
		}
		var b syslogControlBody
		if err := json.Unmarshal(m.Body, &b); err != nil || b.Schema != "paddock.notification.v1" {
			t.Fatalf("syslog %s body %q: %v", msgID, m.Body, err)
		}
		out = append(out, b)
	}
	return out
}

// forwardNumbers is the destination's forward sequence as the sink saw it: every event, and every checkpoint, in
// arrival order.
func forwardNumbers(t *testing.T, msgs []syslogsink.Message) []int64 {
	t.Helper()
	var out []int64
	for _, m := range msgs {
		switch {
		case m.MsgID == "paddock.checkpoint":
			c := syslogControls(t, []syslogsink.Message{m}, m.MsgID)[0]
			out = append(out, c.ForwardSeq.From)
		case !strings.HasPrefix(m.MsgID, "paddock."):
			out = append(out, syslogEvents(t, []syslogsink.Message{m})[0].ForwardSeq)
		}
	}
	return out
}

// requireNoGap fails when a number is skipped. A number that arrives again is allowed: syslog is at-least-once (RR-110).
func requireNoGap(t *testing.T, nums []int64) {
	t.Helper()
	next := int64(1)
	for i, n := range nums {
		switch {
		case n == next:
			next++
		case n < 1 || n > next:
			t.Fatalf("forward sequence %v: number %d at position %d, expected %d or a repeat", nums, n, i, next)
		}
	}
}

// requireNoMalformed fails when the sink saw a frame or header that is not RFC 5424 with octet counting.
func requireNoMalformed(t *testing.T, s *syslogsink.Sink) {
	t.Helper()
	if bad := s.Malformed(); len(bad) > 0 {
		t.Fatalf("the sink received malformed syslog: %v", bad)
	}
}

// syslogDestination creates the destination and waits for its start at the newest event.
func syslogDestination(t *testing.T, u stepper, body map[string]any) (notificationDestination, string) {
	t.Helper()
	d, _ := createDestination(t, u, orgDestinations, body)
	path := orgDestinations + "/" + d.ID
	waitStarted(t, u.Portal, path)
	return d, path
}

// TestNotificationsSyslog is gate S1 (plan M12 §9): a TLS syslog destination receives one RFC 5424 message per event
// with a contiguous forward sequence, the audit code as MSGID and parseable JSON; a test message and an idle
// heartbeat arrive; a stopped sink stalls the destination, a restarted one is caught up without a gap; the CA PEM
// option makes the sink's self-signed certificate verify and its absence is a tls error.
//
// The refusal of a private address needs the production outbound policy; the development stack admits private
// addresses for the sinks (PADDOCK_OUTBOUND_DEV_ALLOW_PRIVATE), so it is covered by the unit tests of notifier.Syslog
// and outbound.ValidateDestination.
func TestNotificationsSyslog(t *testing.T) {
	admin := adminUser(t, "s1")
	as := adminStepper(admin)
	org := orgOf(t, admin.Portal)
	d := activeDevice(t, admin.Portal, "", "s1-"+uniqueSuffix())
	s := syslogsink.Start(t)
	dest, path := syslogDestination(t, as, syslogDestinationBody(destinationName("s1"), s, true, false, 60))

	t.Run("events carry the code as MSGID and a contiguous sequence", func(t *testing.T) {
		sendSudoersEvent(t, d, 1, "s1-a")
		sendSudoersEvent(t, d, 2, "s1-b")
		sendSudoersEvent(t, d, 3, "s1-c")
		got := s.Wait(t, deliveryTimeout, "three events", func(m []syslogsink.Message) bool { return len(syslogEvents(t, m)) >= 3 })
		events := syslogEvents(t, got)
		for i, ev := range events {
			if ev.ForwardSeq != int64(i+1) || ev.Event.Code != tamperCode || ev.Event.OrganizationID != org.String() ||
				ev.Event.Target == nil || ev.Event.Target.ID != d.DeviceID || ev.DeliveryID == "" || ev.CommitSeq <= 0 {
				t.Fatalf("event %d: %+v", i+1, ev)
			}
		}
		requireNoMalformed(t, s)
		delivered := expectOneIndexEvent(t, auditIndex(t), org, "code = 'notification.delivered' AND target->>'id' = $1", dest.ID,
			"notification.delivered", "success", time.Minute)
		if delivered.Params["kind"] != "events" {
			t.Fatalf("delivered params %v", delivered.Params)
		}
	})

	t.Run("test message", func(t *testing.T) {
		admin.stepUp(t)
		expectStatus(t, call(t, admin.Portal, http.MethodPost, path+"/test", nil), http.StatusAccepted, "")
		st := waitDestinationState(t, admin.Portal, path, deliveryTimeout, "the test result",
			func(d destinationState) bool { return d.State.LastTest != nil })
		if !st.State.LastTest.OK {
			t.Fatalf("test result %+v", st.State.LastTest)
		}
		tests := syslogControls(t, s.Wait(t, deliveryTimeout, "the test message", func(m []syslogsink.Message) bool {
			return len(syslogControls(t, m, "paddock.test")) > 0
		}), "paddock.test")
		if tests[0].Kind != "test" || tests[0].DestinationID != dest.ID {
			t.Fatalf("test message %+v", tests[0])
		}
	})

	t.Run("a stopped sink stalls the destination and the restart catches up", func(t *testing.T) {
		cursor := waitDestinationState(t, admin.Portal, path, time.Minute, "an idle destination",
			func(d destinationState) bool { return d.State.Status == "active" }).State.Cursor
		s.Stop()
		sendSudoersEvent(t, d, 4, "s1-d")
		sendSudoersEvent(t, d, 5, "s1-e")
		stalled := waitDestinationState(t, admin.Portal, path, 3*time.Minute, "status stalled",
			func(d destinationState) bool { return d.State.Status == "stalled" })
		if stalled.State.Cursor != cursor || stalled.State.LastError == nil ||
			(*stalled.State.LastError != "dial" && *stalled.State.LastError != "timeout") {
			t.Fatalf("stalled state %+v (cursor before %d)", stalled.State, cursor)
		}
		idx := auditIndex(t)
		expectOneIndexEvent(t, idx, org, "code = 'notification.destination_stalled' AND target->>'id' = $1", dest.ID,
			"notification.destination_stalled", "success", time.Minute)

		s.Restart(t)
		waitDestinationState(t, admin.Portal, path, 5*time.Minute, "status active again",
			func(d destinationState) bool { return d.State.Status == "active" && d.State.Cursor > cursor })
		got := s.Wait(t, deliveryTimeout, "events 4 and 5", func(m []syslogsink.Message) bool { return len(syslogEvents(t, m)) >= 5 })
		nums := forwardNumbers(t, got)
		requireNoGap(t, nums)
		if len(nums) < 5 || nums[len(nums)-1] != 5 {
			t.Fatalf("forward sequence %v after the restart, want 1 to 5", nums)
		}
		expectOneIndexEvent(t, idx, org, "code = 'notification.destination_resumed' AND target->>'id' = $1", dest.ID,
			"notification.destination_resumed", "success", time.Minute)
		requireNoMalformed(t, s)
	})

	t.Run("an idle destination sends a heartbeat with the last number", func(t *testing.T) {
		// A heartbeat sent before the stall carries a lower number; only one with last 5 proves the idle destination.
		isFinal := func(b syslogControlBody) bool {
			return b.Kind == "heartbeat" && b.ForwardSeq != nil && b.ForwardSeq.Last != nil && *b.ForwardSeq.Last == 5
		}
		s.Wait(t, 3*time.Minute, "a heartbeat with last 5", func(m []syslogsink.Message) bool {
			for _, b := range syslogControls(t, m, "paddock.heartbeat") {
				if isFinal(b) {
					return true
				}
			}
			return false
		})
	})

	t.Run("without the CA PEM the self-signed certificate is refused", func(t *testing.T) {
		_, bareSink := syslogDestination(t, as, syslogDestinationBody(destinationName("s1b"), s, false, false, 0))
		admin.stepUp(t)
		expectStatus(t, call(t, admin.Portal, http.MethodPost, bareSink+"/test", nil), http.StatusAccepted, "")
		st := waitDestinationState(t, admin.Portal, bareSink, deliveryTimeout, "the test result",
			func(d destinationState) bool { return d.State.LastTest != nil })
		if st.State.LastTest.OK || st.State.LastTest.Error == nil || *st.State.LastTest.Error != "tls" {
			t.Fatalf("test result %+v, want the error tls", st.State.LastTest)
		}
	})
}

// sealedManifestSHA returns the SHA-256 the admin API shows for the sealed day.
func sealedManifestSHA(t *testing.T, u stepper, day string) string {
	t.Helper()
	res := call(t, u.Portal, http.MethodGet, "/api/v1/audit/manifests?sort=-day&page_size=25", nil)
	expectStatus(t, res, http.StatusOK, "")
	var page struct {
		Items []struct {
			Day    string `json:"day"`
			SHA256 string `json:"sha256"`
		} `json:"items"`
	}
	if err := res.JSON(&page); err != nil {
		t.Fatal(err)
	}
	for _, it := range page.Items {
		if it.Day == day {
			return it.SHA256
		}
	}
	t.Fatalf("no manifest of %s: %s", day, res.Body)
	return ""
}

// TestNotificationsCheckpoints is gate S2 (plan M12 §9): after the audit writer sealed the day, a destination with
// checkpoints receives exactly one checkpoint message for it, whose manifest_sha256 is the day's manifest hash and
// whose number continues the forward sequence, and notification.checkpoint_sent is recorded once.
//
// The day is sealed with the development-only `audit seal --day --org`, as in gate A5 (TestAuditChain). A destination
// never receives days sealed before its creation, so the seal comes after the destination exists.
func TestNotificationsCheckpoints(t *testing.T) {
	admin := adminUser(t, "s2")
	as := adminStepper(admin)
	org := orgOf(t, admin.Portal)
	d := activeDevice(t, admin.Portal, "", "s2-"+uniqueSuffix())
	s := syslogsink.Start(t)
	dest, _ := syslogDestination(t, as, syslogDestinationBody(destinationName("s2"), s, true, true, 0))

	sendSudoersEvent(t, d, 1, "s2-a")
	s.Wait(t, deliveryTimeout, "the tamper event", func(m []syslogsink.Message) bool { return len(syslogEvents(t, m)) >= 1 })

	today := time.Now().UTC().Format(time.DateOnly)
	if code, out, err := stack.PaddockServer(testContext(t, 2*time.Minute), "audit", "seal", "--day", today, "--org", org.String()); err != nil || code != 0 {
		t.Fatalf("audit seal: exit %d, %v\n%s", code, err, out)
	}
	want := sealedManifestSHA(t, as, today)

	checkpointsOf := func(m []syslogsink.Message) []syslogControlBody {
		var out []syslogControlBody
		for _, c := range syslogControls(t, m, "paddock.checkpoint") {
			if c.Day == today {
				out = append(out, c)
			}
		}
		return out
	}
	got := s.Wait(t, 3*time.Minute, "the checkpoint of "+today, func(m []syslogsink.Message) bool { return len(checkpointsOf(m)) > 0 })
	cp := checkpointsOf(got)[0]
	if cp.Kind != "checkpoint" || cp.DestinationID != dest.ID || cp.ManifestSHA256 != want || cp.EventCount < 1 ||
		cp.Signature == "" || cp.KeyVersion < 1 || cp.ForwardSeq == nil || cp.ForwardSeq.From != cp.ForwardSeq.To {
		t.Fatalf("checkpoint %+v, want manifest_sha256 %s", cp, want)
	}
	requireNoGap(t, forwardNumbers(t, got))

	// Each further event arriving proves a later notifier round of this destination; none may send the day again.
	sendSudoersEvent(t, d, 2, "s2-b")
	s.Wait(t, deliveryTimeout, "a second tamper event", func(m []syslogsink.Message) bool { return len(syslogEvents(t, m)) >= 2 })
	sendSudoersEvent(t, d, 3, "s2-c")
	s.Wait(t, deliveryTimeout, "a third tamper event", func(m []syslogsink.Message) bool { return len(syslogEvents(t, m)) >= 3 })
	if n := len(checkpointsOf(s.Messages())); n != 1 {
		t.Fatalf("%d checkpoints of %s, want 1", n, today)
	}
	sent := expectOneIndexEvent(t, auditIndex(t), org, "code = 'notification.checkpoint_sent' AND target->>'id' = $1", dest.ID,
		"notification.checkpoint_sent", "success", time.Minute)
	if sent.Params["day"] != today || sent.Params["forward_seq"] != float64(cp.ForwardSeq.From) {
		t.Fatalf("checkpoint_sent params %v", sent.Params)
	}
	requireNoMalformed(t, s)
}

// TestNotificationsReplay is gate S3 (plan M12 §9): a replay from N sends the stored batches from N on again with
// their original delivery IDs and numbers, new events continue after them, a replay while the destination retries a
// batch is 409, and the request and every replayed batch are audited.
func TestNotificationsReplay(t *testing.T) {
	admin := adminUser(t, "s3")
	as := adminStepper(admin)
	org := orgOf(t, admin.Portal)
	d := activeDevice(t, admin.Portal, "", "s3-"+uniqueSuffix())
	s := syslogsink.Start(t)
	dest, path := syslogDestination(t, as, syslogDestinationBody(destinationName("s3"), s, true, false, 0))
	idx := auditIndex(t)

	// One event per batch: each is delivered before the next is recorded.
	for i := 1; i <= 3; i++ {
		sendSudoersEvent(t, d, int64(i), "s3-"+strconv.Itoa(i))
		s.Wait(t, deliveryTimeout, "event "+strconv.Itoa(i), func(m []syslogsink.Message) bool { return len(syslogEvents(t, m)) >= i })
	}
	original := syslogEvents(t, s.Messages())
	if len(original) != 3 || original[1].DeliveryID == original[2].DeliveryID {
		t.Fatalf("original events %+v", original)
	}

	t.Run("out of range", func(t *testing.T) {
		for _, from := range []int64{0, 4} {
			admin.stepUp(t)
			res := call(t, admin.Portal, http.MethodPost, path+"/replay", map[string]any{"from_forward_seq": from})
			expectStatus(t, res, http.StatusBadRequest, "invalid_request")
		}
	})

	t.Run("replay from 2 sends the batches again", func(t *testing.T) {
		admin.stepUp(t)
		res := call(t, admin.Portal, http.MethodPost, path+"/replay", map[string]any{"from_forward_seq": 2})
		expectStatus(t, res, http.StatusAccepted, "")
		requested := expectOneEvent(t, admin.Portal, res.RequestID, "notification.replay_requested", "success")
		if requested.Params["from_forward_seq"] != float64(2) || requested.Params["to_forward_seq"] != float64(3) || !requested.Actor.StepUp {
			t.Fatalf("replay_requested params %v step-up %t", requested.Params, requested.Actor.StepUp)
		}
		got := s.Wait(t, deliveryTimeout, "the replay", func(m []syslogsink.Message) bool { return len(syslogEvents(t, m)) >= 5 })
		events := syslogEvents(t, got)
		for i, want := range []syslogEventBody{original[1], original[2]} {
			again := events[3+i]
			if again.ForwardSeq != want.ForwardSeq || again.DeliveryID != want.DeliveryID || again.Event.EventID != want.Event.EventID {
				t.Fatalf("replayed event %d: %+v, want the original %+v", i, again, want)
			}
		}

		// Events recorded after the replay continue the sequence.
		sendSudoersEvent(t, d, 4, "s3-4")
		got = s.Wait(t, deliveryTimeout, "event 4", func(m []syslogsink.Message) bool { return len(syslogEvents(t, m)) >= 6 })
		if last := syslogEvents(t, got)[5]; last.ForwardSeq != 4 || last.DeliveryID == original[2].DeliveryID {
			t.Fatalf("event after the replay: %+v", last)
		}

		ctx := testContext(t, 2*time.Minute)
		for deadline := time.Now().Add(time.Minute); ; time.Sleep(time.Second) {
			replayed, err := idx.Events(ctx, org, "code = 'notification.replayed' AND target->>'id' = $1", dest.ID)
			if err != nil {
				t.Fatal(err)
			}
			if len(replayed) == 2 {
				ids := map[any]bool{}
				for _, ev := range replayed {
					ids[ev.Params["original_delivery_id"]] = true
					if ev.Outcome != "success" || ev.Params["forward_from"] != ev.Params["forward_to"] {
						t.Fatalf("notification.replayed %+v", ev)
					}
				}
				if !ids[original[1].DeliveryID] || !ids[original[2].DeliveryID] {
					t.Fatalf("replayed deliveries %v, want %s and %s", ids, original[1].DeliveryID, original[2].DeliveryID)
				}
				break
			}
			if len(replayed) > 2 || time.Now().After(deadline) {
				t.Fatalf("%d notification.replayed events, want 2", len(replayed))
			}
		}
	})

	t.Run("a pending retry refuses the replay", func(t *testing.T) {
		s.Stop()
		sendSudoersEvent(t, d, 5, "s3-5")
		waitDestinationState(t, admin.Portal, path, 3*time.Minute, "status stalled",
			func(d destinationState) bool { return d.State.Status == "stalled" })
		admin.stepUp(t)
		res := call(t, admin.Portal, http.MethodPost, path+"/replay", map[string]any{"from_forward_seq": 1})
		expectStatus(t, res, http.StatusConflict, "invalid_state")
		if !strings.Contains(problemDetail(t, res), "retrying a batch") {
			t.Errorf("409 detail %q", problemDetail(t, res))
		}
		expectOneEvent(t, admin.Portal, res.RequestID, "notification.replay_requested", "failure")

		s.Restart(t)
		waitDestinationState(t, admin.Portal, path, 5*time.Minute, "status active again",
			func(d destinationState) bool { return d.State.Status == "active" })
		requireNoGap(t, forwardNumbers(t, s.Messages()))
		requireNoMalformed(t, s)
	})
}
