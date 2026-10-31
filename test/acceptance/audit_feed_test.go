package acceptance

import (
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/pkg/protocol"
	"github.com/phischl/paddock-mdm/test/acceptance/internal/env"
)

// feedEvent and feedPage are the 200 body of GET /api/v1/audit-events/feed.
type feedEvent struct {
	CommitSeq int64 `json:"commit_seq"`
	Event     struct {
		EventID    string    `json:"event_id"`
		OrgID      string    `json:"organization_id"`
		Code       string    `json:"code"`
		OccurredAt time.Time `json:"occurred_at"`
		RecordedAt time.Time `json:"recorded_at"`
		Target     *struct {
			ID string `json:"id"`
		} `json:"target"`
		Params map[string]any `json:"params"`
	} `json:"event"`
}

type feedPage struct {
	Schema    string      `json:"schema"`
	Events    []feedEvent `json:"events"`
	NextAfter int64       `json:"next_after"`
	Latest    int64       `json:"latest"`
}

func getFeed(t *testing.T, p *env.Portal, after int64, limit int) feedPage {
	t.Helper()
	res := call(t, p, http.MethodGet, fmt.Sprintf("/api/v1/audit-events/feed?after=%d&limit=%d", after, limit), nil)
	expectStatus(t, res, http.StatusOK, "")
	var page feedPage
	if err := res.JSON(&page); err != nil {
		t.Fatal(err)
	}
	if page.Schema != "paddock.audit.feed.v1" {
		t.Fatalf("schema %q", page.Schema)
	}
	return page
}

// drainFeed reads the feed from the beginning in pages of limit until it is caught up. Feed reads the page and
// latest in two statements, so an empty page with next_after below latest means a commit landed in between: the
// page is read again (bounded) instead of ending the drain early.
func drainFeed(t *testing.T, p *env.Portal, limit int) (events []feedEvent, last feedPage) {
	t.Helper()
	after := int64(0)
	stale := 0
	for range 100000 {
		last = getFeed(t, p, after, limit)
		events = append(events, last.Events...)
		after = last.NextAfter
		if len(last.Events) > 0 {
			stale = 0
			continue
		}
		if last.NextAfter >= last.Latest {
			return events, last
		}
		if stale++; stale > 20 {
			t.Fatalf("the feed stays empty below latest: next_after %d, latest %d", last.NextAfter, last.Latest)
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatal("the feed does not run dry")
	return nil, last
}

// feedCreateGroup creates a device group as p and returns its id, the target id of the group-created event.
func feedCreateGroup(t *testing.T, p *env.Portal, name string) string {
	t.Helper()
	res := call(t, p, http.MethodPost, "/api/v1/device-groups", map[string]any{"name": name})
	expectStatus(t, res, http.StatusCreated, "")
	var g struct {
		ID string `json:"id"`
	}
	if err := res.JSON(&g); err != nil || g.ID == "" {
		t.Fatalf("group: %v %s", err, res.Body)
	}
	return g.ID
}

// targetEvents returns the events of the feed whose target is id, waiting until at least n are there.
func targetEvents(t *testing.T, p *env.Portal, id string, n int) []feedEvent {
	t.Helper()
	deadline := time.Now().Add(auditPollTimeout)
	for {
		events, _ := drainFeed(t, p, 100)
		var out []feedEvent
		for _, e := range events {
			if e.Event.Target != nil && e.Event.Target.ID == id {
				out = append(out, e)
			}
		}
		if len(out) >= n {
			return out
		}
		if time.Now().After(deadline) {
			t.Fatalf("feed has %d events for target %s, want %d", len(out), id, n)
		}
		time.Sleep(time.Second)
	}
}

// waitTargetEvent polls the feed until an event for target id satisfies match and returns all events of that
// target. Keying the wait on the event itself, not on a count, keeps unrelated events of the target (enrollment, the
// first bundle) from satisfying it early.
func waitTargetEvent(t *testing.T, p *env.Portal, id string, match func(feedEvent) bool) []feedEvent {
	t.Helper()
	deadline := time.Now().Add(auditPollTimeout)
	for {
		events, _ := drainFeed(t, p, 100)
		var out []feedEvent
		found := false
		for _, e := range events {
			if e.Event.Target != nil && e.Event.Target.ID == id {
				out = append(out, e)
				found = found || match(e)
			}
		}
		if found {
			return out
		}
		if time.Now().After(deadline) {
			t.Fatalf("no matching event for target %s in the feed: %+v", id, out)
		}
		time.Sleep(time.Second)
	}
}

// TestAuditFeed is gates N1 and N2 of plan M9: the feed returns every event of the caller's organization exactly
// once in commit order, and it is closed to other roles and organizations.
func TestAuditFeed(t *testing.T) {
	alice := login(t, env.Alice)
	auditor := tokenPortal(t, createAPIToken(t, alice, env.Alice, "org_auditor").Secret)
	globex := login(t, env.Carol)

	// Interleave group creations of both organizations; their events are this test's own.
	var acmeGroups, globexGroups []string
	for i := range 3 {
		globexGroups = append(globexGroups, feedCreateGroup(t, globex, uniqueName(fmt.Sprintf("feed g%d", i))))
		acmeGroups = append(acmeGroups, feedCreateGroup(t, alice, uniqueName(fmt.Sprintf("feed a%d", i))))
	}

	t.Run("exactly once in commit order", func(t *testing.T) {
		for _, id := range acmeGroups {
			targetEvents(t, auditor, id, 1)
		}
		for _, id := range globexGroups {
			targetEvents(t, globex, id, 1)
		}
		events, last := drainFeed(t, auditor, 7)
		if len(events) == 0 || last.NextAfter != last.Latest {
			t.Fatalf("%d events, next_after %d, latest %d", len(events), last.NextAfter, last.Latest)
		}
		acmeID := orgOf(t, alice).String()
		seen := map[string]bool{}
		targets := map[string]int{}
		for i, e := range events {
			if want := int64(i + 1); e.CommitSeq != want {
				t.Fatalf("event %d has commit_seq %d, want %d (contiguous from 1)", i, e.CommitSeq, want)
			}
			if seen[e.Event.EventID] {
				t.Fatalf("event %s delivered twice", e.Event.EventID)
			}
			seen[e.Event.EventID] = true
			if e.Event.OrgID != acmeID {
				t.Fatalf("event %s belongs to organization %q, the token's is %s", e.Event.EventID, e.Event.OrgID, acmeID)
			}
			if e.Event.Target != nil && e.Event.Code == "device_group.created" {
				targets[e.Event.Target.ID]++
			}
			if i > 0 && e.Event.RecordedAt.Before(events[i-1].Event.RecordedAt) {
				t.Fatalf("commit_seq %d was recorded before commit_seq %d", e.CommitSeq, events[i-1].CommitSeq)
			}
		}
		for _, id := range acmeGroups {
			if targets[id] != 1 {
				t.Errorf("acme group %s has %d created events in the feed, want 1", id, targets[id])
			}
		}
		for _, id := range globexGroups {
			if targets[id] != 0 {
				t.Errorf("globex group %s appears in the acme feed", id)
			}
		}
		if again := getFeed(t, auditor, last.NextAfter, 100); len(again.Events) != 0 || again.NextAfter != last.NextAfter {
			t.Fatalf("a caught-up feed returned %+v", again)
		}

		other, _ := drainFeed(t, globex, 100)
		globexID := orgOf(t, globex).String()
		for _, e := range other {
			if e.Event.OrgID != globexID {
				t.Fatalf("event %s in the globex feed belongs to organization %q, want %s", e.Event.EventID, e.Event.OrgID, globexID)
			}
			if seen[e.Event.EventID] {
				t.Fatalf("event %s appears in both organizations", e.Event.EventID)
			}
		}
		count := 0
		for _, e := range other {
			if e.Event.Target != nil && slices.Contains(globexGroups, e.Event.Target.ID) && e.Event.Code == "device_group.created" {
				count++
			}
		}
		if count != len(globexGroups) {
			t.Errorf("globex feed has %d of its %d created events", count, len(globexGroups))
		}
	})

	t.Run("a late device event gets the highest commit_seq", func(t *testing.T) {
		d := activeDevice(t, alice, "", "feed-late-"+uniqueSuffix())
		ctx := testContext(t, time.Minute)
		send := func(seq int64, at time.Time) {
			if res, err := d.SendEvents(ctx, []protocol.Event{{EventSeq: seq, Type: protocol.EventBundleApplied, OccurredAt: at, Data: json.RawMessage(`{"version":1}`)}}); err != nil || res.Status != http.StatusAccepted {
				t.Fatalf("events: %v HTTP %d %s", err, res.Status, res.Body)
			}
		}
		// The audit event's occurred_at is the server's record time; the device's own time is the occurred_at param.
		deviceSeq := func(e feedEvent) float64 { n, _ := e.Event.Params["event_seq"].(float64); return n }
		deviceTime := func(t *testing.T, e feedEvent) time.Time {
			t.Helper()
			raw, _ := e.Event.Params["occurred_at"].(string)
			at, err := time.Parse(time.RFC3339Nano, raw)
			if err != nil {
				t.Fatalf("event %s has no device occurred_at: %v", e.Event.EventID, err)
			}
			return at
		}
		seq := func(n float64) func(feedEvent) bool {
			return func(e feedEvent) bool { return e.Event.Code == "device.bundle_applied" && deviceSeq(e) == n }
		}
		newer := time.Now()
		late := newer.Add(-3 * time.Hour)
		send(1, newer)
		waitTargetEvent(t, auditor, d.DeviceID, seq(1))
		send(2, late)
		events := waitTargetEvent(t, auditor, d.DeviceID, seq(2))
		var lateEvent *feedEvent
		for i, e := range events {
			if seq(2)(e) {
				lateEvent = &events[i]
			}
		}
		if got := deviceTime(t, *lateEvent); got.Sub(late).Abs() > time.Second {
			t.Fatalf("the late event carries device time %s, want %s", got, late)
		}
		for _, e := range events {
			if e.CommitSeq > lateEvent.CommitSeq {
				t.Errorf("event %s (commit_seq %d) is after the late event (commit_seq %d) although it was sent before", e.Event.EventID, e.CommitSeq, lateEvent.CommitSeq)
			}
			if seq(1)(e) && !deviceTime(t, e).After(deviceTime(t, *lateEvent)) {
				t.Errorf("event %s did not occur after the late event, which is meant to be the oldest", e.Event.EventID)
			}
		}
	})

	t.Run("events carry no device and the stored fields", func(t *testing.T) {
		res := call(t, auditor, http.MethodGet, "/api/v1/audit-events/feed?after=0&limit=5", nil)
		expectStatus(t, res, http.StatusOK, "")
		var raw struct {
			Events []map[string]any `json:"events"`
		}
		if err := res.JSON(&raw); err != nil || len(raw.Events) == 0 {
			t.Fatalf("%v %s", err, res.Body)
		}
		for _, e := range raw.Events {
			ev, ok := e["event"].(map[string]any)
			if !ok || e["commit_seq"] == nil {
				t.Fatalf("event %v", e)
			}
			if _, has := ev["device"]; has {
				t.Errorf("feed event has a device property: %v", ev)
			}
		}
	})

	t.Run("invalid parameters", func(t *testing.T) {
		for _, q := range []string{"after=0&limit=1001", "after=0&limit=0", "after=-1&limit=10"} {
			expectStatus(t, call(t, auditor, http.MethodGet, "/api/v1/audit-events/feed?"+q, nil), http.StatusBadRequest, "invalid_request")
		}
	})

	t.Run("roles", func(t *testing.T) {
		operator := mfaTempUser(t, "feed-operator", env.RoleGroup("acme", "operators"))
		expectStatus(t, call(t, operator.Portal, http.MethodGet, "/api/v1/audit-events/feed?after=0&limit=1", nil), http.StatusForbidden, "forbidden")
		anonymous, err := env.NewHTTPClient()
		if err != nil {
			t.Fatal(err)
		}
		res := call(t, &env.Portal{User: "anonymous", Client: anonymous}, http.MethodGet, "/api/v1/audit-events/feed?after=0&limit=1", nil)
		expectStatus(t, res, http.StatusUnauthorized, "")
		expectStatus(t, call(t, alice, http.MethodGet, "/api/v1/audit-events/feed?after=0&limit=1", nil), http.StatusOK, "")
	})
}
