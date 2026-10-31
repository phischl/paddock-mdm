package acceptance

import (
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/test/acceptance/internal/env"
)

// feedEvent and feedPage are the 200 body of GET /api/v1/audit-events/feed.
type feedEvent struct {
	CommitSeq int64 `json:"commit_seq"`
	Event     struct {
		EventID    string    `json:"event_id"`
		RecordedAt time.Time `json:"recorded_at"`
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

// drainFeed reads the feed from the beginning in pages of limit until it is caught up.
func drainFeed(t *testing.T, p *env.Portal, limit int) (events []feedEvent, last feedPage) {
	t.Helper()
	after := int64(0)
	for range 100000 {
		last = getFeed(t, p, after, limit)
		events = append(events, last.Events...)
		if len(last.Events) == 0 {
			return events, last
		}
		after = last.NextAfter
	}
	t.Fatal("the feed does not run dry")
	return nil, last
}

// TestAuditFeed is gates N1 and N2 of plan M9: the feed returns every event of the caller's organization exactly
// once in commit order, and it is closed to other roles and organizations.
func TestAuditFeed(t *testing.T) {
	alice := login(t, env.Alice)
	auditor := tokenPortal(t, createAPIToken(t, alice, env.Alice, "org_auditor").Secret)
	globex := login(t, env.Carol)

	// Produce a few events in both organizations, interleaved.
	for i := range 3 {
		expectStatus(t, call(t, alice, http.MethodGet, "/api/v1/devices", nil), http.StatusOK, "")
		_ = call(t, globex, http.MethodPost, "/api/v1/device-groups", map[string]any{"name": uniqueName(fmt.Sprintf("feed g%d", i))})
		_ = call(t, alice, http.MethodPost, "/api/v1/device-groups", map[string]any{"name": uniqueName(fmt.Sprintf("feed a%d", i))})
	}

	t.Run("exactly once in commit order", func(t *testing.T) {
		var settled feedPage
		deadline := time.Now().Add(auditPollTimeout)
		for {
			if settled = getFeed(t, auditor, 0, 1); settled.Latest >= 3 || time.Now().After(deadline) {
				break
			}
			time.Sleep(time.Second)
		}
		events, last := drainFeed(t, auditor, 7)
		if len(events) == 0 || last.NextAfter != last.Latest || last.Latest < settled.Latest {
			t.Fatalf("%d events, next_after %d, latest %d", len(events), last.NextAfter, last.Latest)
		}
		seen := map[string]bool{}
		for i, e := range events {
			if want := int64(i + 1); e.CommitSeq != want {
				t.Fatalf("event %d has commit_seq %d, want %d (contiguous from 1)", i, e.CommitSeq, want)
			}
			if seen[e.Event.EventID] {
				t.Fatalf("event %s delivered twice", e.Event.EventID)
			}
			seen[e.Event.EventID] = true
			if i > 0 && e.Event.RecordedAt.Before(events[i-1].Event.RecordedAt) {
				t.Fatalf("commit_seq %d was recorded before commit_seq %d", e.CommitSeq, events[i-1].CommitSeq)
			}
		}
		if again := getFeed(t, auditor, last.NextAfter, 100); len(again.Events) != 0 || again.NextAfter != last.NextAfter {
			t.Fatalf("a caught-up feed returned %+v", again)
		}

		other, _ := drainFeed(t, globex, 100)
		for _, e := range other {
			if seen[e.Event.EventID] {
				t.Fatalf("event %s appears in both organizations", e.Event.EventID)
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
