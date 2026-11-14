package app_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/pkg/protocol"
	"github.com/phischl/paddock-mdm/server/internal/ingest"
	"github.com/phischl/paddock-mdm/server/internal/principal"
)

func withdrawEvent(seq int64, user string, entry uuid.UUID) protocol.Event {
	data, _ := json.Marshal(map[string]string{"user": user, "entry_id": entry.String(), "justification": "secret text"})
	return protocol.Event{EventSeq: seq, Type: protocol.EventSoftwareRequestWithdrawn, OccurredAt: time.Now().UTC(), Data: data}
}

// TestSoftwareRequestWithdrawn (PDK-811b): a device's software.request_withdrawn closes the open request of that
// device, entry and user as withdrawn with exactly one device.software_request_withdrawn event (the device as actor),
// also in the batch that opened it; a redelivery records and changes nothing; it never closes an approved request,
// another device's or another organization's, and with no open request or malformed data it only records the event.
// A new request after the withdrawal opens again.
func TestSoftwareRequestWithdrawn(t *testing.T) {
	h := newRequestHarness(t)
	suffix := h.org.String()[24:]
	alice, bob, carol := "alice-"+suffix+"@acme.test", "bob-"+suffix+"@acme.test", "carol-"+suffix+"@acme.test"
	entry := h.entry(t, h.org, "required")
	received := time.Now().UTC().Truncate(time.Second)
	record := func(dev uuid.UUID, org uuid.UUID, events ...protocol.Event) {
		t.Helper()
		if err := h.reports.RecordEvents(systemCtx(org), dev, received, events); err != nil {
			t.Fatal(err)
		}
	}
	state := func(user string) string {
		t.Helper()
		_, s := h.request(t, entry, user)
		return s
	}

	record(h.dev, h.org, requestEvent(1, alice, entry), requestEvent(2, bob, entry))
	// Another device of the organization and a device of another organization cannot close alice's request.
	otherDev := uuid.Must(uuid.NewV7())
	h.exec(t, "INSERT INTO device (id, organization_id, hostname, state) VALUES ($1, $2, $3, 'active')", otherDev, h.org, "ws-o-"+suffix)
	record(otherDev, h.org, withdrawEvent(1, alice, entry))
	otherOrg, foreignDev := h.orgWithDevice(t)
	record(foreignDev, otherOrg, withdrawEvent(1, alice, entry))
	if s := state(alice); s != "requested" {
		t.Fatalf("another device's withdrawal closed the request: %s", s)
	}

	for range 2 {
		record(h.dev, h.org, withdrawEvent(3, alice, entry))
	}
	if s := state(alice); s != "withdrawn" {
		t.Fatalf("alice's request after the withdrawal: %s", s)
	}
	if s := state(bob); s != "requested" {
		t.Fatalf("bob's request changed with alice's withdrawal: %s", s)
	}
	var decided *time.Time
	var decidedBy *string
	id, _ := h.request(t, entry, alice)
	if err := h.super.QueryRow(context.Background(), "SELECT decided_at, decided_by FROM software_request WHERE id = $1", id).
		Scan(&decided, &decidedBy); err != nil {
		t.Fatal(err)
	}
	if decided == nil || !decided.Equal(received) || decidedBy != nil {
		t.Fatalf("decided_at %v, decided_by %v; want the receive time and no administrator", decided, decidedBy)
	}
	if got := h.count(t, `SELECT count(*) FROM action WHERE organization_id = $1 AND code = 'device.software_request_withdrawn'
		AND actor->>'type' = 'device' AND actor->>'id' = $2 AND outcome = 'success'
		AND params->>'user' = $3 AND params->>'entry_id' = $4 AND NOT params ? 'justification'`,
		h.org, h.dev.String(), alice, entry.String()); got != 1 {
		t.Fatalf("device.software_request_withdrawn of the device: %d, want 1 without the justification", got)
	}
	if got := h.count(t, "SELECT count(*) FROM action WHERE organization_id = $1 AND code LIKE 'software_request.%' AND code <> 'software_request.opened'",
		h.org); got != 0 {
		t.Fatalf("the withdrawal recorded %d software_request events besides the device's", got)
	}

	// An approved request stays approved: the user already holds the approval.
	bobID, _ := h.request(t, entry, bob)
	if _, err := h.api.Approve(adminCtx(h.org, principal.RoleOrgAdmin, "a"), bobID, ""); err != nil {
		t.Fatal(err)
	}
	// Without an open request (approved; never asked) and with malformed data the event is recorded and nothing changes.
	malformed := withdrawEvent(6, "Not Valid", entry)
	record(h.dev, h.org, withdrawEvent(4, bob, entry), withdrawEvent(5, carol, entry), malformed)
	if s := state(bob); s != "approved" {
		t.Fatalf("a withdrawal changed an approved request: %s", s)
	}
	if n := h.count(t, "SELECT count(*) FROM software_request WHERE device_id = $1 AND username = $2", h.dev, carol); n != 0 {
		t.Fatalf("a withdrawal without a request created %d", n)
	}

	// Asked and withdrawn in one batch; then asked again: a new open request.
	record(h.dev, h.org, requestEvent(7, carol, entry), withdrawEvent(8, carol, entry))
	if s := state(carol); s != "withdrawn" {
		t.Fatalf("carol's request withdrawn in the same batch: %s", s)
	}
	record(h.dev, h.org, requestEvent(9, alice, entry))
	if s := state(alice); s != "requested" {
		t.Fatalf("alice's new request after the withdrawal: %s", s)
	}
	if got := h.events(t, "device.software_request_withdrawn"); got != 6 {
		t.Fatalf("device.software_request_withdrawn in the organization: %d, want one per event of its devices", got)
	}
}

// TestSoftwareRequestWithdrawalOrder (PDK-811d, plan M19 D8): the request and the withdrawal of one device, entry and
// user end as the device sent them, whatever order their batches are processed in. A withdrawal processed before its
// request keeps the request from opening; with request A, withdrawal W and request B sent in that order, every
// processing order leaves one open request (B's), and with A and W alone none. The event's closed param says whether
// the withdrawal closed a request.
func TestSoftwareRequestWithdrawalOrder(t *testing.T) {
	h := newRequestHarness(t)
	suffix := h.org.String()[24:]
	received := time.Now().UTC().Truncate(time.Second)
	record := func(events ...protocol.Event) {
		t.Helper()
		if err := h.reports.RecordEvents(systemCtx(h.org), h.dev, received, events); err != nil {
			t.Fatal(err)
		}
	}
	open := func(entry uuid.UUID, user string) int {
		t.Helper()
		return h.count(t, `SELECT count(*) FROM software_request WHERE device_id = $1 AND catalog_entry_id = $2
			AND username = $3 AND state = 'requested'`, h.dev, entry, user)
	}
	closed := func(entry uuid.UUID, user string, seq int64) string {
		t.Helper()
		var v *bool
		if err := h.super.QueryRow(context.Background(), `SELECT (params->>'closed')::boolean FROM action
			WHERE organization_id = $1 AND code = 'device.software_request_withdrawn' AND params->>'user' = $2
			AND params->>'entry_id' = $3 AND (params->>'event_seq')::bigint = $4`, h.org, user, entry.String(), seq).
			Scan(&v); err != nil {
			t.Fatalf("withdrawal event %d of %s: %v", seq, user, err)
		}
		if v == nil {
			return "missing"
		}
		if *v {
			return "true"
		}
		return "false"
	}

	t.Run("withdrawal before request", func(t *testing.T) {
		entry, user := h.entry(t, h.org, "required"), "wr-"+suffix+"@acme.test"
		record(withdrawEvent(2, user, entry))
		record(requestEvent(1, user, entry))
		if n := open(entry, user); n != 0 {
			t.Fatalf("a request withdrawn before it was processed opened: %d open", n)
		}
		if n := h.count(t, "SELECT count(*) FROM software_request WHERE device_id = $1 AND catalog_entry_id = $2",
			h.dev, entry); n != 0 {
			t.Fatalf("the withdrawn request was stored: %d rows", n)
		}
		if got := closed(entry, user, 2); got != "false" {
			t.Fatalf("closed of a withdrawal without a request: %s", got)
		}
		// A request sent after the withdrawal opens.
		record(requestEvent(3, user, entry))
		if n := open(entry, user); n != 1 {
			t.Fatalf("a request after the withdrawal: %d open, want 1", n)
		}
	})

	// The device sent A (1), W (2), B (3); B is pending on the device.
	orders := map[string][]int{
		"A W B": {0, 1, 2}, "A B W": {0, 2, 1}, "B A W": {2, 0, 1}, "B W A": {2, 1, 0}, "W A B": {1, 0, 2}, "W B A": {1, 2, 0},
	}
	seq := int64(10)
	for name, order := range orders {
		t.Run(name, func(t *testing.T) {
			entry, user := h.entry(t, h.org, "required"), "awb-"+strings.ToLower(strings.ReplaceAll(name, " ", ""))+"-"+suffix+"@acme.test"
			events := []protocol.Event{requestEvent(seq, user, entry), withdrawEvent(seq+1, user, entry), requestEvent(seq+2, user, entry)}
			for _, i := range order {
				record(events[i])
			}
			if n := open(entry, user); n != 1 {
				t.Fatalf("open requests after %s: %d, want 1 (the device shows B as pending)", name, n)
			}
			want := "false"
			if name == "A W B" {
				want = "true"
			}
			if got := closed(entry, user, seq+1); got != want {
				t.Fatalf("closed of W after %s: %s, want %s", name, got, want)
			}
		})
		seq += 10
	}

	t.Run("A W in any order", func(t *testing.T) {
		for i, reversed := range []bool{false, true} {
			entry, user := h.entry(t, h.org, "required"), "aw-"+suffix+"@acme.test"
			a, w := requestEvent(int64(100+10*i), user, entry), withdrawEvent(int64(101+10*i), user, entry)
			if reversed {
				record(w)
				record(a)
			} else {
				record(a)
				record(w)
			}
			if n := open(entry, user); n != 0 {
				t.Fatalf("open requests after A and W (reversed %v): %d, want 0", reversed, n)
			}
		}
	})

	// A request opened before the migration has no number (NULL) and any later withdrawal closes it. The withdrawal is
	// recorded on its own (RecordEvent), the path a batch falls back to.
	t.Run("request without number", func(t *testing.T) {
		entry, user := h.entry(t, h.org, "required"), "legacy-"+suffix+"@acme.test"
		record(requestEvent(200, user, entry))
		h.exec(t, "UPDATE software_request SET reported_seq = NULL WHERE device_id = $1 AND catalog_entry_id = $2", h.dev, entry)
		if fresh, err := h.reports.RecordEvent(systemCtx(h.org), h.dev, withdrawEvent(201, user, entry)); err != nil || !fresh {
			t.Fatalf("record the withdrawal: %v, %v", fresh, err)
		}
		if n := open(entry, user); n != 0 {
			t.Fatalf("a request without number stayed open after the withdrawal: %d", n)
		}
		if got := closed(entry, user, 201); got != "true" {
			t.Fatalf("closed of the withdrawal: %s", got)
		}
	})
}

// TestSoftwareRequestOrderAfterSeqReset (plan M19 D8.5): after the device's event numbering restarted
// (device.event_seq_reset), the old numbers no longer order its requests and withdrawals: a withdrawal at 50 before the
// reset keeps no request at 3 from opening, and a request open at 40 before it is closed by a withdrawal at 2.
func TestSoftwareRequestOrderAfterSeqReset(t *testing.T) {
	h := newRequestHarness(t)
	suffix := h.org.String()[24:]
	base := time.Now().UTC().Truncate(time.Second).Add(-time.Hour)
	newDevice := func(name string) uuid.UUID {
		dev := uuid.Must(uuid.NewV7())
		h.exec(t, "INSERT INTO device (id, organization_id, hostname, state) VALUES ($1, $2, $3, 'active')", dev, h.org, name+"-"+suffix)
		return dev
	}
	record := func(dev uuid.UUID, at time.Time, events ...protocol.Event) {
		t.Helper()
		if err := h.reports.RecordEvents(systemCtx(h.org), dev, at, events); err != nil {
			t.Fatal(err)
		}
	}
	reset := func(dev uuid.UUID, at time.Time) {
		t.Helper()
		if err := h.reports.RecordStatus(systemCtx(h.org), ingest.Heartbeat{DeviceID: dev, OrganizationID: h.org,
			ReceivedAt: at, Seq: 1, EventSeqHigh: 1, Health: json.RawMessage(`{}`)}); err != nil {
			t.Fatal(err)
		}
		if n := h.count(t, `SELECT count(*) FROM action WHERE organization_id = $1 AND code = 'device.event_seq_reset'
			AND target->>'id' = $2`, h.org, dev.String()); n != 1 {
			t.Fatalf("device.event_seq_reset of the device: %d, want 1", n)
		}
	}
	open := func(dev, entry uuid.UUID, user string) int {
		t.Helper()
		return h.count(t, `SELECT count(*) FROM software_request WHERE device_id = $1 AND catalog_entry_id = $2
			AND username = $3 AND state = 'requested'`, dev, entry, user)
	}

	t.Run("withdrawal before the reset", func(t *testing.T) {
		dev, entry, user := newDevice("ws-w"), h.entry(t, h.org, "required"), "rw-"+suffix+"@acme.test"
		record(dev, base, withdrawEvent(50, user, entry))
		reset(dev, base.Add(time.Minute))
		record(dev, base.Add(2*time.Minute), requestEvent(3, user, entry))
		if n := open(dev, entry, user); n != 1 {
			t.Fatalf("a request after the reset: %d open, want 1", n)
		}
	})

	t.Run("request before the reset", func(t *testing.T) {
		dev, entry, user := newDevice("ws-r"), h.entry(t, h.org, "required"), "rr-"+suffix+"@acme.test"
		record(dev, base, requestEvent(40, user, entry))
		reset(dev, base.Add(time.Minute))
		record(dev, base.Add(2*time.Minute), withdrawEvent(2, user, entry))
		if n := open(dev, entry, user); n != 0 {
			t.Fatalf("a request from before the reset stayed open after the withdrawal: %d", n)
		}
	})
}
