package app_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/pkg/protocol"
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
