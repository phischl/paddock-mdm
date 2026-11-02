package admin

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/adapters/auditpg/auditstore"
)

// TestToAuditFeedEvent: a feed item carries the event's organization and commit_seq, and its JSON has no device.
func TestToAuditFeedEvent(t *testing.T) {
	org, id := uuid.New(), uuid.New()
	got, err := toAuditFeedEvent(auditstore.AuditEvent{
		EventID: id, OrganizationID: org, CommitSeq: 42, OccurredAt: time.Now(), RecordedAt: time.Now(),
		Code: "device.bundle_applied", Outcome: "success", Source: "device", CorrelationID: "c",
		Actor: json.RawMessage(`{"type":"device","id":"d"}`), Target: json.RawMessage(`{"type":"device","id":"d"}`),
		Params: json.RawMessage(`{"device_id":"d"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.CommitSeq != 42 || got.Event.OrganizationId != org || got.Event.EventId != id {
		t.Errorf("feed event %+v, want commit_seq 42 organization %s event %s", got, org, id)
	}
	raw, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	var m struct {
		Event map[string]any `json:"event"`
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	if _, has := m.Event["device"]; has || m.Event["organization_id"] != org.String() {
		t.Errorf("event JSON %v", m.Event)
	}
}
