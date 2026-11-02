package outbound_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/server/internal/domain/outbound"
)

// TestMessageJSON: the envelope shapes of plan M9 §6.4.
func TestMessageJSON(t *testing.T) {
	at := time.Date(2026, 10, 15, 8, 15, 0, 0, time.UTC)
	hb := outbound.Heartbeat(43, 1290)
	hb.DeliveryID, hb.DestinationID, hb.OrganizationID, hb.Organization, hb.SentAt = "d", "x", "o", "acme", at
	assertJSON(t, hb, `{"schema":"paddock.notification.v1","kind":"heartbeat","delivery_id":"d","destination_id":"x",`+
		`"organization_id":"o","organization":"acme","sent_at":"2026-10-15T08:15:00Z","forward_seq":{"last":43},`+
		`"cursor":1290,"events":[]}`)

	test := outbound.Message{Schema: outbound.MessageSchema, Kind: outbound.KindTest, Organization: "platform",
		SentAt: at, Events: []outbound.MessageEvent{}}
	assertJSON(t, test, `{"schema":"paddock.notification.v1","kind":"test","delivery_id":"","destination_id":"",`+
		`"organization_id":"","organization":"platform","sent_at":"2026-10-15T08:15:00Z","events":[]}`)

	cp := outbound.Checkpoint("2026-10-14", 812, "ab", "vault:v1:sig", 1)
	cp.SentAt = at
	assertJSON(t, cp, `{"schema":"paddock.notification.v1","kind":"checkpoint","delivery_id":"","destination_id":"",`+
		`"organization_id":"","organization":"","sent_at":"2026-10-15T08:15:00Z","day":"2026-10-14",`+
		`"event_count":812,"manifest_sha256":"ab","signature":"vault:v1:sig","key_version":1}`)

	ev := outbound.Message{Schema: outbound.MessageSchema, Kind: outbound.KindEvents, SentAt: at,
		ForwardSeq: &outbound.SeqRange{From: 41, To: 41},
		Events: []outbound.MessageEvent{{ForwardSeq: 41, CommitSeq: 1290,
			Links: &outbound.Links{Device: "https://admin.example.org/devices/1/audit"}}}}
	b, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	var back map[string]any
	_ = json.Unmarshal(b, &back)
	events := back["events"].([]any)
	first := events[0].(map[string]any)
	if fs := back["forward_seq"].(map[string]any); fs["from"] != 41.0 || fs["to"] != 41.0 || len(fs) != 2 {
		t.Errorf("forward_seq %v", fs)
	}
	if first["commit_seq"] != 1290.0 || first["links"].(map[string]any)["device"] == nil || first["event"] == nil {
		t.Errorf("event %v", first)
	}
}

func assertJSON(t *testing.T, v any, want string) {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != want {
		t.Errorf("JSON\n got %s\nwant %s", b, want)
	}
}
