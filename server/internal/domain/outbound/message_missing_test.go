package outbound_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
	"github.com/phischl/paddock-mdm/server/internal/domain/outbound"
)

// TestMessageEventMissingJSON: a forwarded event keeps its encoding (no missing or top-level event_id field); a missing
// one encodes as {forward_seq, event_id, missing: true} only (plan M12 decision 21).
func TestMessageEventMissingJSON(t *testing.T) {
	ev := syslogEvent(audit.CodeDeviceTamperSudoersDFile, audit.OutcomeSuccess)
	raw, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	var top map[string]any
	if err := json.Unmarshal(raw, &top); err != nil {
		t.Fatal(err)
	}
	if _, ok := top["missing"]; ok || top["event_id"] != nil || top["forward_seq"] != float64(41) || top["event"] == nil {
		t.Fatalf("event encodes as %s", raw)
	}
	id := uuid.MustParse("0193a1b2-0000-7000-8000-0000000000bb")
	raw, err = json.Marshal(outbound.MessageEvent{ForwardSeq: 3, CommitSeq: 99, EventID: id, Missing: true})
	if err != nil || string(raw) != `{"forward_seq":3,"event_id":"`+id.String()+`","missing":true}` {
		t.Fatalf("missing event encodes as %s (%v)", raw, err)
	}
	m := outbound.Message{Kind: outbound.KindEvents, Events: []outbound.MessageEvent{{ForwardSeq: 3, EventID: id, Missing: true}}}
	if raw, _ := json.Marshal(m); !strings.Contains(string(raw), `"events":[{"forward_seq":3,"event_id"`) {
		t.Fatalf("message encodes as %s", raw)
	}
}
