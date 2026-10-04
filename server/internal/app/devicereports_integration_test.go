package app_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/paddock-mdm/paddock/pkg/protocol"
)

// TestLoginStateRecordsTheLatestReport: login.* and sudo.* events are audited and the latest one per area is kept in
// device_status.login_state; an older event delivered late does not overwrite a newer one (plan M3b decision 17).
func TestLoginStateRecordsTheLatestReport(t *testing.T) {
	h := newReleaseHarness(t, true)
	org, device := h.device(t)
	at := time.Date(2026, 10, 4, 8, 0, 0, 0, time.UTC)
	for _, ev := range []protocol.Event{
		{EventSeq: 1, Type: protocol.EventLoginApplyFailed, OccurredAt: at, Data: json.RawMessage(`{"stage":"apt","message":"dpkg lock"}`)},
		{EventSeq: 3, Type: protocol.EventLoginApplied, OccurredAt: at.Add(2 * time.Minute), Data: json.RawMessage(`{"changed":["package","config"]}`)},
		{EventSeq: 2, Type: protocol.EventLoginApplyFailed, OccurredAt: at.Add(time.Minute), Data: json.RawMessage(`{"stage":"restart","message":"late"}`)},
		{EventSeq: 4, Type: protocol.EventSudoUserUnresolved, OccurredAt: at, Data: json.RawMessage(`{"username":"dave@acme.test"}`)},
		{EventSeq: 5, Type: protocol.EventTamperSudoersDFile, OccurredAt: at, Data: json.RawMessage(`{"file":"evil","quarantined_as":"x"}`)},
	} {
		if fresh, err := h.reports.RecordEvent(systemCtx(org), device, ev); err != nil || !fresh {
			t.Fatalf("event %d: fresh %v, %v", ev.EventSeq, fresh, err)
		}
	}
	ctx := context.Background()
	var raw []byte
	if err := h.super.QueryRow(ctx, "SELECT login_state FROM device_status WHERE device_id = $1", device).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var state map[string]struct {
		Type   string         `json:"type"`
		Params map[string]any `json:"params"`
	}
	if err := json.Unmarshal(raw, &state); err != nil {
		t.Fatal(err)
	}
	if len(state) != 2 || state["login"].Type != protocol.EventLoginApplied || state["sudo"].Type != protocol.EventSudoUserUnresolved ||
		state["sudo"].Params["username"] != "dave@acme.test" {
		t.Fatalf("login_state %s", raw)
	}
	var n int
	if err := h.super.QueryRow(ctx, "SELECT count(*) FROM action WHERE organization_id = $1 AND code LIKE 'device.%'", org).Scan(&n); err != nil || n != 5 {
		t.Fatalf("%d audit events (%v), want 5", n, err)
	}
}
