package app_test

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/pkg/protocol"
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

// TestLocalAdminRotatedActivatesTheGeneration (plan M4a decision 18): local_admin.rotated makes the generation
// active and every older stored or active one superseded, once; a later rotation_failed is the device's last
// rotation error, and no event carries more than its documented fields.
func TestLocalAdminRotatedActivatesTheGeneration(t *testing.T) {
	h := newReleaseHarness(t, true)
	org, device := h.device(t)
	ctx := context.Background()
	for g, status := range map[int]string{1: "active", 2: "stored", 3: "stored"} {
		if _, err := h.super.Exec(ctx, `INSERT INTO escrow_secret (id, organization_id, device_id, kind, generation, status, ciphertext, key_version)
			VALUES (gen_random_uuid(), $1, $2, 'admin_password', $3, $4, '\x01', 1)`, org, device, g, status); err != nil {
			t.Fatal(err)
		}
	}
	at := time.Now().UTC().Truncate(time.Second)
	for _, ev := range []protocol.Event{
		{EventSeq: 1, Type: protocol.EventLocalAdminRotated, OccurredAt: at, Data: json.RawMessage(`{"generation":3,"password":"never"}`)},
		{EventSeq: 2, Type: protocol.EventLocalAdminRotationFailed, OccurredAt: at.Add(time.Minute), Data: json.RawMessage(`{"generation":4,"reason":"escrow_timeout"}`)},
		{EventSeq: 3, Type: protocol.EventLocalAdminLogin, OccurredAt: at, Data: json.RawMessage(`{"service":"sshd","at":"2026-10-05T08:00:00Z","rhost":"10.0.0.1"}`)},
		{EventSeq: 4, Type: protocol.EventTamperLocalAdminChanged, OccurredAt: at, Data: json.RawMessage(`{"field":"password"}`)},
	} {
		if fresh, err := h.reports.RecordEvent(systemCtx(org), device, ev); err != nil || !fresh {
			t.Fatalf("event %d: fresh %v, %v", ev.EventSeq, fresh, err)
		}
	}
	rows, err := h.super.Query(ctx, "SELECT generation, status, activated_at IS NOT NULL FROM escrow_secret WHERE device_id = $1 ORDER BY generation", device)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for rows.Next() {
		var g int
		var status string
		var activated bool
		_ = rows.Scan(&g, &status, &activated)
		got = append(got, fmt.Sprintf("%d:%s:%v", g, status, activated))
	}
	if strings.Join(got, " ") != "1:superseded:false 2:superseded:false 3:active:true" {
		t.Fatalf("generations %v", got)
	}
	var codes, params string
	if err := h.super.QueryRow(ctx, `SELECT string_agg(code, ' ' ORDER BY code), string_agg(params::text, ' ') FROM action
		WHERE organization_id = $1`, org).Scan(&codes, &params); err != nil {
		t.Fatal(err)
	}
	if codes != "device.tamper_local_admin_changed local_admin.login local_admin.rotated local_admin.rotation_failed" ||
		strings.Contains(params, "never") || strings.Contains(params, "10.0.0.1") || !strings.Contains(params, `"service": "sshd"`) {
		t.Fatalf("codes %s, params %s", codes, params)
	}
	var state string
	if err := h.super.QueryRow(ctx, "SELECT login_state->'local_admin'->>'type' FROM device_status WHERE device_id = $1", device).Scan(&state); err != nil ||
		state != protocol.EventLocalAdminRotationFailed {
		t.Fatalf("last local admin state %q (%v)", state, err)
	}
}
