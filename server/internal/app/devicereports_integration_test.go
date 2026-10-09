package app_test

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/pkg/protocol"
	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
	"github.com/phischl/paddock-mdm/server/internal/ingest"
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

// TestRootVolumeOnLegacyHeaders (PDK-009 decision 1): headers escrowed without a volume belong to the root volume and
// get its UUID with the first check-in that reports it; headers of other volumes keep theirs, and a check-in without
// volumes changes nothing.
func TestRootVolumeOnLegacyHeaders(t *testing.T) {
	h := newReleaseHarness(t, true)
	org, device := h.device(t)
	ctx := context.Background()
	const root, data = "0d8f4c62-0000-4000-8000-0000000000aa", "0d8f4c62-0000-4000-8000-0000000000bb"
	for g, volume := range map[int]*string{1: nil, 2: nil, 3: ptr(data)} {
		if _, err := h.super.Exec(ctx, `INSERT INTO escrow_secret (id, organization_id, device_id, kind, generation, status, key_version,
			object_key, wrapped_dek, nonce, sha256, size, volume) VALUES (gen_random_uuid(), $1, $2, 'luks_header', $3, 'stored', 1, 'k',
			'\x01', '\x000000000000000000000000', $4, 1, $5)`, org, device, g, strings.Repeat("a", 64), volume); err != nil {
			t.Fatal(err)
		}
	}
	volumes := func() string {
		t.Helper()
		var out string
		if err := h.super.QueryRow(ctx, `SELECT string_agg(coalesce(volume::text, '-'), ',' ORDER BY generation) FROM escrow_secret
			WHERE device_id = $1`, device).Scan(&out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	status := func(seq int64, health string) {
		t.Helper()
		if err := h.reports.RecordStatus(systemCtx(org), ingest.Heartbeat{DeviceID: device, OrganizationID: org, Seq: seq,
			ReceivedAt: time.Now(), Health: json.RawMessage(health)}); err != nil {
			t.Fatal(err)
		}
	}
	status(1, `{"disk":{"state":"compliant","keyslots":2}}`)
	if got := volumes(); got != "-,-,"+data {
		t.Fatalf("without volumes: %s", got)
	}
	status(2, `{"disk":{"state":"compliant","keyslots":2,"volumes":[{"uuid":"`+data+`","device":"/dev/sdb1","keyslots":1,"escrowed":true},`+
		`{"uuid":"`+root+`","device":"/dev/sda3","root":true,"keyslots":2,"escrowed":true}]}}`)
	if got := volumes(); got != root+","+root+","+data {
		t.Fatalf("after the root volume was reported: %s", got)
	}
}

// TestKeyslotChangeRecordsTheVolume (PDK-009 decision 3): device.tamper_keyslot_changed carries the volume.
func TestKeyslotChangeRecordsTheVolume(t *testing.T) {
	h := newReleaseHarness(t, true)
	org, device := h.device(t)
	ev := protocol.Event{EventSeq: 1, Type: protocol.EventTamperKeyslotChanged, OccurredAt: time.Now().UTC(),
		Data: json.RawMessage(`{"volume":"0d8f4c62-0000-4000-8000-0000000000bb","before":["password"],"after":["password","password"]}`)}
	if fresh, err := h.reports.RecordEvent(systemCtx(org), device, ev); err != nil || !fresh {
		t.Fatalf("event: fresh %v, %v", fresh, err)
	}
	var volume string
	if err := h.super.QueryRow(context.Background(), `SELECT params ->> 'volume' FROM action WHERE organization_id = $1
		AND code = 'device.tamper_keyslot_changed'`, org).Scan(&volume); err != nil || volume != "0d8f4c62-0000-4000-8000-0000000000bb" {
		t.Fatalf("audit volume %q: %v", volume, err)
	}
}

func ptr(s string) *string { return &s }

// TestRevokeCapabilitiesKept (PDK-009 review round 1, decision 4): a check-in without revoke_capabilities — the
// device could not ask paddock-revoke — keeps the last reported value; a reported value replaces it.
func TestRevokeCapabilitiesKept(t *testing.T) {
	h := newReleaseHarness(t, true)
	org, device := h.device(t)
	ctx := context.Background()
	caps := func(seq int64, health string) string {
		t.Helper()
		if err := h.reports.RecordStatus(systemCtx(org), ingest.Heartbeat{DeviceID: device, OrganizationID: org, Seq: seq,
			ReceivedAt: time.Now(), Health: json.RawMessage(health)}); err != nil {
			t.Fatal(err)
		}
		var out *string
		if err := h.super.QueryRow(ctx, "SELECT (health -> 'revoke_capabilities')::text FROM device_status WHERE device_id = $1", device).Scan(&out); err != nil {
			t.Fatal(err)
		}
		if out == nil {
			return "absent"
		}
		return *out
	}
	for i, c := range []struct{ health, want string }{
		{`{"reconcile":"ok"}`, "absent"},
		{`{"revoke_capabilities":["volumes"]}`, `["volumes"]`},
		{`{"reconcile":"ok"}`, `["volumes"]`},
		{`{"revoke_capabilities":[]}`, `[]`},
	} {
		if got := caps(int64(i+1), c.health); got != c.want {
			t.Fatalf("check-in %d %s: %s, want %s", i+1, c.health, got, c.want)
		}
	}
}

// TestRecordEventsBatch (N2): the events of one ingest message are recorded in one transaction, each audited exactly
// once; a repeated sequence number in the batch and a redelivered batch record nothing more, and a session login is
// noted without an audit event.
func TestRecordEventsBatch(t *testing.T) {
	h := newReleaseHarness(t, true)
	org, device := h.device(t)
	at := time.Now().UTC().Truncate(time.Second)
	batch := []protocol.Event{
		{EventSeq: 1, Type: protocol.EventLoginApplied, OccurredAt: at, Data: json.RawMessage(`{"changed":["config"]}`)},
		{EventSeq: 2, Type: protocol.EventTamperSudoersDFile, OccurredAt: at, Data: json.RawMessage(`{"file":"evil"}`)},
		{EventSeq: 2, Type: protocol.EventTamperSudoersDFile, OccurredAt: at, Data: json.RawMessage(`{"file":"evil"}`)},
		{EventSeq: 3, Type: protocol.EventSessionLogin, OccurredAt: at, Data: json.RawMessage(`{"username":"Dave@acme.test"}`)},
		{EventSeq: 4, Type: "unknown.type", OccurredAt: at},
	}
	for range 2 {
		if err := h.reports.RecordEvents(systemCtx(org), device, batch); err != nil {
			t.Fatal(err)
		}
	}
	ctx := context.Background()
	var codes string
	if err := h.super.QueryRow(ctx, "SELECT string_agg(code, ' ' ORDER BY code) FROM action WHERE organization_id = $1", org).Scan(&codes); err != nil {
		t.Fatal(err)
	}
	if codes != "device.login_applied device.tamper_sudoers_d_file" {
		t.Fatalf("audit codes %q", codes)
	}
	var seen int
	if err := h.super.QueryRow(ctx, "SELECT count(*) FROM device_user_seen WHERE device_id = $1 AND username = 'dave@acme.test'", device).Scan(&seen); err != nil || seen != 1 {
		t.Fatalf("device_user_seen %d (%v)", seen, err)
	}
}

// TestRecordOnceBatchFallback (N2 review): when the batch transaction fails because of one event (a NUL character,
// which jsonb rejects), every other event is still audited exactly once; the bad one fails alone, also on redelivery,
// and leaves no claimed key behind.
func TestRecordOnceBatchFallback(t *testing.T) {
	h := newReleaseHarness(t, true)
	org, device := h.device(t)
	entry := func(seq int64, reason string) app.OnceEntry {
		return app.OnceEntry{
			Spec: app.ActionSpec{Code: audit.CodeDeviceLoginApplyFailed, Actor: &audit.Actor{Type: audit.ActorDevice, ID: device.String()},
				Target: &audit.Target{Type: "device", ID: device.String()}, Params: map[string]any{"event_seq": seq, "reason": reason}},
			Claim: func(ctx context.Context, q *pgstore.Queries) (bool, error) {
				n, err := q.InsertDeviceEventSeen(ctx, pgstore.InsertDeviceEventSeenParams{DeviceID: device, EventSeq: seq, OrganizationID: org})
				return n == 1, err
			},
		}
	}
	entries := []app.OnceEntry{entry(1, "first"), entry(2, "bad\x00reason"), entry(3, "third")}
	for round, want := range [][]bool{{true, false, true}, {false, false, false}} {
		recorded, err := h.runner.RecordOnceBatch(systemCtx(org), entries)
		if err == nil || !strings.Contains(err.Error(), "entry 1:") || strings.Contains(err.Error(), "entry 0:") || strings.Contains(err.Error(), "entry 2:") {
			t.Fatalf("round %d: error %v, want the failure of entry 1 alone", round, err)
		}
		if fmt.Sprint(recorded) != fmt.Sprint(want) {
			t.Fatalf("round %d: recorded %v, want %v", round, recorded, want)
		}
	}
	ctx := context.Background()
	var seqs string
	if err := h.super.QueryRow(ctx, `SELECT string_agg(params->>'event_seq', ' ' ORDER BY params->>'event_seq') FROM action
		WHERE organization_id = $1 AND code = 'device.login_apply_failed'`, org).Scan(&seqs); err != nil || seqs != "1 3" {
		t.Fatalf("audited event_seq %q (%v), want 1 3", seqs, err)
	}
	var seen int
	if err := h.super.QueryRow(ctx, "SELECT count(*) FROM device_event_seen WHERE device_id = $1", device).Scan(&seen); err != nil || seen != 2 {
		t.Fatalf("%d claimed keys (%v), want 2", seen, err)
	}
}

// TestRecordEventsStripsControls (N2 review): a NUL character in a device-supplied string no longer fails the event;
// it is audited without the control characters, and a session login of a username with control characters is ignored.
func TestRecordEventsStripsControls(t *testing.T) {
	h := newReleaseHarness(t, true)
	org, device := h.device(t)
	at := time.Now().UTC()
	events := []protocol.Event{
		{EventSeq: 1, Type: protocol.EventLoginApplyFailed, OccurredAt: at, Data: json.RawMessage(`{"stage":"apt","message":"dpkg\u0000 lock\u001b"}`)},
		{EventSeq: 2, Type: protocol.EventSessionLogin, OccurredAt: at, Data: json.RawMessage(`{"username":"eve\u0000@acme.test"}`)},
	}
	if err := h.reports.RecordEvents(systemCtx(org), device, events); err != nil {
		t.Fatal(err)
	}
	var seen int
	if err := h.super.QueryRow(context.Background(), "SELECT count(*) FROM device_user_seen WHERE device_id = $1", device).Scan(&seen); err != nil || seen != 0 {
		t.Fatalf("device_user_seen %d (%v), want 0", seen, err)
	}
	var msg string
	if err := h.super.QueryRow(context.Background(), "SELECT params->>'message' FROM action WHERE organization_id = $1 AND code = 'device.login_apply_failed'",
		org).Scan(&msg); err != nil || msg != "dpkg lock" {
		t.Fatalf("message %q (%v)", msg, err)
	}
}
