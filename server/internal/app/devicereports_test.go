package app

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/pkg/protocol"
	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
)

func TestEventParams(t *testing.T) {
	at := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	long := strings.Repeat("x", maxParamString+1)
	tests := []struct {
		name string
		data string
		want map[string]any
	}{
		{"bundle applied", `{"version":7,"changed":2,"errors":[{"id":"file:/etc/a","message":"left_modified_file"},{"id":"x"}],"secret":"no"}`,
			map[string]any{"bundle_version": int64(7), "changed": int64(2), "errors": []map[string]string{{"id": "file:/etc/a", "message": "left_modified_file"}}}},
		{"agent update", `{"version":"1.2.0","from_version":"1.1.0","outcome":"rolled_back"}`,
			map[string]any{"version": "1.2.0", "from_version": "1.1.0", "outcome": "rolled_back"}},
		{"drift", `{"resource_ids":["file:/etc/a",3,"` + long + `"]}`, map[string]any{"resource_ids": []string{"file:/etc/a"}}},
		{"dropped", `{"count":10,"from_seq":3,"to_seq":12}`, map[string]any{"count": int64(10), "from_seq": int64(3), "to_seq": int64(12)}},
		{"login applied", `{"changed":["package","config",7]}`, map[string]any{"changed": []string{"package", "config"}}},
		{"login apply failed", `{"stage":"apt","message":"dpkg lock"}`, map[string]any{"stage": "apt", "message": "dpkg lock"}},
		{"user lock applied", `{"username":"dave@acme.test","sessions_locked":1,"sessions_terminated":0,"pid":42}`,
			map[string]any{"username": "dave@acme.test", "sessions_locked": int64(1), "sessions_terminated": int64(0)}},
		{"sudo group member", `{"group":"sudo","username":"eve","removed":true}`, map[string]any{"group": "sudo", "username": "eve", "removed": true}},
		{"sudoers.d file", `{"file":"evil","quarantined_as":"/var/lib/paddock/quarantine/sudoers.d/evil.1759600000"}`,
			map[string]any{"file": "evil", "quarantined_as": "/var/lib/paddock/quarantine/sudoers.d/evil.1759600000"}},
		{"watched unit stopped", `{"unit":"wazuh-agent.service","state":"missing"}`, map[string]any{"unit": "wazuh-agent.service", "state": "missing"}},
		{"sudoers changed", `{"sha256_before":"aa","sha256_after":"bb"}`, map[string]any{"sha256_before": "aa", "sha256_after": "bb"}},
		{"keyslot changed", `{"before":["recovery","tpm2+pin"],"after":["password","recovery","tpm2+pin",1]}`,
			map[string]any{"before": []string{"recovery", "tpm2+pin"}, "after": []string{"password", "recovery", "tpm2+pin"}}},
		{"oversized strings", `{"reason":"` + long + `","version":"` + long + `"}`, map[string]any{}},
		{"not an object", `[1]`, map[string]any{}},
		{"control characters", `{"message":"a\u0000b\u001bc\td\ne\rf","resource_ids":["\u0000x"],"errors":[{"id":"i\u0007","message":"m\u0000"}]}`,
			map[string]any{"message": "abc\td\ne\rf", "resource_ids": []string{"x"}, "errors": []map[string]string{{"id": "i", "message": "m"}}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := eventParams(protocol.Event{EventSeq: 5, OccurredAt: at, Data: json.RawMessage(tt.data)})
			tt.want["event_seq"] = int64(5)
			tt.want["occurred_at"] = "2026-10-04T12:00:00Z"
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("got %#v\nwant %#v", got, tt.want)
			}
		})
	}
}

// TestAgentUpdateEventsAreClassifiedByOutcome (ADR 0024): agent.update_failed with outcome rollback_failed is audited as
// device.agent_rollback_failed and counted as rollback_failed; every other update event keeps its code and count.
func TestAgentUpdateEventsAreClassifiedByOutcome(t *testing.T) {
	tests := []struct {
		eventType, outcome string
		code               audit.Code
		counted            string
	}{
		{protocol.EventAgentUpdateFailed, "rollback_failed", audit.CodeDeviceAgentRollbackFailed, "rollback_failed"},
		{protocol.EventAgentUpdateFailed, "self_test_failed", audit.CodeDeviceAgentUpdateFailed, "update_failed"},
		{protocol.EventAgentUpdateFailed, "signature_invalid", audit.CodeDeviceAgentUpdateFailed, "update_failed"},
		{protocol.EventAgentUpdateFailed, "downgrade_refused", audit.CodeDeviceAgentUpdateFailed, ""},
		{protocol.EventAgentRolledBack, "rolled_back", audit.CodeDeviceAgentRolledBack, "rolled_back"},
		{protocol.EventAgentRolledBack, "rollback_failed", audit.CodeDeviceAgentRolledBack, "rolled_back"},
		{protocol.EventAgentUpdated, "updated", audit.CodeDeviceAgentUpdated, "updated"},
	}
	for _, tt := range tests {
		t.Run(tt.eventType+"/"+tt.outcome, func(t *testing.T) {
			data, _ := json.Marshal(map[string]string{"version": "1.1.0", "from_version": "1.0.0", "outcome": tt.outcome})
			entry, ok := eventEntry(uuid.New(), protocol.Event{EventSeq: 1, Type: tt.eventType, OccurredAt: time.Now(), Data: data}, time.Now())
			if !ok || entry.Spec.Code != tt.code {
				t.Fatalf("audit code %q (audited %t), want %q", entry.Spec.Code, ok, tt.code)
			}
			counted, ok := updateOutcome(tt.eventType, entry.Spec.Params)
			if counted != tt.counted || ok != (tt.counted != "") {
				t.Fatalf("counted as %q (%t), want %q", counted, ok, tt.counted)
			}
		})
	}
}

// TestConversionStartedAfterCancel (plan M8e amendment 2026-10-30, PDK-482): disk.conversion_started with after_cancel
// true is audited as device.disk_conversion_completed_after_cancel; without it, or with after_cancel false or not a boolean, it stays device.disk_conversion_started. A failed
// neutralization and a failed reinstall of the unlock path have their own codes.
func TestConversionStartedAfterCancel(t *testing.T) {
	tests := []struct {
		typ, data string
		code      audit.Code
	}{
		{protocol.EventDiskConversionStarted, `{"conversion_id":"c","after_cancel":true}`, audit.CodeDeviceDiskConversionCompletedAfterCancel},
		{protocol.EventDiskConversionStarted, `{"conversion_id":"c","after_cancel":false}`, audit.CodeDeviceDiskConversionStarted},
		{protocol.EventDiskConversionStarted, `{"conversion_id":"c","after_cancel":"true"}`, audit.CodeDeviceDiskConversionStarted},
		{protocol.EventDiskConversionStarted, `{"conversion_id":"c"}`, audit.CodeDeviceDiskConversionStarted},
		{protocol.EventDiskConversionNeutralizeFailed, `{"conversion_id":"c","reason":"boot_space_low"}`, audit.CodeDeviceDiskConversionNeutralizeFailed},
		{protocol.EventDiskConversionUnlockRestoreFailed, `{"conversion_id":"c","reason":"kernel_not_buildable"}`, audit.CodeDeviceDiskConversionUnlockRestoreFailed},
	}
	for _, tt := range tests {
		entry, ok := eventEntry(uuid.New(), protocol.Event{EventSeq: 1, Type: tt.typ, OccurredAt: time.Now(), Data: json.RawMessage(tt.data)}, time.Now())
		if !ok || entry.Spec.Code != tt.code {
			t.Errorf("%s %s: audit code %q (audited %t), want %q", tt.typ, tt.data, entry.Spec.Code, ok, tt.code)
		}
	}
}

// TestDroppedRange (plan M8b decision 19, PDK-108 review 1): only a range below the event's own number counts as
// dropped; the agent numbers agent.events_dropped after the range it lost.
func TestDroppedRange(t *testing.T) {
	tests := []struct {
		name     string
		typ      string
		seq      int64
		params   map[string]any
		from, to int64
		ok       bool
	}{
		{"range below the event", protocol.EventAgentEventsDropped, 7, map[string]any{"from_seq": int64(5), "to_seq": int64(6)}, 5, 6, true},
		{"single number", protocol.EventAgentEventsDropped, 2, map[string]any{"from_seq": int64(1), "to_seq": int64(1)}, 1, 1, true},
		{"range up to the event's own number", protocol.EventAgentEventsDropped, 6, map[string]any{"from_seq": int64(5), "to_seq": int64(6)}, 0, 0, false},
		{"range beyond the event", protocol.EventAgentEventsDropped, 7, map[string]any{"from_seq": int64(5), "to_seq": int64(9_000_000_000_000_000_000)}, 0, 0, false},
		{"reversed", protocol.EventAgentEventsDropped, 9, map[string]any{"from_seq": int64(6), "to_seq": int64(5)}, 0, 0, false},
		{"from below 1", protocol.EventAgentEventsDropped, 9, map[string]any{"from_seq": int64(0), "to_seq": int64(5)}, 0, 0, false},
		{"missing to_seq", protocol.EventAgentEventsDropped, 9, map[string]any{"from_seq": int64(5)}, 0, 0, false},
		{"another type", protocol.EventBundleApplied, 9, map[string]any{"from_seq": int64(5), "to_seq": int64(6)}, 0, 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			from, to, ok := droppedRange(tt.typ, tt.seq, tt.params)
			if ok != tt.ok || (ok && (from != tt.from || to != tt.to)) {
				t.Fatalf("droppedRange = %d %d %v, want %d %d %v", from, to, ok, tt.from, tt.to, tt.ok)
			}
		})
	}
}
