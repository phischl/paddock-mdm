package app

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/pkg/protocol"
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
		{"sudoers changed", `{"sha256_before":"aa","sha256_after":"bb"}`, map[string]any{"sha256_before": "aa", "sha256_after": "bb"}},
		{"keyslot changed", `{"before":["recovery","tpm2+pin"],"after":["password","recovery","tpm2+pin",1]}`,
			map[string]any{"before": []string{"recovery", "tpm2+pin"}, "after": []string{"password", "recovery", "tpm2+pin"}}},
		{"oversized strings", `{"reason":"` + long + `","version":"` + long + `"}`, map[string]any{}},
		{"not an object", `[1]`, map[string]any{}},
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
