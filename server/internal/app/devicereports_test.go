package app

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/paddock-mdm/paddock/pkg/protocol"
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
