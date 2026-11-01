package acceptance

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/pkg/protocol"
	"github.com/phischl/paddock-mdm/test/acceptance/devicesim"
	"github.com/phischl/paddock-mdm/test/acceptance/internal/env"
)

// sendBundleEvent sends one event of the device as event number seq.
func sendBundleEvent(t *testing.T, d *devicesim.Device, seq int64, typ string, data any) {
	t.Helper()
	raw, err := json.Marshal(data)
	if err != nil {
		t.Fatal(err)
	}
	res, err := d.SendEvents(testContext(t, time.Minute), []protocol.Event{{EventSeq: seq, Type: typ, OccurredAt: time.Now(), Data: raw}})
	if err != nil || res.Status != http.StatusAccepted {
		t.Fatalf("events: %v HTTP %d %s", err, res.Status, res.Body)
	}
}

type resourceStatusItem struct {
	ResourceID string   `json:"resource_id"`
	Type       string   `json:"type"`
	Status     string   `json:"status"`
	Message    string   `json:"message"`
	Changes    []string `json:"changes"`
}

// waitDeviceResources polls the device's resource status until want holds: the worker records the report
// asynchronously.
func waitDeviceResources(t *testing.T, p *env.Portal, deviceID, query string, want func([]resourceStatusItem) bool) []resourceStatusItem {
	t.Helper()
	deadline := time.Now().Add(time.Minute)
	for {
		res := call(t, p, http.MethodGet, "/api/v1/devices/"+deviceID+"/config-status?"+query, nil)
		expectStatus(t, res, http.StatusOK, "")
		var page struct {
			Items []resourceStatusItem `json:"items"`
		}
		if err := res.JSON(&page); err != nil {
			t.Fatal(err)
		}
		if want(page.Items) {
			return page.Items
		}
		if time.Now().After(deadline) {
			t.Fatalf("resource status %s: %+v", query, page.Items)
		}
		time.Sleep(time.Second)
	}
}
