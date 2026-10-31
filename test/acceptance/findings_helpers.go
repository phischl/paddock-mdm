package acceptance

import (
	"encoding/json"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/pkg/protocol"
	"github.com/phischl/paddock-mdm/test/acceptance/devicesim"
	"github.com/phischl/paddock-mdm/test/acceptance/internal/env"
)

// findingItem is a finding as GET /api/v1/findings returns it.
type findingItem struct {
	ID           string  `json:"id"`
	Kind         string  `json:"kind"`
	Code         string  `json:"code"`
	Subject      string  `json:"subject"`
	DeviceID     string  `json:"device_id"`
	Status       string  `json:"status"`
	Occurrences  int     `json:"occurrences"`
	OpenedAt     string  `json:"opened_at"`
	FirstEventID *string `json:"first_event_id"`
	LastEventID  *string `json:"last_event_id"`
	Reason       *string `json:"reason"`
	ClearedAt    *string `json:"cleared_at"`
	Assignee     *struct {
		ID       string `json:"id"`
		Username string `json:"username"`
	} `json:"assignee"`
}

func listFindings(t *testing.T, p *env.Portal, q url.Values) []findingItem {
	t.Helper()
	q.Set("page_size", "100")
	res := call(t, p, http.MethodGet, "/api/v1/findings?"+q.Encode(), nil)
	expectStatus(t, res, http.StatusOK, "")
	var page struct {
		Items []findingItem `json:"items"`
	}
	if err := res.JSON(&page); err != nil {
		t.Fatal(err)
	}
	return page.Items
}

// waitFindings polls the findings list until want holds: the worker writes findings asynchronously.
func waitFindings(t *testing.T, p *env.Portal, q url.Values, timeout time.Duration, want func([]findingItem) bool) []findingItem {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		got := listFindings(t, p, q)
		if want(got) {
			return got
		}
		if time.Now().After(deadline) {
			t.Fatalf("findings %v: %+v", q, got)
		}
		time.Sleep(time.Second)
	}
}

// sendSudoersEvent reports an unexpected file in /etc/sudoers.d with event number seq.
func sendSudoersEvent(t *testing.T, d *devicesim.Device, seq int64, file string) {
	t.Helper()
	data, _ := json.Marshal(map[string]string{"file": file, "quarantined_as": "/var/lib/paddock/quarantine/" + file})
	res, err := d.SendEvents(testContext(t, time.Minute), []protocol.Event{{EventSeq: seq, Type: protocol.EventTamperSudoersDFile, OccurredAt: time.Now(), Data: data}})
	if err != nil || res.Status != http.StatusAccepted {
		t.Fatalf("events: %v HTTP %d %s", err, res.Status, res.Body)
	}
}

// tamperFindingOf waits for the open tamper finding of a device that counts n events.
func tamperFindingOf(t *testing.T, p *env.Portal, deviceID string, n int) findingItem {
	t.Helper()
	q := url.Values{"device_id": {deviceID}, "kind": {"tamper"}, "status": {"open", "acknowledged", "in_progress"}}
	return waitFindings(t, p, q, time.Minute, func(f []findingItem) bool { return len(f) == 1 && f[0].Occurrences == n })[0]
}

// TestFindingsTamper is gate N8 (tamper part, plan M9 §9): three tamper.sudoers_d_file events of one device and file
// are one open finding with occurrences 3 and the audit event of the third as last_event_id; after the close a new
// event opens a second finding.
