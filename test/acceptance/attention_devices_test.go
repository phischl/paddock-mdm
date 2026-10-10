package acceptance

import (
	"encoding/json"
	"net/http"
	"net/url"
	"slices"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/test/acceptance/internal/env"
)

type attentionDevice struct {
	DeviceID   string `json:"device_id"`
	Hostname   string `json:"hostname"`
	Severity   string `json:"severity"`
	Since      string `json:"since"`
	Conditions []struct {
		Kind  string `json:"kind"`
		Since string `json:"since"`
	} `json:"conditions"`
}

func attentionDevices(t *testing.T, p *env.Portal, q url.Values) (int, []attentionDevice) {
	t.Helper()
	res := call(t, p, http.MethodGet, "/api/v1/attention/devices?"+q.Encode(), nil)
	expectStatus(t, res, http.StatusOK, "")
	var page struct {
		Items []attentionDevice `json:"items"`
		Total int               `json:"total"`
		Sort  string            `json:"sort"`
	}
	if err := res.JSON(&page); err != nil {
		t.Fatal(err)
	}
	return page.Total, page.Items
}

// TestAttentionDevicesGate (plan M7c step 5, AC8): a device with two open conditions — a disk that is not encrypted
// and a Lock waiting for the agent — appears once on the grouped attention list with both conditions, most severe
// first; the kind filter keeps every condition; the sorts are honoured; the per-condition list stays as it was.
func TestAttentionDevicesGate(t *testing.T) {
	alice := login(t, env.Alice)
	group := namedGroup(t, alice, "attention devices gate")
	d := activeDevice(t, alice, group, "att-gate-"+uniqueSuffix())
	d.Health = json.RawMessage(`{"reconcile":"ok","disk":{"state":"not_encrypted"}}`)
	ctx := testContext(t, time.Minute)
	if _, _, err := d.Checkin(ctx); err != nil {
		t.Fatal(err)
	}
	hostname := getDevice(t, alice, d.DeviceID).Hostname
	stepUp(t, alice, env.Alice, true)
	res := call(t, alice, http.MethodPost, "/api/v1/devices/"+d.DeviceID+"/lock", map[string]any{"confirm_hostname": hostname, "reason": "attention gate"})
	expectStatus(t, res, http.StatusCreated, "")

	var mine attentionDevice
	deadline := time.Now().Add(time.Minute)
	for {
		_, items := attentionDevices(t, alice, url.Values{"q": {hostname}, "page_size": {"10"}})
		matches := 0
		for _, it := range items {
			if it.DeviceID == d.DeviceID {
				mine, matches = it, matches+1
			}
		}
		if matches > 1 {
			t.Fatalf("device listed %d times", matches)
		}
		if matches == 1 && len(mine.Conditions) >= 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("attention of %s: %+v", hostname, items)
		}
		time.Sleep(2 * time.Second)
	}
	kinds := make([]string, len(mine.Conditions))
	for i, c := range mine.Conditions {
		kinds[i] = c.Kind
	}
	if !slices.Contains(kinds, "disk_not_compliant") || !slices.Contains(kinds, "revocation_pending") {
		t.Fatalf("conditions %v, want disk_not_compliant and revocation_pending", kinds)
	}
	// Most severe first: the warning (disk) before the information (the waiting Lock).
	if slices.Index(kinds, "disk_not_compliant") > slices.Index(kinds, "revocation_pending") || mine.Severity != "warn" {
		t.Fatalf("order %v, severity %s", kinds, mine.Severity)
	}
	if mine.Since == "" || mine.Hostname != hostname {
		t.Fatalf("item %+v", mine)
	}

	// The kind filter selects the device by one condition and still lists all of them.
	_, filtered := attentionDevices(t, alice, url.Values{"q": {hostname}, "kind": {"revocation_pending"}})
	if len(filtered) != 1 || len(filtered[0].Conditions) != len(mine.Conditions) {
		t.Fatalf("kind filter: %+v", filtered)
	}
	_, none := attentionDevices(t, alice, url.Values{"q": {hostname}, "kind": {"presumed_lost"}})
	if len(none) != 0 {
		t.Fatalf("kind filter presumed_lost: %+v", none)
	}

	// Sorts: -severity (default) never puts an info device before a critical one; hostname sorts alphabetically.
	_, bySeverity := attentionDevices(t, alice, url.Values{"page_size": {"100"}})
	rank := map[string]int{"info": 0, "warn": 1, "critical": 2}
	for i := 1; i < len(bySeverity); i++ {
		if rank[bySeverity[i].Severity] > rank[bySeverity[i-1].Severity] {
			t.Fatalf("not sorted by -severity at %d: %+v", i, bySeverity)
		}
	}
	// Only this gate's hostnames: they share a prefix and differ in lowercase alphanumerics, where the database
	// collation and byte order agree (other seeded hostnames contain hyphens that the collation weighs differently).
	_, byHost := attentionDevices(t, alice, url.Values{"q": {"att-gate-"}, "sort": {"hostname"}, "page_size": {"100"}})
	hosts := make([]string, len(byHost))
	for i, it := range byHost {
		hosts[i] = it.Hostname
	}
	if !slices.IsSorted(hosts) {
		t.Fatalf("not sorted by hostname: %v", hosts)
	}

	// The per-condition list still has one row per condition of the device.
	flat := listCount(t, alice, "/api/v1/attention", url.Values{"q": {hostname}, "page_size": {"10"}})
	if flat != len(mine.Conditions) {
		t.Fatalf("flat list %d rows, grouped %d conditions", flat, len(mine.Conditions))
	}
}
