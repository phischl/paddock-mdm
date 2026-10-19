package acceptance

import (
	"encoding/json"
	"fmt"
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

// TestAttentionAgentNotRunning (PDK-295, plan M8x decisions 60 and 62): fleetd's reported failure of the policy
// paddock_agent_running (inventory_policy_result with alerted_at, as the worker writes it with
// device.tamper_agent_not_running) is listed as agent_not_running; it is gone once the policy passes again, and
// another organization never sees it.
func TestAttentionAgentNotRunning(t *testing.T) {
	alice := login(t, env.Alice)
	d := activeDevice(t, alice, namedGroup(t, alice, "agent not running"), "att-anr-"+uniqueSuffix())
	ctx := testContext(t, time.Minute)
	if _, _, err := d.Checkin(ctx); err != nil {
		t.Fatal(err)
	}
	hostname := getDevice(t, alice, d.DeviceID).Hostname
	db := ownerDB(t)
	if _, err := db.Exec(ctx, `INSERT INTO inventory_policy_result (device_id, organization_id, policy_key, passing, updated_at, alerted_at)
		SELECT id, organization_id, 'paddock_agent_running', false, now(), now() FROM device WHERE id = $1`, d.DeviceID); err != nil {
		t.Fatal(err)
	}
	q := url.Values{"q": {hostname}, "kind": {"agent_not_running"}, "page_size": {"10"}}
	if n := listCount(t, alice, "/api/v1/attention", q); n != 1 {
		t.Fatalf("agent_not_running rows for %s: %d, want 1", hostname, n)
	}
	_, grouped := attentionDevices(t, alice, q)
	var kinds []string
	for _, g := range grouped {
		for _, c := range g.Conditions {
			kinds = append(kinds, c.Kind)
		}
	}
	if len(grouped) != 1 || !slices.Contains(kinds, "agent_not_running") {
		t.Fatalf("grouped attention of %s: %+v", hostname, grouped)
	}
	if n := listCount(t, login(t, env.Carol), "/api/v1/attention", q); n != 0 {
		t.Fatalf("carol sees agent_not_running of the acme device %s", hostname)
	}

	// The policy passes again: UpsertPolicyResult clears alerted_at.
	if _, err := db.Exec(ctx, "UPDATE inventory_policy_result SET passing = true, alerted_at = NULL WHERE device_id = $1", d.DeviceID); err != nil {
		t.Fatal(err)
	}
	if n := listCount(t, alice, "/api/v1/attention", q); n != 0 {
		t.Fatalf("agent_not_running rows for %s after the policy passed: %d", hostname, n)
	}
}

// TestAttentionConfigBehind (PDK-293, plan M8f decisions 23–24): the attention list accepts the kind config_behind and
// lists a device that keeps checking in while it applies an older bundle than its newest one, compiled more than an
// hour ago, with the detail "<applied> < <newest>"; another organization never sees it.
func TestAttentionConfigBehind(t *testing.T) {
	alice := login(t, env.Alice)
	d := activeDevice(t, alice, namedGroup(t, alice, "config behind"), "att-cfg-"+uniqueSuffix())
	ctx := testContext(t, time.Minute)
	if _, _, err := d.Checkin(ctx); err != nil {
		t.Fatal(err)
	}
	hostname := getDevice(t, alice, d.DeviceID).Hostname
	q := url.Values{"q": {hostname}, "kind": {"config_behind"}, "page_size": {"10"}}
	if n := listCount(t, alice, "/api/v1/attention", q); n != 0 {
		t.Fatalf("config_behind rows for %s right after its check-in: %d, want 0", hostname, n)
	}
	// A newest bundle compiled two hours ago that the device, checking in now, has not applied.
	db := ownerDB(t)
	var newest int64
	if err := db.QueryRow(ctx, `INSERT INTO bundle (device_id, version, organization_id, content_sha256, envelope_sha256, object_key, created_at)
		SELECT d.id, coalesce((SELECT max(version) FROM bundle WHERE device_id = d.id), 0) + 1000, d.organization_id, '\x00', '\x00',
		       'acceptance/config-behind', now() - interval '2 hours'
		FROM device d WHERE d.id = $1 RETURNING version`, d.DeviceID).Scan(&newest); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, "UPDATE device_status SET last_contact_at = now(), applied_bundle_version = 0 WHERE device_id = $1", d.DeviceID); err != nil {
		t.Fatal(err)
	}
	res := call(t, alice, http.MethodGet, "/api/v1/attention?"+q.Encode(), nil)
	expectStatus(t, res, http.StatusOK, "")
	var page struct {
		Items []struct {
			Kind   string `json:"kind"`
			Detail string `json:"detail"`
		} `json:"items"`
	}
	if err := res.JSON(&page); err != nil {
		t.Fatal(err)
	}
	if want := fmt.Sprintf("0 < %d", newest); len(page.Items) != 1 || page.Items[0].Kind != "config_behind" || page.Items[0].Detail != want {
		t.Fatalf("config_behind of %s: %+v, want one row with detail %q", hostname, page.Items, want)
	}
	if n := listCount(t, login(t, env.Carol), "/api/v1/attention", q); n != 0 {
		t.Fatalf("carol sees config_behind of the acme device %s", hostname)
	}
}
