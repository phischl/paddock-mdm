package acceptance

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/test/acceptance/internal/env"
)

// TestSoftwareStatusFromCheckin (PDK-411, plan M13a §3.4): the software a device reports with its check-in shows on the
// device and on the application; a second check-in with the digest only keeps it; an application assigned to a device
// that has reported nothing is unknown, and another organization sees neither.
func TestSoftwareStatusFromCheckin(t *testing.T) {
	alice, carol := login(t, env.Alice), login(t, env.Carol)
	group := namedGroup(t, alice, "software-status")
	reporting := activeDevice(t, alice, group, "sw-report-"+uniqueSuffix())
	silent := activeDevice(t, alice, group, "sw-silent-"+uniqueSuffix())
	res := call(t, alice, http.MethodPost, softwareCatalog, entryBody("sw-status"))
	expectStatus(t, res, http.StatusCreated, "")
	entry := createdID(t, alice, softwareCatalog, res)
	expectStatus(t, call(t, alice, http.MethodPost, softwareAssignments, map[string]any{
		"catalog_entry_id": entry, "device_group_id": group, "intent": "required",
	}), http.StatusCreated, "")
	requireSingleService(t, testContext(t, time.Minute), "paddock-worker")
	ctx := testContext(t, 5*time.Minute)

	report := func(digest string, items ...map[string]any) {
		t.Helper()
		software := map[string]any{"digest": digest}
		if items != nil {
			software["items"] = items
		}
		raw, err := json.Marshal(map[string]any{"reconcile": "ok", "software": software})
		if err != nil {
			t.Fatal(err)
		}
		valkeyCLI(t, "DEL hb:"+reporting.DeviceID)
		reporting.Health = raw
		if _, res, err := reporting.Checkin(ctx); err != nil || res.Status != http.StatusOK {
			t.Fatalf("check-in: %v %d %s", err, res.Status, res.Body)
		}
	}
	type managedItem struct {
		Name, State, Version string
		ReportedAt           *time.Time `json:"reported_at"`
	}
	managed := func(device string, want func([]managedItem) bool) []managedItem {
		t.Helper()
		for deadline := time.Now().Add(time.Minute); ; time.Sleep(time.Second) {
			res := call(t, alice, http.MethodGet, "/api/v1/devices/"+device+"/managed-software", nil)
			expectStatus(t, res, http.StatusOK, "")
			var page struct {
				Items []managedItem `json:"items"`
			}
			if err := res.JSON(&page); err != nil {
				t.Fatal(err)
			}
			if want(page.Items) {
				return page.Items
			}
			if time.Now().After(deadline) {
				t.Fatalf("managed software of %s: %+v", device, page.Items)
			}
		}
	}

	items := managed(silent.DeviceID, func(i []managedItem) bool { return len(i) == 1 })
	if items[0].State != "unknown" && items[0].State != "not_applicable" || items[0].ReportedAt != nil {
		t.Fatalf("a device that reported nothing: %+v", items)
	}

	report("d1", map[string]any{"id": entry, "package": "nano", "intent": "required", "state": "installed", "version": "1.0"})
	items = managed(reporting.DeviceID, func(i []managedItem) bool { return len(i) == 1 && i[0].State == "installed" })
	if items[0].Version != "1.0" || items[0].ReportedAt == nil {
		t.Fatalf("reported item %+v", items[0])
	}
	first := *items[0].ReportedAt

	// A digest alone stores the digest and keeps the row; the check-in is materialized once the digest shows.
	report("d2")
	db := ownerDB(t)
	for deadline := time.Now().Add(30 * time.Second); ; time.Sleep(250 * time.Millisecond) {
		var digest string
		if err := db.QueryRow(ctx, "SELECT software_digest FROM device_status WHERE device_id = $1", reporting.DeviceID).Scan(&digest); err != nil {
			t.Fatal(err)
		}
		if digest == "d2" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("digest %q, want d2", digest)
		}
	}
	items = managed(reporting.DeviceID, func(i []managedItem) bool { return len(i) == 1 })
	if items[0].State != "installed" || !items[0].ReportedAt.Equal(first) {
		t.Fatalf("a digest alone changed the row: %+v", items[0])
	}

	res = call(t, alice, http.MethodGet, softwareCatalog+"/"+entry+"/devices?state=installed", nil)
	expectStatus(t, res, http.StatusOK, "")
	var page struct {
		Total int `json:"total"`
		Items []struct {
			DeviceID string `json:"device_id"`
		} `json:"items"`
	}
	if err := res.JSON(&page); err != nil || page.Total != 1 || page.Items[0].DeviceID != reporting.DeviceID {
		t.Fatalf("devices of the entry in state installed: %v %s", err, res.Body)
	}

	expectStatus(t, call(t, carol, http.MethodGet, softwareCatalog+"/"+entry+"/devices", nil), http.StatusNotFound, "not_found")
	expectStatus(t, call(t, carol, http.MethodGet, "/api/v1/devices/"+reporting.DeviceID+"/managed-software", nil), http.StatusNotFound, "not_found")
}
