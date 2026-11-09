package acceptance

import (
	"encoding/json"
	"net/http"
	"slices"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/pkg/bundle"
	"github.com/phischl/paddock-mdm/test/acceptance/devicesim"
	"github.com/phischl/paddock-mdm/test/acceptance/internal/env"
)

// TestMaintenanceWindow (PDK-809, plan M13c decisions 4 to 7, C2): two device groups' windows reach a member of both as
// their union; a devicesim that reports its package pending/outside_window shows so on its device page; urgent needs a
// reason (400), is refused for an API token (403) and with a step-up reaches the bundle as urgent, with urgent and the
// reason in the audit event; another organization neither reads nor writes the window.
func TestMaintenanceWindow(t *testing.T) {
	alice, carol := login(t, env.Alice), login(t, env.Carol)
	admin := adminUser(t, "mw")
	night, weekend := namedGroup(t, alice, "mw-night"), namedGroup(t, alice, "mw-weekend")
	d := activeDevice(t, alice, night, "mw-"+uniqueSuffix())
	d.SchemaVersions = []int{bundle.SchemaVersion, bundle.SchemaVersion2}
	expectStatus(t, call(t, alice, http.MethodPut, "/api/v1/devices/"+d.DeviceID+"/groups",
		map[string]any{"device_group_ids": []string{night, weekend}}), http.StatusOK, "")

	windowPath := func(group string) string { return "/api/v1/device-groups/" + group + "/maintenance-window" }
	expectStatus(t, call(t, alice, http.MethodGet, windowPath(night), nil), http.StatusNotFound, "not_found")
	res := call(t, alice, http.MethodPut, windowPath(night), map[string]any{
		"days": []int{5, 1, 2, 3, 4}, "start_minute": 1320, "duration_minutes": 180, "timezone": "Europe/Mars",
	})
	expectStatus(t, res, http.StatusBadRequest, "invalid_request")
	expectOneEvent(t, alice, res.RequestID, "device_group.maintenance_window_changed", "failure")
	res = call(t, alice, http.MethodPut, windowPath(night), map[string]any{
		"days": []int{5, 1, 2, 3, 4}, "start_minute": 1320, "duration_minutes": 180, "timezone": "Europe/Berlin",
	})
	expectStatus(t, res, http.StatusOK, "")
	ev := expectOneEvent(t, alice, res.RequestID, "device_group.maintenance_window_changed", "success")
	if ev.Params["timezone"] != "Europe/Berlin" || ev.Params["start_minute"] != float64(1320) {
		t.Fatalf("changed event params %v", ev.Params)
	}
	var stored struct {
		Days []int `json:"days"`
	}
	if err := res.JSON(&stored); err != nil || !slices.Equal(stored.Days, []int{1, 2, 3, 4, 5}) {
		t.Fatalf("stored window %s (%v)", res.Body, err)
	}
	expectStatus(t, call(t, alice, http.MethodPut, windowPath(weekend), map[string]any{
		"days": []int{6, 7}, "start_minute": 0, "duration_minutes": 1440, "timezone": "UTC",
	}), http.StatusOK, "")

	// Organization isolation: another organization's group is not found.
	expectStatus(t, call(t, carol, http.MethodGet, windowPath(night), nil), http.StatusNotFound, "not_found")
	expectStatus(t, call(t, carol, http.MethodPut, windowPath(night), map[string]any{
		"days": []int{1}, "start_minute": 0, "duration_minutes": 60, "timezone": "UTC",
	}), http.StatusNotFound, "not_found")
	expectStatus(t, call(t, carol, http.MethodDelete, windowPath(night), nil), http.StatusNotFound, "not_found")

	res = call(t, alice, http.MethodPost, softwareCatalog, entryBody("mw"))
	expectStatus(t, res, http.StatusCreated, "")
	entry := createdID(t, alice, softwareCatalog, res)
	res = call(t, alice, http.MethodPost, softwareAssignments, map[string]any{
		"catalog_entry_id": entry, "device_group_id": night, "intent": "required",
	})
	expectStatus(t, res, http.StatusCreated, "")
	assignment := softwareAssignments + "/" + responseID(t, res).String()

	b := latestBundle(t, d, 2*time.Minute, func(b *bundle.Bundle) bool { return b.Software != nil && len(b.Software.Windows) == 2 })
	if w := b.Software.Windows; w[0].Timezone != "Europe/Berlin" || w[1].Timezone != "UTC" || !slices.Equal(w[0].Days, []int{1, 2, 3, 4, 5}) {
		t.Fatalf("windows %s", asJSON(t, w))
	}
	if b.Software.Packages[0].Urgent {
		t.Fatalf("package urgent without urgent assignment %s", asJSON(t, b.Software.Packages[0]))
	}

	// The device reports the package waiting for its window; the device page shows it.
	raw, err := json.Marshal(map[string]any{"reconcile": "ok", "software": map[string]any{"digest": "mw-" + uniqueSuffix(),
		"items": []map[string]any{{"id": entry, "package": "nano", "intent": "required", "state": "pending", "reason": "outside_window"}}}})
	if err != nil {
		t.Fatal(err)
	}
	valkeyCLI(t, "worker", "DEL hb:"+d.DeviceID)
	d.Health = raw
	if _, res, err := d.Checkin(testContext(t, time.Minute)); err != nil || res.Status != http.StatusOK {
		t.Fatalf("check-in: %v %d %s", err, res.Status, res.Body)
	}
	waitManaged(t, alice, d, func(state, reason string) bool { return state == "pending" && reason == "outside_window" })

	// urgent: a reason is required, an API token cannot set it, an administrator with a step-up can.
	urgent := map[string]any{"intent": "required", "urgent": true}
	res = call(t, admin.Portal, http.MethodPatch, assignment, urgent)
	expectStatus(t, res, http.StatusBadRequest, "invalid_request")
	expectOneEvent(t, alice, res.RequestID, "software_assignment.updated", "failure")
	urgent["reason"] = "CVE-2026-0001 in nano"
	token := createAPIToken(t, admin.Portal, admin.username, "org_admin")
	res = call(t, tokenPortal(t, token.Secret), http.MethodPatch, assignment, urgent)
	expectRefusal(t, alice, res, http.StatusForbidden, "step_up_required", "software_assignment.updated")
	admin.stepUp(t)
	res = call(t, admin.Portal, http.MethodPatch, assignment, urgent)
	expectStatus(t, res, http.StatusOK, "")
	ev = expectOneEvent(t, alice, res.RequestID, "software_assignment.updated", "success")
	if ev.Params["urgent"] != true || ev.Params["reason"] != "CVE-2026-0001 in nano" {
		t.Fatalf("urgent event params %v", ev.Params)
	}
	latestBundle(t, d, 2*time.Minute, func(b *bundle.Bundle) bool {
		return b.Software != nil && len(b.Software.Packages) == 1 && b.Software.Packages[0].Urgent
	})

	// Removing a window leaves the other group's; removing both drops the windows from the bundle.
	res = call(t, alice, http.MethodDelete, windowPath(night), nil)
	expectStatus(t, res, http.StatusNoContent, "")
	expectOneEvent(t, alice, res.RequestID, "device_group.maintenance_window_removed", "success")
	latestBundle(t, d, 2*time.Minute, func(b *bundle.Bundle) bool { return b.Software != nil && len(b.Software.Windows) == 1 })
	expectStatus(t, call(t, alice, http.MethodDelete, windowPath(weekend), nil), http.StatusNoContent, "")
	latestBundle(t, d, 2*time.Minute, func(b *bundle.Bundle) bool { return b.Software != nil && b.Software.Windows == nil })
}

// waitManaged waits until the device page lists one managed application whose state and reason satisfy want.
func waitManaged(t *testing.T, p *env.Portal, d *devicesim.Device, want func(state, reason string) bool) {
	t.Helper()
	for deadline := time.Now().Add(time.Minute); ; time.Sleep(time.Second) {
		res := call(t, p, http.MethodGet, "/api/v1/devices/"+d.DeviceID+"/managed-software", nil)
		expectStatus(t, res, http.StatusOK, "")
		var page struct {
			Items []struct{ State, Reason string } `json:"items"`
		}
		if err := res.JSON(&page); err != nil {
			t.Fatal(err)
		}
		if len(page.Items) == 1 && want(page.Items[0].State, page.Items[0].Reason) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("managed software of %s: %s", d.DeviceID, res.Body)
		}
	}
}
