package acceptance

import (
	"net/http"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/test/acceptance/internal/env"
)

// groupWithStaleness creates a device group of p with the given thresholds (hours, minutes in development).
func groupWithStaleness(t *testing.T, p *env.Portal, warning, critical int) string {
	t.Helper()
	res := call(t, p, http.MethodPost, "/api/v1/device-groups", map[string]any{
		"name": uniqueName("a3 staleness"), "staleness": map[string]int{"warning_h": warning, "critical_h": critical},
	})
	expectStatus(t, res, http.StatusCreated, "")
	var g struct {
		ID        string `json:"id"`
		Staleness *struct {
			WarningH  int `json:"warning_h"`
			CriticalH int `json:"critical_h"`
		} `json:"staleness"`
	}
	if err := res.JSON(&g); err != nil || g.Staleness == nil || g.Staleness.WarningH != warning || g.Staleness.CriticalH != critical {
		t.Fatalf("created group %s: %v", res.Body, err)
	}
	deleteOnCleanup(t, p, "/api/v1/device-groups/"+g.ID)
	return g.ID
}

// TestStalenessGroups is gate A3 of plan M8d (AC3): with the development stack's minute unit, a device in a group
// with 2/4 is warned after 2 minutes with source device_group while a device without a group keeps the organization's
// 24/168; a second group with 10/20 on the same device makes the lenient values apply and clears the alert; invalid
// pairs are refused and the events carry the overrides.
func TestStalenessGroups(t *testing.T) {
	slug, org := gateOrganization(t)
	user, password := tempUser(t, "stalegroups", env.RoleGroup(slug, "admins"))
	admin, err := loginAs(t, user, password)
	if err != nil {
		t.Fatal(err)
	}
	settings := currentUpdateSettings(t, admin)
	settings["staleness_warning_h"], settings["staleness_critical_h"] = 24, 168
	expectStatus(t, call(t, admin, http.MethodPut, "/api/v1/settings/updates", settings), http.StatusOK, "")

	for name, body := range map[string]map[string]any{
		"warning only":       {"name": uniqueName("a3 bad"), "staleness": map[string]int{"warning_h": 2}},
		"critical = warning": {"name": uniqueName("a3 bad"), "staleness": map[string]int{"warning_h": 4, "critical_h": 4}},
	} {
		res := call(t, admin, http.MethodPost, "/api/v1/device-groups", body)
		if res.Status != http.StatusBadRequest || res.ProblemCode() != "invalid_request" {
			t.Errorf("%s: HTTP %d %s", name, res.Status, res.ProblemCode())
		}
	}

	strict := groupWithStaleness(t, admin, 2, 4)
	res := call(t, admin, http.MethodPost, "/api/v1/device-groups", map[string]any{"name": uniqueName("a3 params"),
		"staleness": map[string]int{"warning_h": 120, "critical_h": 840}})
	expectStatus(t, res, http.StatusCreated, "")
	ev := expectOneEvent(t, admin, res.RequestID, "device_group.created", "success")
	if ev.Params["staleness_warning_h"] != float64(120) || ev.Params["staleness_critical_h"] != float64(840) ||
		ev.Params["agent_update_policy"] != nil || ev.Params["disk_unlock_mode"] != nil {
		t.Fatalf("created params %v", ev.Params)
	}
	removeCreated(t, admin, "/api/v1/device-groups", res)

	grouped := activeDevice(t, admin, strict, "a3-grouped-"+uniqueSuffix())
	plain := activeDevice(t, admin, "", "a3-plain-"+uniqueSuffix())
	ctx := testContext(t, time.Minute)
	if _, r, err := grouped.Checkin(ctx); err != nil || r.Status != http.StatusOK {
		t.Fatalf("check-in: %v", err)
	}
	if _, r, err := plain.Checkin(ctx); err != nil || r.Status != http.StatusOK {
		t.Fatalf("check-in: %v", err)
	}
	idx := auditIndex(t)
	waitAttention(t, admin, grouped.DeviceID, 4*time.Minute, "stale_warning")
	got := expectOneIndexEvent(t, idx, org, "code = 'device.stale_warning' AND target->>'id' = $1", grouped.DeviceID,
		"device.stale_warning", "success", time.Minute)
	if got.Params["threshold_h"] != float64(2) || got.Params["source"] != "device_group" {
		t.Fatalf("warning params %v", got.Params)
	}
	if kinds := attentionKinds(t, admin, plain.DeviceID); len(kinds) != 0 {
		t.Fatalf("the device without a group override is %v", kinds)
	}

	lenient := groupWithStaleness(t, admin, 10, 20)
	expectStatus(t, call(t, admin, http.MethodPut, "/api/v1/devices/"+grouped.DeviceID+"/groups",
		map[string]any{"device_group_ids": []string{strict, lenient}}), http.StatusOK, "")
	waitAttention(t, admin, grouped.DeviceID, 2*time.Minute)
	expectOneIndexEvent(t, idx, org, "code = 'device.stale_cleared' AND target->>'id' = $1", grouped.DeviceID,
		"device.stale_cleared", "success", time.Minute)

	res = call(t, admin, http.MethodPatch, "/api/v1/device-groups/"+strict, map[string]any{"staleness": nil})
	expectStatus(t, res, http.StatusOK, "")
	ev = expectOneEvent(t, admin, res.RequestID, "device_group.updated", "success")
	if ev.Params["staleness_warning_h"] != nil || ev.Params["staleness_critical_h"] != nil {
		t.Fatalf("cleared params %v", ev.Params)
	}
}
