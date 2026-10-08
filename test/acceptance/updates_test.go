package acceptance

import (
	"net/http"
	"net/url"
	"slices"
	"sort"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/pkg/protocol"
	"github.com/phischl/paddock-mdm/test/acceptance/internal/env"
)

// holdIn holds pkg for a new device group (with the device, if given) and returns the group and the hold. Holds of
// the gates are never organization-wide, so they cannot reach devices of other gates.
func holdIn(t *testing.T, w *auditWorld, pkg, deviceID string) (group, hold string) {
	t.Helper()
	group = namedGroup(t, w.alice, "a3 hold")
	if deviceID != "" {
		res := call(t, w.alice, http.MethodPut, "/api/v1/devices/"+deviceID+"/groups", map[string]any{"device_group_ids": []string{group}})
		expectStatus(t, res, http.StatusOK, "")
	}
	res := call(t, w.alice, http.MethodPost, "/api/v1/package-holds", map[string]any{"package": pkg, "device_group_id": group})
	expectStatus(t, res, http.StatusCreated, "")
	return group, createdID(t, w.alice, "/api/v1/package-holds", res)
}

// updateSettingsCases are the A3 cases of PUT /api/v1/settings/updates; success writes acme's current settings back.
func updateSettingsCases() []auditCase {
	const path, code = "/api/v1/settings/updates", "settings.updates_changed"
	return []auditCase{
		{"success", func(t *testing.T, w *auditWorld) {
			res := call(t, w.alice, http.MethodPut, path, currentUpdateSettings(t, w.alice))
			expectStatus(t, res, http.StatusOK, "")
			expectOneEvent(t, w.alice, res.RequestID, code, "success")
		}},
		{"invalid schedule", func(t *testing.T, w *auditWorld) {
			body := currentUpdateSettings(t, w.alice)
			body["regular_schedule"] = "*-*-* 04:00"
			res := call(t, w.alice, http.MethodPut, path, body)
			expectStatus(t, res, http.StatusUnprocessableEntity, "invalid_schedule")
			expectOneEvent(t, w.alice, res.RequestID, code, "failure")
		}},
		{"validation failure", func(t *testing.T, w *auditWorld) {
			body := currentUpdateSettings(t, w.alice)
			body["staleness_critical_h"] = body["staleness_warning_h"]
			res := call(t, w.alice, http.MethodPut, path, body)
			expectStatus(t, res, http.StatusBadRequest, "invalid_request")
			expectOneEvent(t, w.alice, res.RequestID, code, "failure")
		}},
		{"wrong role", func(t *testing.T, w *auditWorld) {
			res := call(t, w.bob, http.MethodPut, path, currentUpdateSettings(t, w.alice))
			expectStatus(t, res, http.StatusForbidden, "forbidden")
			expectOneEvent(t, w.alice, res.RequestID, code, "denied")
		}},
	}
}

// packageHoldCases are the A3 cases of the package hold operations.
func packageHoldCases() map[string][]auditCase {
	const collection = "/api/v1/package-holds"
	create := func(t *testing.T, w *auditWorld) string {
		_, hold := holdIn(t, w, "a3-"+uniqueSuffix(), "")
		return hold
	}
	update := map[string]any{"version": "1.0-1", "reason": "a3"}
	return map[string][]auditCase{
		"POST " + collection: {
			{"success", func(t *testing.T, w *auditWorld) {
				res := call(t, w.alice, http.MethodPost, collection, map[string]any{"package": "a3-" + uniqueSuffix(), "device_group_id": namedGroup(t, w.alice, "a3 hold")})
				expectStatus(t, res, http.StatusCreated, "")
				createdID(t, w.alice, collection, res)
				expectOneEvent(t, w.alice, res.RequestID, "package_hold.created", "success")
			}},
			{"validation failure", func(t *testing.T, w *auditWorld) {
				res := call(t, w.alice, http.MethodPost, collection, map[string]any{"package": "-oAPT::x"})
				expectStatus(t, res, http.StatusBadRequest, "invalid_request")
				expectOneEvent(t, w.alice, res.RequestID, "package_hold.created", "failure")
			}},
			{"wrong role", func(t *testing.T, w *auditWorld) {
				res := call(t, w.bob, http.MethodPost, collection, map[string]any{"package": "a3-" + uniqueSuffix(), "device_group_id": namedGroup(t, w.alice, "a3 hold")})
				expectStatus(t, res, http.StatusForbidden, "forbidden")
				expectOneEvent(t, w.alice, res.RequestID, "package_hold.created", "denied")
			}},
			{"conflict", func(t *testing.T, w *auditWorld) {
				pkg := "a3-" + uniqueSuffix()
				group, _ := holdIn(t, w, pkg, "")
				res := call(t, w.alice, http.MethodPost, collection, map[string]any{"package": pkg, "device_group_id": group})
				expectStatus(t, res, http.StatusConflict, "already_exists")
				expectOneEvent(t, w.alice, res.RequestID, "package_hold.created", "failure")
			}},
		},
		"PATCH " + collection + "/{id}": {
			{"success", func(t *testing.T, w *auditWorld) {
				res := call(t, w.alice, http.MethodPatch, collection+"/"+create(t, w), update)
				expectStatus(t, res, http.StatusOK, "")
				expectOneEvent(t, w.alice, res.RequestID, "package_hold.updated", "success")
			}},
			{"validation failure", func(t *testing.T, w *auditWorld) {
				res := call(t, w.alice, http.MethodPatch, collection+"/"+create(t, w), map[string]any{"version": "1 0", "reason": ""})
				expectStatus(t, res, http.StatusBadRequest, "invalid_request")
				expectOneEvent(t, w.alice, res.RequestID, "package_hold.updated", "failure")
			}},
			{"wrong role", func(t *testing.T, w *auditWorld) {
				res := call(t, w.bob, http.MethodPatch, collection+"/"+create(t, w), update)
				expectStatus(t, res, http.StatusForbidden, "forbidden")
				expectOneEvent(t, w.alice, res.RequestID, "package_hold.updated", "denied")
			}},
			{"not found", func(t *testing.T, w *auditWorld) {
				res := call(t, w.alice, http.MethodPatch, collection+"/"+uuid.NewString(), update)
				expectStatus(t, res, http.StatusNotFound, "not_found")
				expectOneEvent(t, w.alice, res.RequestID, "package_hold.updated", "failure")
			}},
		},
		"DELETE " + collection + "/{id}": {
			{"success", func(t *testing.T, w *auditWorld) {
				res := call(t, w.alice, http.MethodDelete, collection+"/"+create(t, w), nil)
				expectStatus(t, res, http.StatusNoContent, "")
				expectOneEvent(t, w.alice, res.RequestID, "package_hold.deleted", "success")
			}},
			{"wrong role", func(t *testing.T, w *auditWorld) {
				res := call(t, w.bob, http.MethodDelete, collection+"/"+create(t, w), nil)
				expectStatus(t, res, http.StatusForbidden, "forbidden")
				expectOneEvent(t, w.alice, res.RequestID, "package_hold.deleted", "denied")
			}},
			{"not found", func(t *testing.T, w *auditWorld) {
				res := call(t, w.alice, http.MethodDelete, collection+"/"+uuid.NewString(), nil)
				expectStatus(t, res, http.StatusNotFound, "not_found")
				expectOneEvent(t, w.alice, res.RequestID, "package_hold.deleted", "failure")
			}},
		},
	}
}

// installNowCases are the A3 cases of POST /api/v1/<collection>/{id}/install-now; target returns an active device or
// a device group with one, and its ID once the device holds the package.
func installNowCases(collection string, target func(t *testing.T, w *auditWorld) string, held func(t *testing.T, w *auditWorld, pkg string) string,
	success int) []auditCase {
	const code = "device.install_now_requested"
	path := func(id string) string { return collection + "/" + id + "/install-now" }
	body := map[string]any{"packages": []string{"htop"}}
	return []auditCase{
		{"success", func(t *testing.T, w *auditWorld) {
			res := call(t, w.alice, http.MethodPost, path(target(t, w)), body)
			expectStatus(t, res, success, "")
			expectOneEvent(t, w.alice, res.RequestID, code, "success")
		}},
		{"validation failure", func(t *testing.T, w *auditWorld) {
			res := call(t, w.alice, http.MethodPost, path(target(t, w)), map[string]any{"packages": []string{"-y"}})
			expectStatus(t, res, http.StatusBadRequest, "invalid_request")
			expectOneEvent(t, w.alice, res.RequestID, code, "failure")
		}},
		{"wrong role", func(t *testing.T, w *auditWorld) {
			res := call(t, w.bob, http.MethodPost, path(target(t, w)), body)
			expectStatus(t, res, http.StatusForbidden, "forbidden")
			expectOneEvent(t, w.alice, res.RequestID, code, "denied")
		}},
		{"not found", func(t *testing.T, w *auditWorld) {
			res := call(t, w.alice, http.MethodPost, path(uuid.NewString()), body)
			expectStatus(t, res, http.StatusNotFound, "not_found")
			expectOneEvent(t, w.alice, res.RequestID, code, "failure")
		}},
		{"package on hold", func(t *testing.T, w *auditWorld) {
			pkg := "a3-" + uniqueSuffix()
			res := call(t, w.alice, http.MethodPost, path(held(t, w, pkg)), map[string]any{"packages": []string{"htop", pkg}})
			expectStatus(t, res, http.StatusConflict, "package_on_hold")
			expectOneEvent(t, w.alice, res.RequestID, code, "failure")
		}},
	}
}

func init() {
	deviceAuditCases["PUT /api/v1/settings/updates"] = updateSettingsCases()
	for op, cases := range packageHoldCases() {
		deviceAuditCases[op] = cases
	}
	deviceAuditCases["POST /api/v1/devices/{id}/install-now"] = append(installNowCases("/api/v1/devices", activeID,
		func(t *testing.T, w *auditWorld, pkg string) string {
			id := activeID(t, w)
			holdIn(t, w, pkg, id)
			return id
		}, http.StatusAccepted),
		auditCase{"conflict", func(t *testing.T, w *auditWorld) {
			res := call(t, w.alice, http.MethodPost, "/api/v1/devices/"+pendingDevice(t, w)+"/install-now", map[string]any{"packages": []string{"htop"}})
			expectStatus(t, res, http.StatusConflict, "invalid_state")
			expectOneEvent(t, w.alice, res.RequestID, "device.install_now_requested", "failure")
		}})
	deviceAuditCases["POST /api/v1/device-groups/{id}/install-now"] = installNowCases("/api/v1/device-groups",
		func(t *testing.T, w *auditWorld) string {
			group := namedGroup(t, w.alice, "a3 install")
			activeDevice(t, w.alice, group, "a3-install-"+uniqueSuffix())
			return group
		},
		func(t *testing.T, w *auditWorld, pkg string) string {
			group := namedGroup(t, w.alice, "a3 install")
			d := activeDevice(t, w.alice, group, "a3-install-"+uniqueSuffix())
			holdGroup, _ := holdIn(t, w, pkg, "")
			// The member's other group holds the package.
			res := call(t, w.alice, http.MethodPut, "/api/v1/devices/"+d.DeviceID+"/groups", map[string]any{"device_group_ids": []string{group, holdGroup}})
			expectStatus(t, res, http.StatusOK, "")
			return group
		}, http.StatusAccepted)
}

// attentionKinds returns the staleness kinds of the attention list entries of a device (a simulated device's agent is
// never the current release).
func attentionKinds(t *testing.T, p *env.Portal, deviceID string) []string {
	t.Helper()
	q := url.Values{"page_size": {"100"}, "q": {getDevice(t, p, deviceID).Hostname}, "kind": {"stale_warning", "stale_critical", "presumed_lost"}}
	res := call(t, p, http.MethodGet, "/api/v1/attention?"+q.Encode(), nil)
	expectStatus(t, res, http.StatusOK, "")
	var page struct {
		Items []struct {
			Kind     string `json:"kind"`
			DeviceID string `json:"device_id"`
		} `json:"items"`
	}
	if err := res.JSON(&page); err != nil {
		t.Fatal(err)
	}
	var kinds []string
	for _, it := range page.Items {
		if it.DeviceID == deviceID {
			kinds = append(kinds, it.Kind)
		}
	}
	sort.Strings(kinds)
	return kinds
}

// waitAttention polls the attention list until the device's kinds are want.
func waitAttention(t *testing.T, p *env.Portal, deviceID string, timeout time.Duration, want ...string) {
	t.Helper()
	sort.Strings(want)
	deadline := time.Now().Add(timeout)
	for {
		got := attentionKinds(t, p, deviceID)
		if slices.Equal(got, want) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("attention of %s: %v, want %v", deviceID, got, want)
		}
		time.Sleep(5 * time.Second)
	}
}

// TestStalenessGate is gate U4 (plan M5b §5, AC4): with the development stack's minute unit, a device that stops
// checking in gets a warning and then a critical alert, each audited once, is listed on the attention page as
// presumed lost, and one check-in clears it with device.stale_cleared. It runs in an organization of its own, whose
// thresholds it may shorten.
func TestStalenessGate(t *testing.T) {
	slug, org := gateOrganization(t)
	user, password := tempUser(t, "stale", env.RoleGroup(slug, "admins"))
	admin, err := loginAs(t, user, password)
	if err != nil {
		t.Fatal(err)
	}
	settings := currentUpdateSettings(t, admin)
	settings["staleness_warning_h"], settings["staleness_critical_h"] = 1, 3
	expectStatus(t, call(t, admin, http.MethodPut, "/api/v1/settings/updates", settings), http.StatusOK, "")
	d := activeDevice(t, admin, "", "u4-"+uniqueSuffix())
	ctx := testContext(t, time.Minute)
	if _, res, err := d.Checkin(ctx); err != nil || res.Status != http.StatusOK {
		t.Fatalf("check-in: %v %d", err, res.Status)
	}
	idx := auditIndex(t)
	waitAttention(t, admin, d.DeviceID, 3*time.Minute, "stale_warning")
	expectOneIndexEvent(t, idx, org, "code = 'device.stale_warning' AND target->>'id' = $1", d.DeviceID, "device.stale_warning", "success", time.Minute)
	waitAttention(t, admin, d.DeviceID, 4*time.Minute, "stale_critical", "presumed_lost")
	expectOneIndexEvent(t, idx, org, "code = 'device.stale_critical' AND target->>'id' = $1", d.DeviceID, "device.stale_critical", "success", time.Minute)
	if detail := getDeviceDetail(t, admin, d.DeviceID); detail["presumed_lost_at"] == nil {
		t.Fatalf("device detail without presumed_lost_at: %v", detail)
	}
	if _, res, err := d.Checkin(testContext(t, time.Minute)); err != nil || res.Status != http.StatusOK {
		t.Fatalf("check-in: %v %d", err, res.Status)
	}
	waitAttention(t, admin, d.DeviceID, 2*time.Minute)
	expectOneIndexEvent(t, idx, org, "code = 'device.stale_cleared' AND target->>'id' = $1", d.DeviceID, "device.stale_cleared", "success", time.Minute)
	// Exactly once each, also after further rounds.
	for _, code := range []string{"device.stale_warning", "device.stale_critical"} {
		expectOneIndexEvent(t, idx, org, "code = '"+code+"' AND target->>'id' = $1", d.DeviceID, code, "success", time.Second)
	}
	if detail := getDeviceDetail(t, admin, d.DeviceID); detail["presumed_lost_at"] != nil {
		t.Fatalf("presumed_lost_at after the check-in: %v", detail["presumed_lost_at"])
	}
}

func getDeviceDetail(t *testing.T, p *env.Portal, id string) map[string]any {
	t.Helper()
	res := call(t, p, http.MethodGet, "/api/v1/devices/"+id, nil)
	expectStatus(t, res, http.StatusOK, "")
	var out map[string]any
	if err := res.JSON(&out); err != nil {
		t.Fatal(err)
	}
	return out
}

// TestInstallNowRefusesHeldPackages is the API part of gate U2 (plan M5b §5, AC2): a package held for the device is
// refused with 409 package_on_hold and no command is issued; an unheld one is delivered with the next check-in.
func TestInstallNowRefusesHeldPackages(t *testing.T) {
	alice := login(t, env.Alice)
	group := namedGroup(t, alice, "u2 hold")
	d := activeDevice(t, alice, group, "u2-"+uniqueSuffix())
	pkg := "u2-" + uniqueSuffix()
	res := call(t, alice, http.MethodPost, "/api/v1/package-holds", map[string]any{"package": pkg, "device_group_id": group, "version": "1.0-1"})
	expectStatus(t, res, http.StatusCreated, "")
	createdID(t, alice, "/api/v1/package-holds", res)
	res = call(t, alice, http.MethodPost, "/api/v1/devices/"+d.DeviceID+"/install-now", map[string]any{"packages": []string{"htop", pkg}})
	expectStatus(t, res, http.StatusConflict, "package_on_hold")
	commands := func() int {
		res := call(t, alice, http.MethodGet, "/api/v1/devices/"+d.DeviceID+"/commands?type=install_now", nil)
		expectStatus(t, res, http.StatusOK, "")
		var page struct {
			Total int `json:"total"`
		}
		if err := res.JSON(&page); err != nil {
			t.Fatal(err)
		}
		return page.Total
	}
	if n := commands(); n != 0 {
		t.Fatalf("%d install_now commands after the refusal", n)
	}
	res = call(t, alice, http.MethodGet, "/api/v1/devices/"+d.DeviceID+"/updates", nil)
	expectStatus(t, res, http.StatusOK, "")
	var upd struct {
		Holds []struct {
			Package string  `json:"package"`
			Version *string `json:"version"`
		} `json:"holds"`
	}
	if err := res.JSON(&upd); err != nil || !slices.ContainsFunc(upd.Holds, func(h struct {
		Package string  `json:"package"`
		Version *string `json:"version"`
	}) bool {
		return h.Package == pkg && h.Version != nil && *h.Version == "1.0-1"
	}) {
		t.Fatalf("device updates %s (%v)", res.Body, err)
	}
	res = call(t, alice, http.MethodPost, "/api/v1/devices/"+d.DeviceID+"/install-now", map[string]any{"packages": []string{"htop"}})
	expectStatus(t, res, http.StatusAccepted, "")
	checkinUntil(t, d, time.Minute, func(r protocol.CheckinResponse) bool { return len(r.Commands) == 1 })
	if n := commands(); n != 1 {
		t.Fatalf("%d install_now commands", n)
	}
}
