package acceptance

import (
	"net/http"
	"reflect"
	"testing"

	"github.com/phischl/paddock-mdm/test/acceptance/internal/env"
)

// rolloutSettingsCases are the A3 cases of PUT /api/v1/settings/rollout; success writes acme's current settings back.
func rolloutSettingsCases() []auditCase {
	const path, code = "/api/v1/settings/rollout", "settings.rollout_changed"
	return []auditCase{
		{"success", func(t *testing.T, w *auditWorld) {
			res := call(t, w.alice, http.MethodPut, path, currentRolloutSettings(t, w.alice))
			expectStatus(t, res, http.StatusOK, "")
			expectOneEvent(t, w.alice, res.RequestID, code, "success")
		}},
		{"invalid waves", func(t *testing.T, w *auditWorld) {
			body := currentRolloutSettings(t, w.alice)
			body["waves"] = []int{1, 10}
			res := call(t, w.alice, http.MethodPut, path, body)
			expectStatus(t, res, http.StatusBadRequest, "invalid_request")
			expectOneEvent(t, w.alice, res.RequestID, code, "failure")
		}},
		{"unknown canary group", func(t *testing.T, w *auditWorld) {
			body := currentRolloutSettings(t, w.alice)
			body["canary_device_group_id"] = "00000000-0000-7000-8000-000000000000"
			res := call(t, w.alice, http.MethodPut, path, body)
			expectStatus(t, res, http.StatusNotFound, "not_found")
			expectOneEvent(t, w.alice, res.RequestID, code, "failure")
		}},
		{"wrong role", func(t *testing.T, w *auditWorld) {
			res := call(t, w.bob, http.MethodPut, path, currentRolloutSettings(t, w.alice))
			expectStatus(t, res, http.StatusForbidden, "forbidden")
			expectOneEvent(t, w.alice, res.RequestID, code, "denied")
		}},
	}
}

func init() {
	deviceAuditCases["PUT /api/v1/settings/rollout"] = rolloutSettingsCases()
}

// TestRolloutSettings is the gate of the rollout settings (plan M11 §8): the defaults, the validation, the audit event
// with every field, the roles, the isolation between organizations and the canary group that disappears with its
// device group. It runs in an organization of its own. The production minimum of 15 minutes is a unit test; the
// development stack accepts 1.
func TestRolloutSettings(t *testing.T) {
	admin, slug := gateOrg(t, "rollout-settings")
	const path = "/api/v1/settings/rollout"

	res := call(t, admin.Portal, http.MethodGet, path, nil)
	expectStatus(t, res, http.StatusOK, "")
	var got map[string]any
	if err := res.JSON(&got); err != nil {
		t.Fatal(err)
	}
	want := map[string]any{
		"enabled": false, "waves": []any{1.0, 10.0, 50.0, 100.0}, "min_wave_minutes": 60.0,
		"failure_threshold_percent": 2.0, "failure_threshold_min": 3.0, "canary_device_group_id": nil,
	}
	delete(got, "updated_at")
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("defaults %v, want %v", got, want)
	}

	valid := func() map[string]any {
		return map[string]any{
			"enabled": true, "waves": []int{5, 50, 100}, "min_wave_minutes": 30,
			"failure_threshold_percent": 4, "failure_threshold_min": 2,
		}
	}
	invalid := map[string]func(map[string]any){
		"waves not ending with 100": func(b map[string]any) { b["waves"] = []int{10, 50} },
		"waves not increasing":      func(b map[string]any) { b["waves"] = []int{50, 10, 100} },
		"no waves":                  func(b map[string]any) { b["waves"] = []int{} },
		"zero minutes":              func(b map[string]any) { b["min_wave_minutes"] = 0 },
		"threshold above 100":       func(b map[string]any) { b["failure_threshold_percent"] = 101 },
	}
	for name, mutate := range invalid {
		body := valid()
		mutate(body)
		res := call(t, admin.Portal, http.MethodPut, path, body)
		if res.Status != http.StatusBadRequest {
			t.Errorf("%s: HTTP %d %s", name, res.Status, res.Body)
		}
	}
	// Refused writes leave the defaults in place.
	if s := currentRolloutSettings(t, admin.Portal); s["enabled"] != false {
		t.Fatalf("settings after refused writes: %v", s)
	}

	group := namedGroup(t, admin.Portal, "rollout canary")
	body := valid()
	body["canary_device_group_id"] = group
	res = call(t, admin.Portal, http.MethodPut, path, body)
	expectStatus(t, res, http.StatusOK, "")
	ev := expectOneEvent(t, admin.Portal, res.RequestID, "settings.rollout_changed", "success")
	for _, k := range []string{"enabled", "waves", "min_wave_minutes", "failure_threshold_percent", "failure_threshold_min", "canary_device_group_id"} {
		if _, ok := ev.Params[k]; !ok {
			t.Errorf("audit param %s missing: %v", k, ev.Params)
		}
	}
	if ev.Params["canary_device_group_id"] != group || ev.Params["enabled"] != true {
		t.Errorf("audit params %v", ev.Params)
	}
	if s := currentRolloutSettings(t, admin.Portal); s["canary_device_group_id"] != group || s["min_wave_minutes"] != 30.0 {
		t.Fatalf("reload %v", s)
	}

	// A device group of another organization is invisible: not_found, the same as an unknown one.
	acme := login(t, env.Alice)
	foreign := valid()
	foreign["canary_device_group_id"] = namedGroup(t, acme, "rollout foreign")
	expectStatus(t, call(t, admin.Portal, http.MethodPut, path, foreign), http.StatusNotFound, "not_found")
	foreign["canary_device_group_id"] = "00000000-0000-7000-8000-000000000000"
	expectStatus(t, call(t, admin.Portal, http.MethodPut, path, foreign), http.StatusNotFound, "not_found")

	operatorName, operatorPW := tempUser(t, "rollout-operator", env.RoleGroup(slug, "operators"))
	operator, err := loginAs(t, operatorName, operatorPW)
	if err != nil {
		t.Fatal(err)
	}
	expectStatus(t, call(t, operator, http.MethodPut, path, valid()), http.StatusForbidden, "forbidden")
	expectStatus(t, call(t, operator, http.MethodGet, path, nil), http.StatusOK, "")

	// Another organization is not affected.
	if s := currentRolloutSettings(t, acme); s["canary_device_group_id"] == group {
		t.Fatalf("acme sees the canary group of the gate organization: %v", s)
	}

	expectStatus(t, call(t, admin.Portal, http.MethodDelete, "/api/v1/device-groups/"+group, nil), http.StatusNoContent, "")
	if s := currentRolloutSettings(t, admin.Portal); s["canary_device_group_id"] != nil || s["enabled"] != true {
		t.Fatalf("after deleting the canary group: %v", s)
	}
}
