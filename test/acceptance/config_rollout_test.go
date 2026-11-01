package acceptance

import (
	"net/http"
	"net/url"
	"reflect"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/pkg/bundle"
	"github.com/phischl/paddock-mdm/pkg/protocol"
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
	for verb, code := range map[string]string{
		"halt": "config_rollout.halted", "resume": "config_rollout.resumed", "advance": "config_rollout.advanced",
		"complete": "config_rollout.completed",
	} {
		deviceAuditCases["POST /api/v1/config-rollouts/{id}/"+verb] = configRolloutCases(verb, code)
	}
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

// configRollout is a configuration rollout as GET /api/v1/config-rollouts/{id} and the actions return it.
type configRollout struct {
	ID               string  `json:"id"`
	ChangeSetID      string  `json:"change_set_id"`
	Status           string  `json:"status"`
	CurrentWaveIndex int     `json:"current_wave_index"`
	HaltedReason     *string `json:"halted_reason"`
	EndedAt          *string `json:"ended_at"`
	EndedReason      *string `json:"ended_reason"`
	Counts           struct {
		Eligible, Applied, Failed, Pending int
	} `json:"counts"`
}

func configRolloutPath(id, verb string) string {
	if verb == "" {
		return "/api/v1/config-rollouts/" + id
	}
	return "/api/v1/config-rollouts/" + id + "/" + verb
}

func configRolloutOf(t *testing.T, res env.Response) configRollout {
	t.Helper()
	expectStatus(t, res, http.StatusOK, "")
	var r configRollout
	if err := res.JSON(&r); err != nil {
		t.Fatal(err)
	}
	return r
}

// getConfigRollout reads rollout id.
func getConfigRollout(t *testing.T, p *env.Portal, id string) configRollout {
	t.Helper()
	res := call(t, p, http.MethodGet, configRolloutPath(id, ""), nil)
	expectStatus(t, res, http.StatusOK, "")
	var d struct {
		Rollout configRollout `json:"rollout"`
	}
	if err := res.JSON(&d); err != nil {
		t.Fatal(err)
	}
	return d.Rollout
}

// startConfigRollout switches rollouts on with settings and stages a managed file at path for every device; it returns
// the rollout and its change set. When the test ends the rollout is completed if it is still open, before the cleanups
// registered earlier (device groups the rollout may name) run.
func startConfigRollout(t *testing.T, p *env.Portal, settings map[string]any, path string) (rollout, changeSet string) {
	t.Helper()
	settings["enabled"] = true
	expectStatus(t, call(t, p, http.MethodPut, "/api/v1/settings/rollout", settings), http.StatusOK, "")
	applied := stagedResultOf(t, putConfig(t, p, withFile(getConfig(t, p), path, "staged\n"), false))
	if applied.Rollout == nil || *applied.Rollout != "staged" || applied.RolloutID == nil || applied.ChangeSetID == nil {
		t.Fatalf("staged apply: %+v", applied)
	}
	rollout = *applied.RolloutID
	t.Cleanup(func() {
		res := call(t, p, http.MethodPost, configRolloutPath(rollout, "complete"), nil)
		if res.Status != http.StatusOK && res.Status != http.StatusConflict {
			t.Errorf("cleanup: complete rollout %s: HTTP %d %s", rollout, res.Status, res.Body)
		}
	})
	return rollout, *applied.ChangeSetID
}

// waitConfigRolloutStatus polls rollout id until it has status want.
func waitConfigRolloutStatus(t *testing.T, p *env.Portal, id, want string, timeout time.Duration) configRollout {
	t.Helper()
	for deadline := time.Now().Add(timeout); ; time.Sleep(2 * time.Second) {
		// The deadline is checked against the poll's start, as in expectOneEvent (PDK-551, PDK-561).
		polled := time.Now()
		r := getConfigRollout(t, p, id)
		if r.Status == want {
			return r
		}
		if polled.After(deadline) {
			t.Fatalf("rollout %s is %s after %s, want %s", id, r.Status, timeout, want)
		}
	}
}

// rolloutEvents polls p's audit log until it holds at least one event with code for rollout id and returns them all.
func rolloutEvents(t *testing.T, p *env.Portal, code, id string) []env.AuditEvent {
	t.Helper()
	ctx := testContext(t, 2*time.Minute)
	for deadline := time.Now().Add(auditPollTimeout); ; time.Sleep(time.Second) {
		polled := time.Now()
		events, err := p.AuditEvents(ctx, code)
		if err != nil {
			t.Fatal(err)
		}
		var out []env.AuditEvent
		for _, e := range events {
			if e.Params["rollout_id"] == id {
				out = append(out, e)
			}
		}
		if len(out) > 0 || polled.After(deadline) {
			return out
		}
	}
}

// configRolloutCases are the A3 cases of POST /api/v1/config-rollouts/{id}/<verb>: success on a rollout of a gate
// organization of its own (one open rollout per organization), a missing rollout, the auditor, and for halt a missing
// reason.
func configRolloutCases(verb, code string) []auditCase {
	body := func() any {
		if verb == "halt" {
			return map[string]string{"reason": "audit gate"}
		}
		return nil
	}
	cases := []auditCase{
		{"success", func(t *testing.T, w *auditWorld) {
			admin, _ := gateOrg(t, "a3-rollout-"+verb)
			id, _ := startConfigRollout(t, admin.Portal, map[string]any{"waves": []int{50, 100}, "min_wave_minutes": 60,
				"failure_threshold_percent": 2, "failure_threshold_min": 3}, "/etc/paddock-gates/a3-rollout-"+verb+"-"+uniqueSuffix()+".conf")
			if verb == "resume" {
				expectStatus(t, call(t, admin.Portal, http.MethodPost, configRolloutPath(id, "halt"), map[string]string{"reason": "a3"}), http.StatusOK, "")
			}
			res := call(t, admin.Portal, http.MethodPost, configRolloutPath(id, verb), body())
			expectStatus(t, res, http.StatusOK, "")
			expectOneEvent(t, admin.Portal, res.RequestID, code, "success")
		}},
		{"not found", func(t *testing.T, w *auditWorld) {
			res := call(t, w.alice, http.MethodPost, configRolloutPath("00000000-0000-7000-8000-000000000000", verb), body())
			expectStatus(t, res, http.StatusNotFound, "not_found")
			expectOneEvent(t, w.alice, res.RequestID, code, "failure")
		}},
		{"wrong role", func(t *testing.T, w *auditWorld) {
			res := call(t, w.bob, http.MethodPost, configRolloutPath("00000000-0000-7000-8000-000000000000", verb), body())
			expectStatus(t, res, http.StatusForbidden, "forbidden")
			expectOneEvent(t, w.alice, res.RequestID, code, "denied")
		}},
	}
	if verb == "halt" {
		cases = append(cases, auditCase{"no reason", func(t *testing.T, w *auditWorld) {
			res := call(t, w.alice, http.MethodPost, configRolloutPath("00000000-0000-7000-8000-000000000000", verb), map[string]string{})
			expectStatus(t, res, http.StatusBadRequest, "invalid_request")
			expectOneEvent(t, w.alice, res.RequestID, code, "failure")
		}})
	}
	return cases
}

// rolloutDevice is an item of GET /api/v1/config-rollouts/{id}/devices.
type rolloutDevice struct {
	DeviceID          string   `json:"device_id"`
	InWave            bool     `json:"in_wave"`
	CarriesRollout    bool     `json:"carries_rollout"`
	ReportOutcome     string   `json:"report_outcome"`
	FailedResourceIDs []string `json:"failed_resource_ids"`
}

func rolloutDevices(t *testing.T, p *env.Portal, id string) map[string]rolloutDevice {
	t.Helper()
	res := call(t, p, http.MethodGet, configRolloutPath(id, "devices")+"?page_size=100", nil)
	expectStatus(t, res, http.StatusOK, "")
	var page struct {
		Items []rolloutDevice `json:"items"`
	}
	if err := res.JSON(&page); err != nil {
		t.Fatal(err)
	}
	out := map[string]rolloutDevice{}
	for _, d := range page.Items {
		out[d.DeviceID] = d
	}
	return out
}

// TestConfigRolloutActions is the gate of the wave actions (plan M11 decision 32, §8, amendment R6.13): halt needs a
// reason, resume, advance (refused in the last wave) and complete change the rollout and are audited once each with
// manual where the registry defines it; the device list marks in_wave per device; the auditor is refused every
// action and another organization gets not_found. Rollouts are switched off after the start: every action still
// works, an open rollout keeps its rules until it ends.
func TestConfigRolloutActions(t *testing.T) {
	admin, slug := gateOrg(t, "m11-actions")
	suffix := uniqueSuffix()
	a, b := activeDevice(t, admin.Portal, "", "ra-a-"+suffix), activeDevice(t, admin.Portal, "", "ra-b-"+suffix)
	for _, d := range []string{a.DeviceID, b.DeviceID} {
		waitBundleVersion(t, admin.Portal, d)
	}
	id, changeSet := startConfigRollout(t, admin.Portal, map[string]any{"waves": []int{50, 100}, "min_wave_minutes": 60,
		"failure_threshold_percent": 2, "failure_threshold_min": 3}, "/etc/paddock-gates/m11-actions-"+suffix+".conf")
	off := currentRolloutSettings(t, admin.Portal)
	off["enabled"] = false
	expectStatus(t, call(t, admin.Portal, http.MethodPut, "/api/v1/settings/rollout", off), http.StatusOK, "")

	devices := rolloutDevices(t, admin.Portal, id)
	for _, d := range []string{a.DeviceID, b.DeviceID} {
		if got, ok := devices[d]; !ok || got.InWave != (configRolloutBucket(d, id) < 50) {
			t.Errorf("device %s: %+v (bucket %d)", d, got, configRolloutBucket(d, id))
		}
	}

	auditor := tempPortal(t, "ra-auditor", env.RoleGroup(slug, "auditors"))
	expectStatus(t, call(t, auditor, http.MethodGet, configRolloutPath(id, ""), nil), http.StatusOK, "")
	acme := login(t, env.Alice)
	expectStatus(t, call(t, acme, http.MethodGet, configRolloutPath(id, ""), nil), http.StatusNotFound, "not_found")
	expectStatus(t, call(t, acme, http.MethodGet, configRolloutPath(id, "devices"), nil), http.StatusNotFound, "not_found")
	for _, verb := range []string{"halt", "resume", "advance", "complete"} {
		var body any
		if verb == "halt" {
			body = map[string]string{"reason": "not allowed"}
		}
		expectStatus(t, call(t, auditor, http.MethodPost, configRolloutPath(id, verb), body), http.StatusForbidden, "forbidden")
		expectStatus(t, call(t, acme, http.MethodPost, configRolloutPath(id, verb), body), http.StatusNotFound, "not_found")
	}

	res := call(t, admin.Portal, http.MethodPost, configRolloutPath(id, "halt"), map[string]string{})
	expectStatus(t, res, http.StatusBadRequest, "invalid_request")
	expectOneEvent(t, admin.Portal, res.RequestID, "config_rollout.halted", "failure")
	res = call(t, admin.Portal, http.MethodPost, configRolloutPath(id, "resume"), nil)
	expectStatus(t, res, http.StatusConflict, "invalid_state")
	expectOneEvent(t, admin.Portal, res.RequestID, "config_rollout.resumed", "failure")

	res = call(t, admin.Portal, http.MethodPost, configRolloutPath(id, "halt"), map[string]string{"reason": "gate halt"})
	if r := configRolloutOf(t, res); r.Status != "halted" || r.HaltedReason == nil || *r.HaltedReason != "gate halt" {
		t.Fatalf("halted %+v", r)
	}
	ev := expectOneEvent(t, admin.Portal, res.RequestID, "config_rollout.halted", "success")
	if ev.Params["rollout_id"] != id || ev.Params["change_set_id"] != changeSet || ev.Params["reason"] != "gate halt" {
		t.Fatalf("halted params %v", ev.Params)
	}
	res = call(t, admin.Portal, http.MethodPost, configRolloutPath(id, "resume"), nil)
	if r := configRolloutOf(t, res); r.Status != "running" {
		t.Fatalf("resumed %+v", r)
	}
	expectOneEvent(t, admin.Portal, res.RequestID, "config_rollout.resumed", "success")

	res = call(t, admin.Portal, http.MethodPost, configRolloutPath(id, "advance"), nil)
	if r := configRolloutOf(t, res); r.Status != "running" || r.CurrentWaveIndex != 1 {
		t.Fatalf("advanced %+v", r)
	}
	ev = expectOneEvent(t, admin.Portal, res.RequestID, "config_rollout.advanced", "success")
	if ev.Params["manual"] != true || ev.Params["wave"] != 1.0 || ev.Params["percent"] != 100.0 {
		t.Fatalf("advanced params %v", ev.Params)
	}
	res = call(t, admin.Portal, http.MethodPost, configRolloutPath(id, "advance"), nil)
	expectStatus(t, res, http.StatusConflict, "invalid_state")
	expectOneEvent(t, admin.Portal, res.RequestID, "config_rollout.advanced", "failure")
	for d, got := range rolloutDevices(t, admin.Portal, id) {
		if !got.InWave {
			t.Errorf("device %s outside the last wave: %+v", d, got)
		}
	}

	res = call(t, admin.Portal, http.MethodPost, configRolloutPath(id, "complete"), nil)
	if r := configRolloutOf(t, res); r.Status != "completed" || r.EndedAt == nil || r.EndedReason == nil {
		t.Fatalf("completed %+v", r)
	}
	if ev := expectOneEvent(t, admin.Portal, res.RequestID, "config_rollout.completed", "success"); ev.Params["manual"] != true {
		t.Fatalf("completed params %v", ev.Params)
	}
	expectStatus(t, call(t, admin.Portal, http.MethodPost, configRolloutPath(id, "complete"), nil), http.StatusConflict, "invalid_state")
}

// TestConfigRolloutAutoStop is the gate of the worker's evaluation (plan M11 decision 33, §8): with the threshold at
// one failed device, a failure of a staged resource halts the rollout within one round as worker, exactly one
// config_rollout.halted; a failure of another resource does not count. Resumed and completed, a device outside the
// wave receives the file. The revert of the change set of a running rollout ends it as reverted.
func TestConfigRolloutAutoStop(t *testing.T) {
	admin, _ := gateOrg(t, "m11-autostop")
	suffix := uniqueSuffix()
	canary := namedGroup(t, admin.Portal, "autostop canary")
	a := activeDevice(t, admin.Portal, canary, "as-a-"+suffix)
	b := activeDevice(t, admin.Portal, canary, "as-b-"+suffix)
	c := activeDevice(t, admin.Portal, "", "as-c-"+suffix)
	for _, d := range []string{a.DeviceID, b.DeviceID, c.DeviceID} {
		waitBundleVersion(t, admin.Portal, d)
	}
	file := "/etc/paddock-gates/m11-autostop-" + suffix + ".conf"
	staged := "file:" + file
	id, _ := startConfigRollout(t, admin.Portal, map[string]any{"waves": []int{1, 100}, "min_wave_minutes": 60,
		"failure_threshold_percent": 0, "failure_threshold_min": 1, "canary_device_group_id": canary}, file)
	cInWave := configRolloutBucket(c.DeviceID, id) < 1

	ba := latestBundle(t, a, 2*time.Minute, func(b *bundle.Bundle) bool { return hasResource(b, staged) })
	bb := latestBundle(t, b, 2*time.Minute, func(b *bundle.Bundle) bool { return hasResource(b, staged) })
	other := "unit:as-other-" + suffix + ".service"
	sendBundleEvent(t, a, 1, protocol.EventBundleApplied, map[string]any{
		"version": ba.BundleVersion, "changed": 1, "mode": "enforce", "errors": []map[string]string{{"id": other, "message": "unit not found"}},
		"resources": []map[string]any{{"id": staged, "status": "applied"}, {"id": other, "status": "failed", "message": "unit not found"}},
	})
	sendBundleEvent(t, b, 1, protocol.EventBundleApplied, map[string]any{
		"version": bb.BundleVersion, "changed": 0, "mode": "enforce", "errors": []map[string]string{{"id": staged, "message": "write failed"}},
		"resources": []map[string]any{{"id": staged, "status": "failed", "message": "write failed"}},
	})
	halted := waitConfigRolloutStatus(t, admin.Portal, id, "halted", 3*time.Minute)
	if halted.HaltedReason == nil || *halted.HaltedReason != "1 failed devices reached the threshold of 1" {
		t.Fatalf("halted reason %v", halted.HaltedReason)
	}
	events := rolloutEvents(t, admin.Portal, "config_rollout.halted", id)
	wantEligible := 2.0
	if cInWave {
		wantEligible = 3
	}
	if len(events) != 1 || events[0].Outcome != "success" || events[0].Actor.Type != "system" || events[0].Params["failed"] != 1.0 ||
		events[0].Params["eligible"] != wantEligible || events[0].Params["threshold"] != 1.0 {
		t.Fatalf("halted events %+v", events)
	}
	if !cInWave {
		if got := rolloutDevices(t, admin.Portal, id)[c.DeviceID]; got.InWave || got.CarriesRollout {
			t.Fatalf("device outside the wave %+v", got)
		}
	}
	if got := rolloutDevices(t, admin.Portal, id)[b.DeviceID]; got.ReportOutcome != "applied" || len(got.FailedResourceIDs) != 1 || got.FailedResourceIDs[0] != staged {
		t.Fatalf("failed device %+v", got)
	}

	res := call(t, admin.Portal, http.MethodPost, configRolloutPath(id, "resume"), nil)
	if r := configRolloutOf(t, res); r.Status != "running" {
		t.Fatalf("resumed %+v", r)
	}
	res = call(t, admin.Portal, http.MethodPost, configRolloutPath(id, "complete"), nil)
	if r := configRolloutOf(t, res); r.Status != "completed" {
		t.Fatalf("completed %+v", r)
	}
	latestBundle(t, c, 2*time.Minute, func(b *bundle.Bundle) bool { return hasResource(b, staged) })

	// The revert of the change set of a running rollout is immediate and ends it.
	second, secondChangeSet := startConfigRollout(t, admin.Portal, currentRolloutSettings(t, admin.Portal),
		"/etc/paddock-gates/m11-autostop-revert-"+suffix+".conf")
	_, hash := revertDryRun(t, admin.Portal, secondChangeSet)
	res = call(t, admin.Portal, http.MethodPost, revertPath(secondChangeSet, url.Values{"expected_plan": {hash}}), nil)
	expectStatus(t, res, http.StatusOK, "")
	ev := expectOneEvent(t, admin.Portal, res.RequestID, "config.reverted", "success")
	if ev.Params["rollout_id"] != second || ev.Params["rollout_status"] != "reverted" {
		t.Fatalf("config.reverted params %v", ev.Params)
	}
	if r := getConfigRollout(t, admin.Portal, second); r.Status != "reverted" || r.EndedAt == nil || r.EndedReason == nil {
		t.Fatalf("reverted rollout %+v", r)
	}
}
