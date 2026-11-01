package acceptance

import (
	"hash/fnv"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/pkg/bundle"
	"github.com/phischl/paddock-mdm/test/acceptance/devicesim"
	"github.com/phischl/paddock-mdm/test/acceptance/internal/env"
)

// configRolloutBucket is the bucket of a device in a configuration rollout, computed as the server's
// configrollout.Bucket (plan M11 decision 28): FNV-1a (32 bit) of "<device>:<rollout>" modulo 100.
func configRolloutBucket(device, rollout string) int {
	h := fnv.New32a()
	_, _ = h.Write([]byte(device + ":" + rollout))
	return int(h.Sum32() % 100)
}

// stagedResult is the part of ConfigApplyResult the staging gate reads.
type stagedResult struct {
	ChangeSetID *string `json:"change_set_id"`
	Rollout     *string `json:"rollout"`
	RolloutID   *string `json:"rollout_id"`
}

func stagedResultOf(t *testing.T, res env.Response) stagedResult {
	t.Helper()
	expectStatus(t, res, http.StatusOK, "")
	var out stagedResult
	if err := res.JSON(&out); err != nil {
		t.Fatal(err)
	}
	return out
}

// withFile returns doc with one more managed file for every device.
func withFile(doc configDoc, path, content string) configDoc {
	files, _ := doc["managed_files"].([]any)
	doc["managed_files"] = append(files, map[string]any{"path": path, "device_group": nil, "mode": "0644", "owner": "root",
		"group": "root", "content": content})
	return doc
}

// hasResource reports whether b has the resource id.
func hasResource(b *bundle.Bundle, id string) bool {
	for _, r := range b.Resources {
		if r.ID == id {
			return true
		}
	}
	return false
}

// TestConfigRolloutStaging is the gate of plan M11 decisions 25-31 (PDK-157, §8): with rollouts enabled a managed file
// apply is staged; the canary device and the devices whose bucket is inside the first wave receive the file and their
// bundle rows carry the rollout, the others keep the before-state. While the rollout is open a change of the staged
// file is rollout_conflict, a second staged file rollout_running, and an unrelated unit is immediate and reaches every
// device. The urgent opt-out needs a reason and a step-up and then reaches every device.
func TestConfigRolloutStaging(t *testing.T) {
	admin, slug := gateOrg(t, "m11-staging")
	suffix := uniqueSuffix()
	canary := namedGroup(t, admin.Portal, "staging canary")
	devices := []*devicesim.Device{
		activeDevice(t, admin.Portal, canary, "stg-a-"+suffix),
		activeDevice(t, admin.Portal, "", "stg-b-"+suffix),
		activeDevice(t, admin.Portal, "", "stg-c-"+suffix),
	}
	for _, d := range devices {
		waitBundleVersion(t, admin.Portal, d.DeviceID)
	}
	res := call(t, admin.Portal, http.MethodPut, "/api/v1/settings/rollout", map[string]any{
		"enabled": true, "waves": []int{50, 100}, "min_wave_minutes": 60, "failure_threshold_percent": 2,
		"failure_threshold_min": 3, "canary_device_group_id": canary,
	})
	expectStatus(t, res, http.StatusOK, "")

	staged := "/etc/paddock-gates/m11-staged-" + suffix + ".conf"
	res = putConfig(t, admin.Portal, withFile(getConfig(t, admin.Portal), staged, "staged\n"), false)
	applied := stagedResultOf(t, res)
	if applied.Rollout == nil || *applied.Rollout != "staged" || applied.RolloutID == nil || applied.ChangeSetID == nil {
		t.Fatalf("staged apply: %s", res.Body)
	}
	rollout := *applied.RolloutID
	// The rollout must end before the canary group's cleanup deletes the group (R6.13 refuses that while it is open);
	// cleanups run last-in first-out, so this one runs first.
	stagedChangeSet := *applied.ChangeSetID
	t.Cleanup(func() {
		_, hash := revertDryRun(t, admin.Portal, stagedChangeSet)
		res := call(t, admin.Portal, http.MethodPost, revertPath(stagedChangeSet, url.Values{"expected_plan": {hash}}), nil)
		if res.Status != http.StatusOK {
			t.Errorf("cleanup: revert the staged change set %s: HTTP %d %s", stagedChangeSet, res.Status, res.Body)
		}
	})
	ev := expectOneEvent(t, admin.Portal, res.RequestID, "config.applied", "success")
	if ev.Params["rollout"] != "staged" || ev.Params["rollout_id"] != rollout {
		t.Fatalf("config.applied params %v", ev.Params)
	}
	got := call(t, admin.Portal, http.MethodGet, "/api/v1/change-sets/"+*applied.ChangeSetID, nil)
	expectStatus(t, got, http.StatusOK, "")
	var cs struct {
		Rollout   string  `json:"rollout"`
		RolloutID *string `json:"rollout_id"`
	}
	if err := got.JSON(&cs); err != nil || cs.Rollout != "staged" || cs.RolloutID == nil || *cs.RolloutID != rollout {
		t.Fatalf("change set %s", got.Body)
	}

	inWave := make([]bool, len(devices))
	for i, d := range devices {
		inWave[i] = i == 0 || configRolloutBucket(d.DeviceID, rollout) < 50
		eff := call(t, admin.Portal, http.MethodGet, "/api/v1/devices/"+d.DeviceID+"/effective-config", nil)
		expectStatus(t, eff, http.StatusOK, "")
		var cfg struct {
			Rollout *struct {
				ID     string `json:"id"`
				InWave bool   `json:"in_wave"`
			} `json:"rollout"`
		}
		if err := eff.JSON(&cfg); err != nil || cfg.Rollout == nil || cfg.Rollout.ID != rollout || cfg.Rollout.InWave != inWave[i] {
			t.Fatalf("effective config of device %d: %s", i, eff.Body)
		}
		if !inWave[i] {
			continue
		}
		latestBundle(t, d, 2*time.Minute, func(b *bundle.Bundle) bool { return hasResource(b, "file:"+staged) })
		bundles := call(t, admin.Portal, http.MethodGet, "/api/v1/devices/"+d.DeviceID+"/bundles?sort=-version&page_size=10", nil)
		expectStatus(t, bundles, http.StatusOK, "")
		var page struct {
			Items []struct {
				ConfigRolloutID *string `json:"config_rollout_id"`
			} `json:"items"`
		}
		if err := bundles.JSON(&page); err != nil || len(page.Items) == 0 || page.Items[0].ConfigRolloutID == nil || *page.Items[0].ConfigRolloutID != rollout {
			t.Fatalf("bundles of device %d in the wave: %s", i, bundles.Body)
		}
	}

	// While the rollout is open: the staged file is refused, a second staged file too, an unrelated unit is immediate.
	doc := getConfig(t, admin.Portal)
	files, _ := doc["managed_files"].([]any)
	for _, f := range files {
		if m, ok := f.(map[string]any); ok && m["path"] == staged {
			m["content"] = "changed\n"
		}
	}
	res = putConfig(t, admin.Portal, doc, false)
	expectStatus(t, res, http.StatusConflict, "rollout_conflict")
	expectOneEvent(t, admin.Portal, res.RequestID, "config.applied", "failure")
	res = putConfig(t, admin.Portal, withFile(getConfig(t, admin.Portal), "/etc/paddock-gates/m11-second-"+suffix+".conf", "x\n"), false)
	expectStatus(t, res, http.StatusConflict, "rollout_running")
	expectOneEvent(t, admin.Portal, res.RequestID, "config.applied", "failure")

	unit := "m11-unrelated-" + suffix + ".service"
	doc = getConfig(t, admin.Portal)
	units, _ := doc["managed_units"].([]any)
	doc["managed_units"] = append(units, map[string]any{"unit": unit, "device_group": nil, "enabled": true, "active": true})
	if r := stagedResultOf(t, putConfig(t, admin.Portal, doc, false)); r.Rollout == nil || *r.Rollout != "immediate" || r.RolloutID != nil {
		t.Fatalf("unrelated unit: %+v", r)
	}
	for i, d := range devices {
		b := latestBundle(t, d, 2*time.Minute, func(b *bundle.Bundle) bool { return hasResource(b, "unit:"+unit) })
		if hasResource(b, "file:"+staged) != inWave[i] {
			t.Fatalf("device %d (in wave %v): staged file present %v", i, inWave[i], !inWave[i])
		}
	}

	// The urgent opt-out: a reason, then a step-up; then every device gets the change.
	urgentFile := "/etc/paddock-gates/m11-urgent-" + suffix + ".conf"
	urgentPath := func(q url.Values) string { return "/api/v1/config?" + q.Encode() }
	res = call(t, admin.Portal, http.MethodPut, urgentPath(url.Values{"urgent": {"true"}}), withFile(getConfig(t, admin.Portal), urgentFile, "u\n"))
	expectStatus(t, res, http.StatusBadRequest, "invalid_request")
	expectOneEvent(t, admin.Portal, res.RequestID, "config.applied", "failure")
	plain := mfaTempUser(t, "m11-nostepup", env.RoleGroup(slug, "admins"))
	res = call(t, plain.Portal, http.MethodPut, urgentPath(url.Values{"urgent": {"true"}, "reason": {"broken motd"}}),
		withFile(getConfig(t, plain.Portal), urgentFile, "u\n"))
	expectStatus(t, res, http.StatusForbidden, "step_up_required")
	expectOneEvent(t, admin.Portal, res.RequestID, "config.applied", "denied")
	admin.stepUp(t)
	res = call(t, admin.Portal, http.MethodPut, urgentPath(url.Values{"urgent": {"true"}, "reason": {"broken motd"}}),
		withFile(getConfig(t, admin.Portal), urgentFile, "u\n"))
	urgent := stagedResultOf(t, res)
	if urgent.Rollout == nil || *urgent.Rollout != "urgent" || urgent.RolloutID != nil || urgent.ChangeSetID == nil {
		t.Fatalf("urgent apply: %s", res.Body)
	}
	ev = expectOneEvent(t, admin.Portal, res.RequestID, "config.applied", "success")
	if ev.Params["rollout"] != "urgent" || ev.Params["urgent_reason"] != "broken motd" {
		t.Fatalf("urgent params %v", ev.Params)
	}
	got = call(t, admin.Portal, http.MethodGet, "/api/v1/change-sets/"+*urgent.ChangeSetID, nil)
	var urgentCS struct {
		Rollout      string  `json:"rollout"`
		UrgentReason *string `json:"urgent_reason"`
	}
	if err := got.JSON(&urgentCS); err != nil || urgentCS.Rollout != "urgent" || urgentCS.UrgentReason == nil || *urgentCS.UrgentReason != "broken motd" {
		t.Fatalf("urgent change set %s", got.Body)
	}
	for _, d := range devices {
		latestBundle(t, d, 2*time.Minute, func(b *bundle.Bundle) bool { return hasResource(b, "file:"+urgentFile) })
	}
}
