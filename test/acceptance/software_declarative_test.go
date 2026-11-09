package acceptance

import (
	"encoding/json"
	"net/http"
	"net/url"
	"slices"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/pkg/bundle"
	"github.com/phischl/paddock-mdm/pkg/protocol"
)

// softwarePlan is the part of ConfigApplyResult the software gates read.
type softwarePlan struct {
	ChangeSetID *string `json:"change_set_id"`
	Rollout     *string `json:"rollout"`
	RolloutID   *string `json:"rollout_id"`
	Plan        struct {
		Created        int      `json:"created"`
		Updated        int      `json:"updated"`
		Deleted        int      `json:"deleted"`
		RequiresStepUp []string `json:"requires_step_up"`
	} `json:"plan"`
}

func softwarePlanOf(t *testing.T, body []byte) softwarePlan {
	t.Helper()
	var out softwarePlan
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// TestSoftwareDeclarative is the gate of plan M13c decisions 1 and 2: the three software sections export and apply
// through PUT /api/v1/config; a plan with a source change shows requires_step_up in the dry run, is refused for an API
// token with 403 step_up_required (audited, nothing applied) and applied by an administrator with a step-up; without
// a source change the token applies.
func TestSoftwareDeclarative(t *testing.T) {
	admin, _ := gateOrg(t, "m13c-declarative")
	suffix := uniqueSuffix()
	slug, entry := "m13c-"+suffix, "M13c browser "+suffix
	doc := getConfig(t, admin.Portal)
	for _, s := range []string{"software_sources", "software_catalog", "software_assignments"} {
		if _, ok := doc[s]; !ok {
			t.Fatalf("export without %s: %v", s, doc)
		}
	}
	doc["software_sources"] = []any{map[string]any{"slug": slug, "name": "Vendor " + suffix, "uris": []string{"https://apt.gates.example/"},
		"suites": []string{"stable"}, "components": []string{"main"}, "signing_key": gateSourceKey, "fingerprint": gateSourceFP}}
	doc["software_catalog"] = []any{map[string]any{"name": entry, "source": slug,
		"packages": []map[string]any{{"distribution": "ubuntu", "release": "*", "architecture": "*", "package": "nano"}}}}
	doc["software_assignments"] = []any{map[string]any{"entry": entry, "target": map[string]any{"type": "organization"}, "intent": "required"}}

	res := putConfig(t, admin.Portal, doc, true)
	expectStatus(t, res, http.StatusOK, "")
	if p := softwarePlanOf(t, res.Body); p.Plan.Created != 3 || !slices.Equal(p.Plan.RequiresStepUp, []string{"software_sources"}) {
		t.Fatalf("dry run %s", res.Body)
	}

	admin.stepUp(t)
	token := tokenPortal(t, createAPIToken(t, admin.Portal, admin.username, "org_admin").Secret)
	res = putConfig(t, token, doc, true)
	expectStatus(t, res, http.StatusOK, "")
	if p := softwarePlanOf(t, res.Body); !slices.Equal(p.Plan.RequiresStepUp, []string{"software_sources"}) {
		t.Fatalf("token dry run %s", res.Body)
	}
	res = putConfig(t, token, doc, false)
	expectStatus(t, res, http.StatusForbidden, "step_up_required")
	expectOneEvent(t, admin.Portal, res.RequestID, "config.applied", "denied")
	if got := getConfig(t, admin.Portal)["software_sources"].([]any); len(got) != 0 {
		t.Fatalf("a refused apply created sources: %v", got)
	}

	admin.stepUp(t)
	res = putConfig(t, admin.Portal, doc, false)
	expectStatus(t, res, http.StatusOK, "")
	if p := softwarePlanOf(t, res.Body); p.Plan.Created != 3 || p.ChangeSetID == nil {
		t.Fatalf("apply %s", res.Body)
	}
	expectOneEvent(t, admin.Portal, res.RequestID, "config.applied", "success")
	exported := getConfig(t, admin.Portal)
	srcs := exported["software_sources"].([]any)
	if len(srcs) != 1 || srcs[0].(map[string]any)["fingerprint"] != gateSourceFP || srcs[0].(map[string]any)["signing_key"] == "" {
		t.Fatalf("exported sources %v", srcs)
	}
	res = putConfig(t, admin.Portal, exported, true)
	expectStatus(t, res, http.StatusOK, "")
	if p := softwarePlanOf(t, res.Body); p.Plan.Created+p.Plan.Updated+p.Plan.Deleted != 0 || p.Plan.RequiresStepUp != nil {
		t.Fatalf("export again %s", res.Body)
	}

	// The two-step: CI changes the assignment with its token, the source stays with the portal.
	exported["software_assignments"].([]any)[0].(map[string]any)["intent"] = "available"
	res = putConfig(t, token, exported, false)
	expectStatus(t, res, http.StatusOK, "")
	if p := softwarePlanOf(t, res.Body); p.Plan.Updated != 1 {
		t.Fatalf("token apply %s", res.Body)
	}
}

// TestSoftwareRollout is the gate of ADR 0033 amendment 2026-11-05: with rollouts enabled a catalog entry is
// immediate and an assignment change is staged; a device outside the wave keeps the before assignment; a failed
// software status of the staged entry on a device of the wave halts the rollout; the revert of the change set ends it.
func TestSoftwareRollout(t *testing.T) {
	admin, _ := gateOrg(t, "m13c-rollout")
	suffix := uniqueSuffix()
	canary := namedGroup(t, admin.Portal, "m13c canary")
	a := activeDevice(t, admin.Portal, canary, "swr-a-"+suffix)
	c := activeDevice(t, admin.Portal, "", "swr-c-"+suffix)
	for _, d := range []string{a.DeviceID, c.DeviceID} {
		waitBundleVersion(t, admin.Portal, d)
	}
	expectStatus(t, call(t, admin.Portal, http.MethodPut, "/api/v1/settings/rollout", map[string]any{
		"enabled": true, "waves": []int{1, 100}, "min_wave_minutes": 60, "failure_threshold_percent": 0,
		"failure_threshold_min": 1, "canary_device_group_id": canary,
	}), http.StatusOK, "")

	entry := "M13c rollout " + suffix
	doc := getConfig(t, admin.Portal)
	doc["software_catalog"] = []any{map[string]any{"name": entry,
		"packages": []map[string]any{{"distribution": "ubuntu", "release": "*", "architecture": "*", "package": "nano"}}}}
	res := putConfig(t, admin.Portal, doc, false)
	expectStatus(t, res, http.StatusOK, "")
	if p := softwarePlanOf(t, res.Body); p.Rollout == nil || *p.Rollout != "immediate" {
		t.Fatalf("catalog entry %s", res.Body)
	}
	doc = getConfig(t, admin.Portal)
	doc["software_assignments"] = []any{map[string]any{"entry": entry, "target": map[string]any{"type": "organization"}, "intent": "required"}}
	res = putConfig(t, admin.Portal, doc, false)
	expectStatus(t, res, http.StatusOK, "")
	applied := softwarePlanOf(t, res.Body)
	if applied.Rollout == nil || *applied.Rollout != "staged" || applied.RolloutID == nil || applied.ChangeSetID == nil {
		t.Fatalf("assignment %s", res.Body)
	}
	rollout, changeSet := *applied.RolloutID, *applied.ChangeSetID
	t.Cleanup(func() {
		res := call(t, admin.Portal, http.MethodPost, configRolloutPath(rollout, "complete"), nil)
		if res.Status != http.StatusOK && res.Status != http.StatusConflict {
			t.Errorf("cleanup: complete rollout %s: HTTP %d %s", rollout, res.Status, res.Body)
		}
	})
	res = call(t, admin.Portal, http.MethodGet, softwareCatalog+"?q="+url.QueryEscape(entry), nil)
	expectStatus(t, res, http.StatusOK, "")
	var page struct {
		Items []struct {
			ID string `json:"id"`
		} `json:"items"`
	}
	if err := res.JSON(&page); err != nil || len(page.Items) != 1 {
		t.Fatalf("entry %s", res.Body)
	}
	entryID := page.Items[0].ID
	staged := "software:" + entryID
	detail := call(t, admin.Portal, http.MethodGet, configRolloutPath(rollout, ""), nil)
	expectStatus(t, detail, http.StatusOK, "")
	var stagedIDs struct {
		StagedResourceIDs []string `json:"staged_resource_ids"`
	}
	if err := detail.JSON(&stagedIDs); err != nil || !slices.Equal(stagedIDs.StagedResourceIDs, []string{staged}) {
		t.Fatalf("rollout %s", detail.Body)
	}

	hasNano := func(b *bundle.Bundle) bool {
		if b.Software == nil {
			return false
		}
		return slices.ContainsFunc(b.Software.Packages, func(p bundle.SoftwarePackage) bool { return p.CatalogEntryID == entryID })
	}
	ba := latestBundle(t, a, 2*time.Minute, hasNano)
	if configRolloutBucket(c.DeviceID, rollout) >= 1 {
		if hasNano(latestBundle(t, c, 2*time.Minute, func(*bundle.Bundle) bool { return true })) {
			t.Fatal("a device outside the wave received the staged assignment")
		}
	}
	sendBundleEvent(t, a, 1, protocol.EventBundleApplied, map[string]any{
		"version": ba.BundleVersion, "changed": 1, "mode": "enforce", "errors": []map[string]string{},
		"resources": []map[string]any{{"id": bundle.TypeSoftware, "status": "applied"}},
	})
	requireSingleService(t, testContext(t, time.Minute), "paddock-worker")
	health, err := json.Marshal(map[string]any{"reconcile": "ok", "software": map[string]any{"digest": "m13c-" + suffix,
		"items": []map[string]any{{"id": entryID, "package": "nano", "intent": "required", "state": "failed", "error": "apt-get failed"}}}})
	if err != nil {
		t.Fatal(err)
	}
	valkeyCLI(t, "worker", "DEL hb:"+a.DeviceID)
	a.Health = health
	if _, res, err := a.Checkin(testContext(t, time.Minute)); err != nil || res.Status != http.StatusOK {
		t.Fatalf("check-in: %v %d %s", err, res.Status, res.Body)
	}
	halted := waitConfigRolloutStatus(t, admin.Portal, rollout, "halted", 3*time.Minute)
	if halted.HaltedReason == nil || *halted.HaltedReason != "1 failed devices reached the threshold of 1" {
		t.Fatalf("halted reason %v", halted.HaltedReason)
	}
	if got := rolloutDevices(t, admin.Portal, rollout)[a.DeviceID]; !slices.Contains(got.FailedResourceIDs, staged) {
		t.Fatalf("failed device %+v", got)
	}

	_, hash := revertDryRun(t, admin.Portal, changeSet)
	res = call(t, admin.Portal, http.MethodPost, revertPath(changeSet, url.Values{"expected_plan": {hash}}), nil)
	expectStatus(t, res, http.StatusOK, "")
	if r := getConfigRollout(t, admin.Portal, rollout); r.Status != "reverted" {
		t.Fatalf("rollout after the revert %+v", r)
	}
	if got := getConfig(t, admin.Portal)["software_assignments"].([]any); len(got) != 0 {
		t.Fatalf("assignments after the revert %v", got)
	}
}
