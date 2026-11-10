package acceptance

import (
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/test/acceptance/internal/env"
)

// openRollouts returns the IDs of p's open (running or halted) configuration rollouts.
func openRollouts(t *testing.T, p *env.Portal) []string {
	t.Helper()
	res := call(t, p, http.MethodGet, "/api/v1/config-rollouts?"+url.Values{"status": {"running", "halted"}, "page_size": {"100"}}.Encode(), nil)
	expectStatus(t, res, http.StatusOK, "")
	var page struct {
		Items []struct {
			ID string `json:"id"`
		} `json:"items"`
	}
	if err := res.JSON(&page); err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, r := range page.Items {
		ids = append(ids, r.ID)
	}
	return ids
}

// completeOnCleanup completes rollout id when the test ends, before the cleanups registered earlier run.
func completeOnCleanup(t *testing.T, p *env.Portal, id string) {
	t.Helper()
	t.Cleanup(func() {
		res := call(t, p, http.MethodPost, configRolloutPath(id, "complete"), nil)
		if res.Status != http.StatusOK && res.Status != http.StatusConflict {
			t.Errorf("cleanup: complete rollout %s: HTTP %d %s", id, res.Status, res.Body)
		}
	})
}

// removeEntryAssignments completes rollout, deletes the remaining assignments of entry (404 tolerated) and completes
// the rollouts their staged deletion opens, so that the entry can be deleted afterwards.
func removeEntryAssignments(t *testing.T, p *env.Portal, rollout, entry string) {
	t.Helper()
	complete := func(id string) {
		if res := call(t, p, http.MethodPost, configRolloutPath(id, "complete"), nil); res.Status != http.StatusOK && res.Status != http.StatusConflict {
			t.Errorf("cleanup: complete rollout %s: HTTP %d %s", id, res.Status, res.Body)
		}
	}
	complete(rollout)
	deleteEntryAssignments(t, p, entry)
	for _, id := range openRollouts(t, p) {
		complete(id)
	}
}

// catalogNames are the entry names of the exported software_catalog section.
func catalogNames(t *testing.T, p *env.Portal) []string {
	t.Helper()
	var names []string
	for _, e := range getConfig(t, p)["software_catalog"].([]any) {
		names = append(names, e.(map[string]any)["name"].(string))
	}
	return names
}

// TestSoftwareEntryDeletion is the gate of architect decisions A10-12 and A10-13 (plan M13c amendment 2026-11-09):
//   - an entry with assignments is not deleted (409 in_use naming them, audited with assignment_count), neither through
//     the API nor through a document that deletes the entry and its assignments together; without assignments it is;
//   - with rollouts on, renaming an assigned entry stages nothing (the MEDIUM rename finding);
//   - deleting the assignment is staged, and while it rolls out the entry's deletion is 409 rollout_conflict;
//   - the revert of a halted rollout whose change set created an entry and its assignment removes both (A10-13).
func TestSoftwareEntryDeletion(t *testing.T) {
	admin, _ := gateOrg(t, "m13c-entry-delete")
	p := admin.Portal
	group := namedGroup(t, p, "m13c delete")
	res := call(t, p, http.MethodGet, "/api/v1/device-groups/"+group, nil)
	expectStatus(t, res, http.StatusOK, "")
	var g struct {
		Name string `json:"name"`
	}
	if err := res.JSON(&g); err != nil {
		t.Fatal(err)
	}

	assigned := func(prefix string) (entry, assignment string) {
		res := call(t, p, http.MethodPost, softwareCatalog, entryBody(prefix))
		expectStatus(t, res, http.StatusCreated, "")
		entry = createdID(t, p, softwareCatalog, res)
		return entry, assign(t, p, map[string]any{"catalog_entry_id": entry, "device_group_id": group, "intent": "required"})
	}
	gone, goneAssignment := assigned("m13c-gone")
	renamed, renamedAssignment := assigned("m13c-renamed")

	t.Run("in use", func(t *testing.T) {
		res := call(t, p, http.MethodDelete, softwareCatalog+"/"+gone, nil)
		expectStatus(t, res, http.StatusConflict, "in_use")
		var problem struct {
			Detail string `json:"detail"`
		}
		if err := res.JSON(&problem); err != nil || !strings.Contains(problem.Detail, `device group "`+g.Name+`"`) {
			t.Fatalf("the refusal does not name the assignment's group %q: %s", g.Name, res.Body)
		}
		if ev := expectOneEvent(t, p, res.RequestID, "software_catalog_entry.deleted", "failure"); ev.Params["assignment_count"] != float64(1) {
			t.Fatalf("refusal params %v, want assignment_count 1", ev.Params)
		}

		// A document that deletes the entry together with its assignments is refused before anything is written.
		doc := getConfig(t, p)
		before := len(doc["software_assignments"].([]any))
		doc["software_catalog"], doc["software_assignments"] = []any{}, []any{}
		expectStatus(t, putConfig(t, p, doc, false), http.StatusConflict, "in_use")
		if after := getConfig(t, p); len(after["software_assignments"].([]any)) != before || !slices.Contains(catalogNames(t, p), entryName(t, p, gone)) {
			t.Fatalf("a refused document changed the configuration: %v", after)
		}

		expectStatus(t, call(t, p, http.MethodDelete, softwareAssignments+"/"+goneAssignment, nil), http.StatusNoContent, "")
		res = call(t, p, http.MethodDelete, softwareCatalog+"/"+gone, nil)
		expectStatus(t, res, http.StatusNoContent, "")
		if ev := expectOneEvent(t, p, res.RequestID, "software_catalog_entry.deleted", "success"); ev.Params["assignment_count"] != float64(0) {
			t.Fatalf("deletion params %v, want assignment_count 0", ev.Params)
		}
	})

	settings := currentRolloutSettings(t, p)
	on := map[string]any{}
	for k, v := range settings {
		on[k] = v
	}
	on["enabled"], on["waves"], on["min_wave_minutes"], on["canary_device_group_id"] = true, []int{100}, 60, nil
	on["failure_threshold_percent"], on["failure_threshold_min"] = 0, 1
	expectStatus(t, call(t, p, http.MethodPut, "/api/v1/settings/rollout", on), http.StatusOK, "")
	// Registered after the entries' cleanups, so it runs before them: their assignments are then deleted at once.
	t.Cleanup(func() {
		off := currentRolloutSettings(t, p)
		off["enabled"] = false
		if res := call(t, p, http.MethodPut, "/api/v1/settings/rollout", off); res.Status != http.StatusOK {
			t.Errorf("cleanup: rollouts off: HTTP %d %s", res.Status, res.Body)
		}
	})

	t.Run("rename stages nothing", func(t *testing.T) {
		name := entryName(t, p, renamed) + " renamed"
		res := call(t, p, http.MethodPatch, softwareCatalog+"/"+renamed, map[string]any{"name": name, "packages": entryBody("x")["packages"]})
		expectStatus(t, res, http.StatusOK, "")
		if open := openRollouts(t, p); len(open) != 0 {
			t.Fatalf("renaming an assigned entry opened rollouts %v", open)
		}
	})

	t.Run("staged removal", func(t *testing.T) {
		expectStatus(t, call(t, p, http.MethodDelete, softwareAssignments+"/"+renamedAssignment, nil), http.StatusNoContent, "")
		open := openRollouts(t, p)
		if len(open) != 1 {
			t.Fatalf("the assignment's deletion opened rollouts %v, want one", open)
		}
		completeOnCleanup(t, p, open[0])
		res := call(t, p, http.MethodDelete, softwareCatalog+"/"+renamed, nil)
		expectStatus(t, res, http.StatusConflict, "rollout_conflict")
		expectOneEvent(t, p, res.RequestID, "software_catalog_entry.deleted", "failure")
		expectStatus(t, call(t, p, http.MethodPost, configRolloutPath(open[0], "complete"), nil), http.StatusOK, "")
		expectStatus(t, call(t, p, http.MethodDelete, softwareCatalog+"/"+renamed, nil), http.StatusNoContent, "")
	})

	t.Run("revert", func(t *testing.T) {
		entry := "m13c-revert-" + uniqueSuffix()
		doc := getConfig(t, p)
		doc["software_catalog"] = append(doc["software_catalog"].([]any), map[string]any{"name": entry,
			"packages": []map[string]any{{"distribution": "ubuntu", "release": "*", "architecture": "*", "package": "nano"}}})
		doc["software_assignments"] = append(doc["software_assignments"].([]any), map[string]any{"entry": entry,
			"target": map[string]any{"type": "device_group", "name": g.Name}, "intent": "required"})
		applied := softwarePlanOf(t, putConfigOK(t, p, doc))
		if applied.Rollout == nil || *applied.Rollout != "staged" || applied.RolloutID == nil || applied.ChangeSetID == nil {
			t.Fatalf("entry and assignment in one document: %+v", applied)
		}
		rollout := *applied.RolloutID
		completeOnCleanup(t, p, rollout)
		res := call(t, p, http.MethodGet, softwareCatalog+"?q="+url.QueryEscape(entry), nil)
		expectStatus(t, res, http.StatusOK, "")
		var page struct {
			Items []struct {
				ID string `json:"id"`
			} `json:"items"`
		}
		if err := res.JSON(&page); err != nil || len(page.Items) != 1 {
			t.Fatalf("entry %s: %s", entry, res.Body)
		}
		deleteOnCleanup(t, p, softwareCatalog+"/"+page.Items[0].ID)
		// Registered after the entry's cleanup, so it runs before it: a failure before the revert leaves the
		// document's assignment, which would refuse the entry's and the group's deletion with 409.
		t.Cleanup(func() { removeEntryAssignments(t, p, rollout, page.Items[0].ID) })
		expectStatus(t, call(t, p, http.MethodDelete, softwareCatalog+"/"+page.Items[0].ID, nil), http.StatusConflict, "in_use")
		expectStatus(t, call(t, p, http.MethodPost, configRolloutPath(rollout, "halt"), map[string]string{"reason": "A10-13 gate"}), http.StatusOK, "")

		_, hash := revertDryRun(t, p, *applied.ChangeSetID)
		res = call(t, p, http.MethodPost, revertPath(*applied.ChangeSetID, url.Values{"expected_plan": {hash}}), nil)
		expectStatus(t, res, http.StatusOK, "")
		if r := getConfigRollout(t, p, rollout); r.Status != "reverted" {
			t.Fatalf("rollout after the revert %+v", r)
		}
		if slices.Contains(catalogNames(t, p), entry) {
			t.Fatalf("the revert left the entry %s", entry)
		}
		for _, a := range getConfig(t, p)["software_assignments"].([]any) {
			if a.(map[string]any)["entry"] == entry {
				t.Fatalf("the revert left the assignment %v", a)
			}
		}
	})
}

// entryName reads the name of catalog entry id.
func entryName(t *testing.T, p *env.Portal, id string) string {
	t.Helper()
	res := call(t, p, http.MethodGet, softwareCatalog+"/"+id, nil)
	expectStatus(t, res, http.StatusOK, "")
	var e struct {
		Name string `json:"name"`
	}
	if err := res.JSON(&e); err != nil {
		t.Fatal(err)
	}
	return e.Name
}

// putConfigOK applies doc and returns the 200 body.
func putConfigOK(t *testing.T, p *env.Portal, doc configDoc) []byte {
	t.Helper()
	res := putConfig(t, p, doc, false)
	expectStatus(t, res, http.StatusOK, "")
	return res.Body
}

// waitRolloutDevice polls the rollout's device list until want holds for the device.
func waitRolloutDevice(t *testing.T, p *env.Portal, rollout, device string, want func(rolloutDevice) bool) rolloutDevice {
	t.Helper()
	for deadline := time.Now().Add(3 * time.Minute); ; time.Sleep(2 * time.Second) {
		polled := time.Now()
		d := rolloutDevices(t, p, rollout)[device]
		if want(d) {
			return d
		}
		if polled.After(deadline) {
			t.Fatalf("rollout %s device %s: %+v", rollout, device, d)
		}
	}
}
