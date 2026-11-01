package acceptance

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/test/acceptance/internal/env"
)

// revertPath is POST /api/v1/change-sets/{id}/revert with its query.
func revertPath(id string, query url.Values) string {
	path := "/api/v1/change-sets/" + id + "/revert"
	if len(query) > 0 {
		path += "?" + query.Encode()
	}
	return path
}

// revertDryRun returns the inverse plan of change set id and its hash.
func revertDryRun(t *testing.T, p *env.Portal, id string) (configResult, string) {
	t.Helper()
	res := call(t, p, http.MethodPost, revertPath(id, url.Values{"dry_run": {"true"}}), nil)
	out := configResultOf(t, res)
	var hash struct {
		PlanSHA256 string `json:"plan_sha256"`
	}
	if err := res.JSON(&hash); err != nil || hash.PlanSHA256 == "" {
		t.Fatalf("dry run without plan_sha256: %s", res.Body)
	}
	return out, hash.PlanSHA256
}

// TestChangeSetRevert is the gate of plan M11 decisions 21 and 22 (PDK-155): the dry run shows the inverse plan and
// changes nothing; the revert needs the confirmed plan, restores the before-state, keeps what was created since,
// records a change set that references the original and one config.reverted event; a second revert is refused, and a
// revert that makes a profile full again needs a step-up like the apply.
func TestChangeSetRevert(t *testing.T) {
	admin, _ := gateOrg(t, "m11-revert")
	path, later := "/etc/paddock-gates/m11-revert.conf", "/etc/paddock-gates/m11-revert-later.conf"
	res := call(t, admin.Portal, http.MethodPost, "/api/v1/managed-files", map[string]any{"path": path, "content": "first\n"})
	expectStatus(t, res, http.StatusCreated, "")
	fileID := responseID(t, res).String()

	// One change set that updates the file content and creates a unit.
	doc := getConfig(t, admin.Portal)
	files, _ := doc["managed_files"].([]any)
	for _, f := range files {
		if m, ok := f.(map[string]any); ok && m["path"] == path {
			m["content"] = "second\n"
		}
	}
	units, _ := doc["managed_units"].([]any)
	doc["managed_units"] = append(units, map[string]any{"unit": "m11-revert.service", "device_group": nil, "enabled": true, "active": true})
	applied := configResultOf(t, putConfig(t, admin.Portal, doc, false))
	if applied.ChangeSetID == nil || applied.Plan.Updated != 1 || applied.Plan.Created != 1 {
		t.Fatalf("apply: %+v", applied)
	}
	original := *applied.ChangeSetID

	res = call(t, admin.Portal, http.MethodPost, "/api/v1/managed-files", map[string]any{"path": later, "content": "kept\n"})
	expectStatus(t, res, http.StatusCreated, "")

	plan, hash := revertDryRun(t, admin.Portal, original)
	actions := map[string]string{}
	for _, c := range plan.Plan.Changes {
		actions[c.Section] += c.Action
	}
	if len(plan.Plan.Changes) != 2 || actions["managed_files"] != "update" || actions["managed_units"] != "delete" || !plan.DryRun || plan.ChangeSetID != nil {
		t.Fatalf("dry run plan %+v", plan)
	}
	if got := fileContent(t, admin.Portal, fileID); got != "second\n" {
		t.Fatalf("the dry run changed the file to %q", got)
	}

	res = call(t, admin.Portal, http.MethodPost, revertPath(original, nil), nil)
	expectStatus(t, res, http.StatusBadRequest, "invalid_request")
	res = call(t, admin.Portal, http.MethodPost, revertPath(original, url.Values{"expected_plan": {strings.Repeat("0", 64)}}), nil)
	expectStatus(t, res, http.StatusPreconditionFailed, "plan_changed")
	expectOneEvent(t, admin.Portal, res.RequestID, "config.reverted", "failure")

	res = call(t, admin.Portal, http.MethodPost, revertPath(original, url.Values{"expected_plan": {hash}}), nil)
	reverted := configResultOf(t, res)
	if reverted.ChangeSetID == nil || reverted.DryRun {
		t.Fatalf("revert: %s", res.Body)
	}
	id := *reverted.ChangeSetID
	ev := expectOneEvent(t, admin.Portal, res.RequestID, "config.reverted", "success")
	if ev.Target == nil || ev.Target.Type != "change_set" || ev.Target.ID != id || ev.Params["reverts_change_set_id"] != original ||
		ev.Params["plan_sha256"] != hash || ev.Params["change_set_id"] != id || ev.Params["updated"] != float64(1) ||
		ev.Params["deleted"] != float64(1) || ev.Params["created"] != float64(0) {
		t.Fatalf("config.reverted event %+v", ev)
	}

	got := call(t, admin.Portal, http.MethodGet, "/api/v1/change-sets/"+original, nil)
	expectStatus(t, got, http.StatusOK, "")
	var cs changeSetView
	if err := got.JSON(&cs); err != nil || cs.RevertedBy == nil || *cs.RevertedBy != id {
		t.Fatalf("original change set %s", got.Body)
	}
	if c := fileContent(t, admin.Portal, fileID); c != "first\n" {
		t.Fatalf("file content %q after the revert, want the before content", c)
	}
	if listTotal(t, admin.Portal, "/api/v1/managed-files?q="+url.QueryEscape(later)) != 1 {
		t.Fatal("the file created after the original is gone")
	}
	if listTotal(t, admin.Portal, "/api/v1/managed-units?q=m11-revert.service") != 0 {
		t.Fatal("the unit the original created is still there")
	}

	res = call(t, admin.Portal, http.MethodPost, revertPath(original, url.Values{"expected_plan": {hash}}), nil)
	expectStatus(t, res, http.StatusConflict, "invalid_state")
	if !strings.Contains(string(res.Body), "already reverted by "+id) {
		t.Fatalf("second revert: %s", res.Body)
	}
	expectOneEvent(t, admin.Portal, res.RequestID, "config.reverted", "failure")

	t.Run("a revert that makes a profile full again needs a step-up", func(t *testing.T) {
		admin.stepUp(t)
		res := call(t, admin.Portal, http.MethodPost, "/api/v1/permission-profiles", map[string]any{"name": uniqueName("m11 revert full"), "class": "full"})
		expectStatus(t, res, http.StatusCreated, "")
		prof := responseID(t, res).String()
		res = call(t, admin.Portal, http.MethodPatch, "/api/v1/permission-profiles/"+prof,
			map[string]any{"class": "restricted", "commands": []string{"/usr/bin/true"}})
		expectStatus(t, res, http.StatusOK, "")
		ev := expectOneEvent(t, admin.Portal, res.RequestID, "permission_profile.updated", "success")
		changed, _ := ev.Params["change_set_id"].(string)
		if changed == "" {
			t.Fatalf("permission_profile.updated carries no change_set_id: %+v", ev.Params)
		}
		admin.stepUp(t)
		_, hash := revertDryRun(t, admin.Portal, changed)

		created := postAPIToken(t, admin.Portal, apiTokenName("m11-revert"), "org_admin", 2*time.Hour)
		expectStatus(t, created, http.StatusCreated, "")
		removeCreated(t, admin.Portal, "/api/v1/api-tokens", created)
		var token apiTokenCreated
		if err := created.JSON(&token); err != nil {
			t.Fatal(err)
		}
		res = call(t, tokenPortal(t, token.Secret), http.MethodPost, revertPath(changed, url.Values{"expected_plan": {hash}}), nil)
		expectStatus(t, res, http.StatusForbidden, "step_up_required")
		expectOneEvent(t, admin.Portal, res.RequestID, "config.reverted", "denied")

		admin.stepUp(t)
		res = call(t, admin.Portal, http.MethodPost, revertPath(changed, url.Values{"expected_plan": {hash}}), nil)
		if out := configResultOf(t, res); out.ChangeSetID == nil {
			t.Fatalf("stepped-up revert: %s", res.Body)
		}
		expectOneEvent(t, admin.Portal, res.RequestID, "config.reverted", "success")
	})
}

// fileContent is the content of managed file id.
func fileContent(t *testing.T, p *env.Portal, id string) string {
	t.Helper()
	res := call(t, p, http.MethodGet, "/api/v1/managed-files/"+id, nil)
	expectStatus(t, res, http.StatusOK, "")
	var f struct {
		Content string `json:"content"`
	}
	if err := res.JSON(&f); err != nil {
		t.Fatal(err)
	}
	return f.Content
}

// holdChangeSet changes the reason of a new package hold of acme and returns the change set of that update.
func holdChangeSet(t *testing.T, w *auditWorld) string {
	t.Helper()
	_, hold := holdIn(t, w, "a3-revert-"+uniqueSuffix(), "")
	res := call(t, w.alice, http.MethodPatch, "/api/v1/package-holds/"+hold, map[string]any{"version": nil, "reason": "a3 revert"})
	expectStatus(t, res, http.StatusOK, "")
	ev := expectOneEvent(t, w.alice, res.RequestID, "package_hold.updated", "success")
	id, _ := ev.Params["change_set_id"].(string)
	if id == "" {
		t.Fatalf("package_hold.updated carries no change_set_id: %+v", ev.Params)
	}
	return id
}

// revertCases are the A3 cases of POST /api/v1/change-sets/{id}/revert. Each reverts the change set of its own hold, so
// the cases run in parallel with the others.
func revertCases() []auditCase {
	const code = "config.reverted"
	return []auditCase{
		{"success", func(t *testing.T, w *auditWorld) {
			id := holdChangeSet(t, w)
			_, hash := revertDryRun(t, w.alice, id)
			res := call(t, w.alice, http.MethodPost, revertPath(id, url.Values{"expected_plan": {hash}}), nil)
			expectStatus(t, res, http.StatusOK, "")
			expectOneEvent(t, w.alice, res.RequestID, code, "success")
		}},
		{"validation failure", func(t *testing.T, w *auditWorld) {
			res := call(t, w.alice, http.MethodPost, revertPath(holdChangeSet(t, w), nil), nil)
			expectStatus(t, res, http.StatusBadRequest, "invalid_request")
			expectOneEvent(t, w.alice, res.RequestID, code, "failure")
		}},
		{"wrong role", func(t *testing.T, w *auditWorld) {
			res := call(t, w.bob, http.MethodPost, revertPath(holdChangeSet(t, w), url.Values{"expected_plan": {strings.Repeat("0", 64)}}), nil)
			expectStatus(t, res, http.StatusForbidden, "forbidden")
			expectOneEvent(t, w.alice, res.RequestID, code, "denied")
		}},
		{"not found", func(t *testing.T, w *auditWorld) {
			res := call(t, w.alice, http.MethodPost, revertPath(uuid.NewString(), url.Values{"expected_plan": {strings.Repeat("0", 64)}}), nil)
			expectStatus(t, res, http.StatusNotFound, "not_found")
			expectOneEvent(t, w.alice, res.RequestID, code, "failure")
		}},
		{"plan changed", func(t *testing.T, w *auditWorld) {
			res := call(t, w.alice, http.MethodPost, revertPath(holdChangeSet(t, w), url.Values{"expected_plan": {strings.Repeat("0", 64)}}), nil)
			expectStatus(t, res, http.StatusPreconditionFailed, "plan_changed")
			expectOneEvent(t, w.alice, res.RequestID, code, "failure")
		}},
	}
}

func init() {
	auditCases["POST /api/v1/change-sets/{id}/revert"] = revertCases()
}
