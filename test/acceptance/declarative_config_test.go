package acceptance

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/test/acceptance/internal/env"
)

// gateOrg creates an organization of its own and a stepped-up administrator of it. A present section of a
// declarative document deletes every item it does not list, so the gates that apply documents never apply them to
// acme, where other gates create items concurrently.
func gateOrg(t *testing.T, prefix string) (*mfaUser, string) {
	t.Helper()
	root := login(t, env.PlatformAdmin)
	body := newOrg()
	res := call(t, root, http.MethodPost, "/api/platform/v1/organizations", body)
	expectStatus(t, res, http.StatusCreated, "")
	return steppedUpTempUser(t, prefix, env.RoleGroup(body["slug"], "admins")), body["slug"]
}

// configDoc is a paddock.v1 document as the admin API carries it.
type configDoc map[string]any

func getConfig(t *testing.T, p *env.Portal) configDoc {
	t.Helper()
	res := call(t, p, http.MethodGet, "/api/v1/config", nil)
	expectStatus(t, res, http.StatusOK, "")
	var doc configDoc
	if err := res.JSON(&doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

// configResult is the 200 body of PUT /api/v1/config.
type configResult struct {
	DryRun      bool    `json:"dry_run"`
	ChangeSetID *string `json:"change_set_id"`
	Plan        struct {
		Changes []struct {
			Section string `json:"section"`
			Key     string `json:"key"`
			Action  string `json:"action"`
		} `json:"changes"`
		Created int `json:"created"`
		Updated int `json:"updated"`
		Deleted int `json:"deleted"`
	} `json:"plan"`
}

func putConfig(t *testing.T, p *env.Portal, doc configDoc, dryRun bool) env.Response {
	t.Helper()
	path := "/api/v1/config"
	if dryRun {
		path += "?dry_run=true"
	}
	return call(t, p, http.MethodPut, path, doc)
}

func configResultOf(t *testing.T, res env.Response) configResult {
	t.Helper()
	expectStatus(t, res, http.StatusOK, "")
	var out configResult
	if err := res.JSON(&out); err != nil {
		t.Fatal(err)
	}
	return out
}

// expectNoEvent requires that no audit event visible to viewer carries the request's correlation ID once the audit
// pipeline settled.
func expectNoEvent(t *testing.T, viewer *env.Portal, requestID string) {
	t.Helper()
	time.Sleep(auditPollTimeout)
	events, err := viewer.AuditEvents(testContext(t, time.Minute), "")
	if err != nil {
		t.Fatal(err)
	}
	if found := env.EventsFor(events, requestID); len(found) != 0 {
		t.Fatalf("request %s recorded %+v, want no event", requestID, found)
	}
}

func clone(t *testing.T, doc configDoc) configDoc {
	t.Helper()
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	var out configDoc
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func listTotal(t *testing.T, p *env.Portal, path string) int {
	t.Helper()
	res := call(t, p, http.MethodGet, path, nil)
	expectStatus(t, res, http.StatusOK, "")
	var page struct {
		Total int `json:"total"`
	}
	if err := res.JSON(&page); err != nil {
		t.Fatal(err)
	}
	return page.Total
}

// TestDeclarativeConfig is gate T2 of plan M6c: export and re-import is an empty plan without an audit event, a
// changed document shows its creations, updates and deletions in the dry run and applies them atomically with one
// config.applied event and a change set that reaches the devices, schema violations name their path, and a full
// profile assignment sent with an API token is refused without applying anything.
func TestDeclarativeConfig(t *testing.T) {
	admin, _ := gateOrg(t, "t2-admin")

	// A package hold and an active device the document will act on.
	res := call(t, admin.Portal, http.MethodPost, "/api/v1/package-holds", map[string]any{"package": "t2-held", "reason": "gate T2"})
	expectStatus(t, res, http.StatusCreated, "")
	tok := createToken(t, admin.Portal, tokenOptions{autoApprove: true})
	dev, s := enroll(t, tok.EnrollmentConfig, "t2-"+uniqueSuffix())
	if s.Status != "active" {
		t.Fatalf("enrollment %+v", s)
	}

	doc := getConfig(t, admin.Portal)
	res = putConfig(t, admin.Portal, doc, true)
	if plan := configResultOf(t, res); len(plan.Plan.Changes) != 0 || !plan.DryRun || plan.ChangeSetID != nil {
		t.Fatalf("dry run of the export: %s", res.Body)
	}
	expectNoEvent(t, admin.Portal, res.RequestID)

	changed := clone(t, doc)
	changed["managed_files"] = append(changed["managed_files"].([]any), map[string]any{"path": "/etc/paddock-t2.conf", "content": "t2"})
	changed["settings"].(map[string]any)["updates"].(map[string]any)["security_daily_at"] = "02:45"
	changed["package_holds"] = []any{}
	res = putConfig(t, admin.Portal, changed, true)
	dry := configResultOf(t, res)
	if dry.Plan.Created != 1 || dry.Plan.Updated != 1 || dry.Plan.Deleted != 1 || len(dry.Plan.Changes) != 3 {
		t.Fatalf("dry run: %s", res.Body)
	}
	actions := map[string]string{}
	for _, c := range dry.Plan.Changes {
		actions[c.Section] = c.Action + " " + c.Key
	}
	if actions["managed_files"] != `create [null,"/etc/paddock-t2.conf"]` || actions["settings.updates"] != "update " ||
		actions["package_holds"] != `delete [null,"t2-held"]` {
		t.Fatalf("dry run changes %v", actions)
	}
	if listTotal(t, admin.Portal, "/api/v1/managed-files?q=paddock-t2") != 0 {
		t.Fatal("the dry run created the managed file")
	}

	res = putConfig(t, admin.Portal, changed, false)
	applied := configResultOf(t, res)
	if applied.DryRun || applied.ChangeSetID == nil || applied.Plan.Created != 1 {
		t.Fatalf("apply: %s", res.Body)
	}
	ev := expectOneEvent(t, admin.Portal, res.RequestID, "config.applied", "success")
	if ev.Params["change_set_id"] != *applied.ChangeSetID || ev.Target == nil || ev.Target.Type != "change_set" {
		t.Fatalf("config.applied event %+v", ev)
	}
	if listTotal(t, admin.Portal, "/api/v1/change-sets?source=session") != 1 {
		t.Fatal("the change set is not listed")
	}
	expectStatus(t, call(t, admin.Portal, http.MethodGet, "/api/v1/change-sets/"+*applied.ChangeSetID, nil), http.StatusOK, "")
	if listTotal(t, admin.Portal, "/api/v1/managed-files?q=paddock-t2") != 1 {
		t.Fatal("the managed file was not created")
	}
	if listTotal(t, admin.Portal, "/api/v1/package-holds?q=t2-held") != 0 {
		t.Fatal("the package hold was not deleted")
	}
	eff := call(t, admin.Portal, http.MethodGet, "/api/v1/devices/"+dev.DeviceID+"/effective-config", nil)
	expectStatus(t, eff, http.StatusOK, "")
	if !strings.Contains(string(eff.Body), "/etc/paddock-t2.conf") {
		t.Fatalf("effective config of the device lacks the file: %s", eff.Body)
	}

	t.Run("schema violation", func(t *testing.T) {
		bad := clone(t, changed)
		bad["managed_files"] = []any{map[string]any{"path": "/etc/paddock-t2.conf", "content": "t2", "mode": "999"}}
		res := putConfig(t, admin.Portal, bad, false)
		expectStatus(t, res, http.StatusUnprocessableEntity, "invalid_document")
		if !strings.Contains(string(res.Body), "/managed_files/0/mode") {
			t.Fatalf("detail does not name the path: %s", res.Body)
		}
		expectOneEvent(t, admin.Portal, res.RequestID, "config.applied", "failure")
		if res := putConfig(t, admin.Portal, changed, true); len(configResultOf(t, res).Plan.Changes) != 0 {
			t.Fatalf("the refused document changed something: %s", res.Body)
		}
	})

	t.Run("full profile needs a step-up", func(t *testing.T) {
		full := clone(t, changed)
		full["permission_profiles"] = []any{map[string]any{"name": "t2-root", "class": "full"}}
		full["profile_assignments"] = []any{map[string]any{"profile": "t2-root", "subject": map[string]any{"type": "global"}}}
		admin.stepUp(t)
		created := postAPIToken(t, admin.Portal, apiTokenName("t2"), "org_admin", 2*time.Hour)
		expectStatus(t, created, http.StatusCreated, "")
		removeCreated(t, admin.Portal, "/api/v1/api-tokens", created)
		var token apiTokenCreated
		if err := created.JSON(&token); err != nil {
			t.Fatal(err)
		}
		res := putConfig(t, tokenPortal(t, token.Secret), full, false)
		expectStatus(t, res, http.StatusForbidden, "step_up_required")
		expectOneEvent(t, admin.Portal, res.RequestID, "config.applied", "denied")
		if listTotal(t, admin.Portal, "/api/v1/permission-profiles?q=t2-root") != 0 {
			t.Fatal("the refused apply created the profile")
		}
		admin.stepUp(t)
		res = putConfig(t, admin.Portal, full, false)
		if out := configResultOf(t, res); out.Plan.Created != 2 {
			t.Fatalf("stepped-up apply: %s", res.Body)
		}
		expectOneEvent(t, admin.Portal, res.RequestID, "config.applied", "success")
	})

	// Review 2 of PDK-008: deleting a device group deletes its scoped items, so each must be a deletion in the plan.
	t.Run("device group deletion", func(t *testing.T) {
		seed := getConfig(t, admin.Portal)
		seed["device_groups"] = append(seed["device_groups"].([]any), map[string]any{"name": "t2-lab"})
		seed["managed_files"] = append(seed["managed_files"].([]any),
			map[string]any{"path": "/etc/paddock-t2-lab.conf", "content": "lab", "device_group": "t2-lab"})
		configResultOf(t, putConfig(t, admin.Portal, seed, false))
		doc := getConfig(t, admin.Portal)
		var keep []any
		for _, g := range doc["device_groups"].([]any) {
			if g.(map[string]any)["name"] != "t2-lab" {
				keep = append(keep, g)
			}
		}
		if keep == nil {
			keep = []any{}
		}

		// The managed files section is left out: 409 in_use, nothing changed.
		omitted := configDoc{"api_version": "paddock/v1", "kind": "OrganizationConfig", "device_groups": keep}
		res := putConfig(t, admin.Portal, omitted, false)
		expectStatus(t, res, http.StatusConflict, "in_use")
		expectOneEvent(t, admin.Portal, res.RequestID, "config.applied", "failure")
		// The section still lists the group's file: 422 invalid_document naming it.
		listed := clone(t, doc)
		listed["device_groups"] = keep
		res = putConfig(t, admin.Portal, listed, false)
		expectStatus(t, res, http.StatusUnprocessableEntity, "invalid_document")
		if !strings.Contains(string(res.Body), "/managed_files/") {
			t.Fatalf("detail does not name the file: %s", res.Body)
		}
		if listTotal(t, admin.Portal, "/api/v1/managed-files?q=paddock-t2-lab") != 1 {
			t.Fatal("a refused apply changed something")
		}

		// The section is present without the file: the plan lists both deletions and the apply runs them.
		var files []any
		for _, f := range doc["managed_files"].([]any) {
			if f.(map[string]any)["device_group"] != "t2-lab" {
				files = append(files, f)
			}
		}
		if files == nil {
			files = []any{}
		}
		listed["managed_files"] = files
		dry := configResultOf(t, putConfig(t, admin.Portal, listed, true))
		if dry.Plan.Deleted != 2 {
			t.Fatalf("plan deletes %d, want the group and its file", dry.Plan.Deleted)
		}
		res = putConfig(t, admin.Portal, listed, false)
		if out := configResultOf(t, res); out.Plan.Deleted != 2 {
			t.Fatalf("apply: %s", res.Body)
		}
		if listTotal(t, admin.Portal, "/api/v1/managed-files?q=paddock-t2-lab") != 0 {
			t.Fatal("the group's file survived")
		}
	})
}
