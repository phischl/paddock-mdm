package admin_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/phischl/paddock-mdm/server/internal/platform/httpx"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/transport/http/admin/adminapi"
)

// TestDeclarativeConfigEndpoints covers plan M6c decisions 16–18 over HTTP: the export keeps the key order of the
// schema, dry runs change and record nothing, schema violations are 422 invalid_document with their paths, oversized
// bodies are refused and recorded once, and applies produce change sets the auditor reads.
func TestDeclarativeConfigEndpoints(t *testing.T) {
	e := newEnv(t)
	alice := e.session(e.acme, principal.RoleOrgAdmin)
	auditor := e.session(e.acme, principal.RoleOrgAuditor)

	r := e.do(call{method: "GET", path: "/api/v1/config", cookie: auditor})
	if r.status != http.StatusOK {
		t.Fatalf("export: %d %s", r.status, r.body)
	}
	body := string(r.body)
	order := []string{`"api_version"`, `"kind"`, `"settings"`, `"login"`, `"updates"`, `"device_groups"`, `"permission_profiles"`,
		`"managed_files"`, `"managed_units"`, `"package_holds"`, `"profile_assignments"`}
	last := -1
	for _, k := range order {
		i := strings.Index(body, k)
		if i <= last {
			t.Fatalf("key %s out of order in %s", k, body)
		}
		last = i
	}
	var doc map[string]any
	r.decode(t, &doc)

	r = e.do(call{method: "PUT", path: "/api/v1/config?dry_run=true", cookie: alice, body: doc})
	var res adminapi.ConfigApplyResult
	r.decode(t, &res)
	if r.status != http.StatusOK || !res.DryRun || res.ChangeSetId != nil || len(res.Plan.Changes) != 0 {
		t.Fatalf("dry run of the export: %d %s", r.status, r.body)
	}
	if ev := e.events(r.header.Get(httpx.HeaderRequestID)); len(ev) != 0 {
		t.Fatalf("dry run recorded %v", ev)
	}

	doc["device_groups"] = []any{map[string]any{"name": "from config"}}
	r = e.do(call{method: "PUT", path: "/api/v1/config?dry_run=true", cookie: alice, body: doc})
	r.decode(t, &res)
	if res.Plan.Created != 1 || len(res.Plan.Changes) != 1 || res.Plan.Changes[0].Key != `["from config"]` {
		t.Fatalf("dry run plan %s", r.body)
	}
	if ev := e.events(r.header.Get(httpx.HeaderRequestID)); len(ev) != 0 {
		t.Fatalf("dry run recorded %v", ev)
	}

	confirmed := res.PlanSha256
	if len(confirmed) != 64 {
		t.Fatalf("plan_sha256 %q", confirmed)
	}
	// expected_plan (plan M6c amendment 2026-10-08): another plan is refused with 412 and applies nothing.
	r = e.do(call{method: "PUT", path: "/api/v1/config?expected_plan=" + strings.Repeat("0", 64), cookie: alice, body: doc})
	if r.status != http.StatusPreconditionFailed || r.problemCode(t) != "plan_changed" {
		t.Fatalf("other plan: %d %s", r.status, r.body)
	}
	e.expectEvent(r, "config.applied:failure:plan_changed")
	r = e.do(call{method: "PUT", path: "/api/v1/config?expected_plan=XYZ", cookie: alice, body: doc, skipReqCheck: true})
	if r.status != http.StatusBadRequest || r.problemCode(t) != "invalid_request" {
		t.Fatalf("malformed expected_plan: %d %s", r.status, r.body)
	}
	r = e.do(call{method: "PUT", path: "/api/v1/config?expected_plan=" + confirmed, cookie: alice, body: doc})
	r.decode(t, &res)
	if r.status != http.StatusOK || res.DryRun || res.ChangeSetId == nil || res.Plan.Created != 1 || res.PlanSha256 != confirmed {
		t.Fatalf("apply: %d %s", r.status, r.body)
	}
	e.expectEvent(r, "config.applied:success:")
	cs := e.do(call{method: "GET", path: "/api/v1/change-sets/" + res.ChangeSetId.String(), cookie: auditor})
	var set adminapi.ChangeSet
	cs.decode(t, &set)
	if cs.status != http.StatusOK || set.Source != adminapi.ChangeSetSourceSession || set.Summary.Created != 1 ||
		set.Actor.Display != "org_admin@test" || len(set.Plan.Changes) != 1 {
		t.Fatalf("change set: %d %s", cs.status, cs.body)
	}
	list := e.do(call{method: "GET", path: "/api/v1/change-sets?source=session&q=org_admin&sort=applied_at", cookie: auditor})
	var page adminapi.ChangeSetPage
	list.decode(t, &page)
	if list.status != http.StatusOK || page.Total != 1 || page.Items[0].Id != *res.ChangeSetId {
		t.Fatalf("change sets: %d %s", list.status, list.body)
	}
	carol := e.session(e.globex, principal.RoleOrgAdmin)
	if r := e.do(call{method: "GET", path: "/api/v1/change-sets/" + res.ChangeSetId.String(), cookie: carol}); r.status != http.StatusNotFound {
		t.Fatalf("foreign change set: %d", r.status)
	}

	files := []any{map[string]any{"path": "/etc/motd", "content": "x", "mode": "999"}}
	doc["managed_files"] = files
	r = e.do(call{method: "PUT", path: "/api/v1/config", cookie: alice, body: doc})
	if r.status != http.StatusUnprocessableEntity || r.problemCode(t) != "invalid_document" || !strings.Contains(string(r.body), "/managed_files/0/mode") {
		t.Fatalf("schema violation: %d %s", r.status, r.body)
	}
	e.expectEvent(r, "config.applied:failure:invalid_document")

	if r := e.do(call{method: "PUT", path: "/api/v1/config", cookie: auditor, body: doc}); r.status != http.StatusForbidden {
		t.Fatalf("auditor apply: %d", r.status)
	} else {
		e.expectEvent(r, "config.applied:denied:forbidden")
	}

	big, _ := json.Marshal(map[string]any{"api_version": "paddock/v1", "kind": "OrganizationConfig",
		"managed_files": []any{map[string]any{"path": "/etc/big", "content": strings.Repeat("a", 1<<20)}}})
	r = e.do(call{method: "PUT", path: "/api/v1/config?dry_run=true", cookie: alice, rawBody: string(big), skipReqCheck: true})
	if r.status != http.StatusBadRequest || r.problemCode(t) != "invalid_request" {
		t.Fatalf("oversized body: %d %s", r.status, r.body)
	}
	e.expectEvent(r, "config.applied:failure:invalid_request")

	r = e.do(call{method: "PUT", path: "/api/v1/config?dry_run=maybe", cookie: alice, body: doc, skipReqCheck: true})
	if r.status != http.StatusBadRequest {
		t.Fatalf("dry_run=maybe: %d %s", r.status, r.body)
	}
	r = e.do(call{method: "PUT", path: "/api/v1/config", cookie: alice, body: doc, noCSRF: true, skipReqCheck: true})
	if r.status != http.StatusForbidden || r.problemCode(t) != "csrf_missing" {
		t.Fatalf("without CSRF: %d %s", r.status, r.body)
	}
	e.expectEvent(r, "config.applied:denied:csrf_missing")
}
