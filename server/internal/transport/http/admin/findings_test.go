package admin_test

import (
	"context"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/transport/http/admin/adminapi"
)

// insertFinding stores a live finding of a device as the worker would.
func (e *env) insertFinding(org, device uuid.UUID, kind, key, code, subject string) uuid.UUID {
	e.t.Helper()
	id := uuid.Must(uuid.NewV7())
	if _, err := e.super.Exec(context.Background(), `INSERT INTO finding (id, organization_id, kind, key, device_id, code, subject, status,
		opened_at, last_seen_at) VALUES ($1, $2, $3, $4, $5, $6, $7, 'open', now(), now())`, id, org, kind, key, device, code, subject); err != nil {
		e.t.Fatal(err)
	}
	return id
}

// TestFindingsAPI (N9, plan M9 decision 34): the findings list contract and the four verbs over HTTP with their
// events, the account list of the assignee picker, the finding of an attention condition in both attention lists,
// and 404 for another organization.
func TestFindingsAPI(t *testing.T) {
	e := newEnv(t)
	operator := e.session(e.acme, principal.RoleOrgOperator)
	admin := e.session(e.acme, principal.RoleOrgAdmin)
	auditor := e.session(e.acme, principal.RoleOrgAuditor)
	carol := e.session(e.globex, principal.RoleOrgAdmin)
	host := "fnd-" + uuid.NewString()[:8]
	dev := e.insertDevice(e.acme, host, "active")
	tamper := e.insertFinding(e.acme, dev, "tamper", "tamper:"+dev.String()+":device.tamper_sudoers_d_file:evil", "device.tamper_sudoers_d_file", "evil")
	alert := uuid.Must(uuid.NewV7())
	if _, err := e.super.Exec(context.Background(), `INSERT INTO device_alert (id, organization_id, device_id, kind, raised_at)
		VALUES ($1, $2, $3, 'stale_critical', $4)`, alert, e.acme, dev, time.Now().Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	attention := e.insertFinding(e.acme, dev, "attention", "attention:stale_critical:"+alert.String(), "stale_critical", "")

	if p := e.list(auditor, "/api/v1/findings", url.Values{"q": {host}}); p.Total != 2 || p.Sort != "-last_seen_at" {
		t.Fatalf("list: total %d sort %s", p.Total, p.Sort)
	}
	if p := e.list(auditor, "/api/v1/findings", url.Values{"q": {host}, "kind": {"tamper"}, "status": {"open", "in_progress"}}); p.Total != 1 {
		t.Fatalf("kind and status filter: total %d", p.Total)
	}
	if p := e.list(auditor, "/api/v1/findings", url.Values{"q": {host}, "cleared": {"true"}}); p.Total != 0 {
		t.Fatalf("cleared: total %d", p.Total)
	}
	if p := e.list(carol, "/api/v1/findings", url.Values{"q": {host}}); p.Total != 0 {
		t.Fatalf("other organization lists %d findings", p.Total)
	}

	var accounts adminapi.AccountPage
	r := e.do(call{method: "GET", path: "/api/v1/accounts?" + url.Values{"q": {"org_operator@test"}, "role": {"org_operator"}}.Encode(), cookie: auditor})
	if r.status != http.StatusOK {
		t.Fatalf("accounts: %d %s", r.status, r.body)
	}
	r.decode(t, &accounts)
	if len(accounts.Items) == 0 {
		t.Fatal("no operator account listed")
	}
	assignee := accounts.Items[0].Id

	base := "/api/v1/findings/" + tamper.String()
	var f adminapi.Finding
	r = e.do(call{method: "POST", path: base + "/acknowledge", cookie: operator})
	if r.status != http.StatusOK {
		t.Fatalf("acknowledge: %d %s", r.status, r.body)
	}
	e.expectEvent(r, "finding.acknowledged:success:")
	r = e.do(call{method: "POST", path: base + "/assign", cookie: operator, body: map[string]any{"assignee_id": assignee}})
	if r.status != http.StatusOK {
		t.Fatalf("assign: %d %s", r.status, r.body)
	}
	e.expectEvent(r, "finding.assigned:success:")
	r.decode(t, &f)
	if f.Status != adminapi.FindingStatusInProgress || f.Assignee == nil || f.Assignee.Id != assignee {
		t.Fatalf("assigned finding %+v", f)
	}
	r = e.do(call{method: "POST", path: base + "/close", cookie: operator, body: map[string]any{"resolution": "accepted_risk", "reason": "known"}})
	if r.status != http.StatusForbidden || r.problemCode(t) != "forbidden" {
		t.Fatalf("operator accepts a risk: %d %s", r.status, r.body)
	}
	e.expectEvent(r, "finding.closed:denied:forbidden")
	r = e.do(call{method: "POST", path: base + "/close", cookie: operator, body: map[string]any{"resolution": "resolved"}, skipReqCheck: true})
	if r.status != http.StatusBadRequest {
		t.Fatalf("close without a reason: %d %s", r.status, r.body)
	}
	r = e.do(call{method: "POST", path: base + "/close", cookie: admin, body: map[string]any{"resolution": "false_positive", "reason": "test file", "external_ref": "CHG-1"}})
	if r.status != http.StatusOK {
		t.Fatalf("close: %d %s", r.status, r.body)
	}
	e.expectEvent(r, "finding.closed:success:")
	r.decode(t, &f)
	if f.Status != adminapi.FindingStatusFalsePositive || f.Reason == nil || *f.Reason != "test file" || f.ClosedBy == nil {
		t.Fatalf("closed finding %+v", f)
	}
	r = e.do(call{method: "POST", path: base + "/acknowledge", cookie: operator})
	if r.status != http.StatusConflict || r.problemCode(t) != "invalid_state" {
		t.Fatalf("acknowledge a closed finding: %d %s", r.status, r.body)
	}
	e.expectEvent(r, "finding.acknowledged:failure:invalid_state")
	r = e.do(call{method: "POST", path: base + "/reopen", cookie: operator, body: map[string]any{"reason": ""}})
	if r.status != http.StatusBadRequest || r.problemCode(t) != "invalid_request" {
		t.Fatalf("reopen without a reason: %d %s", r.status, r.body)
	}
	r = e.do(call{method: "POST", path: base + "/reopen", cookie: auditor, body: map[string]any{"reason": "x"}})
	if r.status != http.StatusForbidden {
		t.Fatalf("auditor reopens: %d %s", r.status, r.body)
	}
	e.expectEvent(r, "finding.reopened:denied:forbidden")
	r = e.do(call{method: "GET", path: base, cookie: auditor})
	if r.status != http.StatusOK {
		t.Fatalf("auditor get: %d %s", r.status, r.body)
	}
	if r = e.do(call{method: "GET", path: base, cookie: carol}); r.status != http.StatusNotFound || r.problemCode(t) != "not_found" {
		t.Fatalf("other organization get: %d %s", r.status, r.body)
	}

	r = e.do(call{method: "POST", path: "/api/v1/findings/" + attention.String() + "/acknowledge", cookie: operator})
	if r.status != http.StatusOK {
		t.Fatalf("acknowledge the attention finding: %d %s", r.status, r.body)
	}
	var page adminapi.AttentionPage
	r = e.do(call{method: "GET", path: "/api/v1/attention?" + url.Values{"q": {host}}.Encode(), cookie: auditor})
	if r.status != http.StatusOK {
		t.Fatalf("attention: %d %s", r.status, r.body)
	}
	r.decode(t, &page)
	var linked *adminapi.AttentionFinding
	for _, it := range page.Items {
		if it.Kind == adminapi.AttentionKindStaleCritical {
			linked = it.Finding
		}
	}
	if linked == nil || linked.Id != attention || linked.Status != adminapi.FindingStatusAcknowledged {
		t.Fatalf("attention item finding %+v", linked)
	}
	var devices adminapi.AttentionDevicePage
	r = e.do(call{method: "GET", path: "/api/v1/attention/devices?" + url.Values{"device_id": {dev.String()}}.Encode(), cookie: auditor})
	if r.status != http.StatusOK {
		t.Fatalf("attention devices: %d %s", r.status, r.body)
	}
	r.decode(t, &devices)
	linked = nil
	for _, d := range devices.Items {
		for _, c := range d.Conditions {
			if c.Kind == adminapi.AttentionKindStaleCritical {
				linked = c.Finding
			}
		}
	}
	if linked == nil || linked.Id != attention || linked.Status != adminapi.FindingStatusAcknowledged {
		t.Fatalf("attention device condition finding %+v", linked)
	}
}
