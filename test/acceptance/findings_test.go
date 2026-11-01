package acceptance

import (
	"fmt"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/test/acceptance/internal/env"
)

func TestFindingsTamper(t *testing.T) {
	alice := login(t, env.Alice)
	org := orgOf(t, alice)
	d := activeDevice(t, alice, "", "n8-tamper-"+uniqueSuffix())
	for seq := int64(1); seq <= 3; seq++ {
		sendSudoersEvent(t, d, seq, "n8-evil")
	}
	f := tamperFindingOf(t, alice, d.DeviceID, 3)
	if f.Code != "device.tamper_sudoers_d_file" || f.Subject != "n8-evil" || f.Status != "open" {
		t.Fatalf("finding %+v", f)
	}
	third := expectOneIndexEvent(t, auditIndex(t), org, "code = 'device.tamper_sudoers_d_file' AND target->>'id' = $1 AND params->>'event_seq' = '3'",
		d.DeviceID, "device.tamper_sudoers_d_file", "success", time.Minute)
	if f.LastEventID == nil || *f.LastEventID != third.EventID.String() {
		t.Fatalf("last_event_id %v, want %s", f.LastEventID, third.EventID)
	}
	res := call(t, alice, http.MethodPost, "/api/v1/findings/"+f.ID+"/close", map[string]any{"resolution": "resolved", "reason": "file removed"})
	expectStatus(t, res, http.StatusOK, "")
	sendSudoersEvent(t, d, 4, "n8-evil")
	waitFindings(t, alice, url.Values{"device_id": {d.DeviceID}, "kind": {"tamper"}}, time.Minute, func(all []findingItem) bool {
		closed, open := 0, 0
		for _, x := range all {
			switch {
			case x.ID == f.ID && x.Status == "resolved" && x.Occurrences == 3:
				closed++
			case x.ID != f.ID && x.Status == "open" && x.Occurrences == 1:
				open++
			}
		}
		return len(all) == 2 && closed == 1 && open == 1
	})
}

// TestFindingsAttention is gate N8 (attention part): with the development stack's minute unit, a device in a group
// with 1/2 that stops checking in gets a finding kind attention, code stale_critical, opened when the condition
// began, which the attention list shows with the condition; a check-in clears it.
func TestFindingsAttention(t *testing.T) {
	alice := login(t, env.Alice)
	group := groupWithStaleness(t, alice, 1, 2)
	hostname := "n8-stale-" + uniqueSuffix()
	d := activeDevice(t, alice, group, hostname)
	if _, r, err := d.Checkin(testContext(t, time.Minute)); err != nil || r.Status != http.StatusOK {
		t.Fatalf("check-in: %v", err)
	}
	q := url.Values{"device_id": {d.DeviceID}, "kind": {"attention"}}
	f := waitFindings(t, alice, q, 5*time.Minute, func(all []findingItem) bool {
		for _, x := range all {
			if x.Code == "stale_critical" {
				return true
			}
		}
		return false
	})
	var stale findingItem
	for _, x := range f {
		if x.Code == "stale_critical" {
			stale = x
		}
	}
	res := call(t, alice, http.MethodGet, "/api/v1/attention?"+url.Values{"q": {hostname}, "kind": {"stale_critical"}}.Encode(), nil)
	expectStatus(t, res, http.StatusOK, "")
	var page struct {
		Items []struct {
			Since   string `json:"since"`
			Finding *struct {
				ID     string `json:"id"`
				Status string `json:"status"`
			} `json:"finding"`
		} `json:"items"`
	}
	if err := res.JSON(&page); err != nil || len(page.Items) != 1 {
		t.Fatalf("attention %s: %v", res.Body, err)
	}
	item := page.Items[0]
	since, _ := time.Parse(time.RFC3339Nano, item.Since)
	opened, _ := time.Parse(time.RFC3339Nano, stale.OpenedAt)
	if item.Finding == nil || item.Finding.ID != stale.ID || item.Finding.Status != "open" || !since.Equal(opened) {
		t.Fatalf("attention item %+v, finding %+v", item, stale)
	}
	if _, r, err := d.Checkin(testContext(t, time.Minute)); err != nil || r.Status != http.StatusOK {
		t.Fatalf("check-in: %v", err)
	}
	waitFindings(t, alice, url.Values{"device_id": {d.DeviceID}, "kind": {"attention"}, "cleared": {"true"}}, 2*time.Minute, func(all []findingItem) bool {
		for _, x := range all {
			if x.ID == stale.ID && x.ClearedAt != nil {
				return true
			}
		}
		return false
	})
}

// expectFindingParams requires the params of plan M9 §6.3 on a finding event.
func expectFindingParams(t *testing.T, ev env.AuditEvent, hostname, previous string, extra map[string]any) {
	t.Helper()
	want := map[string]any{"kind": "tamper", "code": "device.tamper_sudoers_d_file", "hostname": hostname, "subject": "n9-evil",
		"previous_status": previous}
	for k, v := range extra {
		want[k] = v
	}
	if len(ev.Params) != len(want) {
		t.Fatalf("%s params %v, want %v", ev.Code, ev.Params, want)
	}
	for k, v := range want {
		if fmt.Sprint(ev.Params[k]) != fmt.Sprint(v) {
			t.Fatalf("%s param %s = %v, want %v", ev.Code, k, ev.Params[k], v)
		}
	}
}

// TestFindingsWorkflow is gate N9 (operator and auditor, plan M9 §9): an operator acknowledges, assigns to an
// account and closes as false_positive with a reason, each 200 with one event the auditor sees with its params;
// accepted_risk is forbidden for the operator (denied) and allowed for the administrator; acknowledge on a closed
// finding is 409, reopen without a reason 400; another organization gets 404.
func TestFindingsWorkflow(t *testing.T) {
	alice := login(t, env.Alice)
	bob := login(t, env.Bob)
	carol := login(t, env.Carol)
	operator := operatorUser(t)
	hostname := "n9-" + uniqueSuffix()
	d := activeDevice(t, alice, "", hostname)
	sendSudoersEvent(t, d, 1, "n9-evil")
	f := tamperFindingOf(t, alice, d.DeviceID, 1)
	base := "/api/v1/findings/" + f.ID
	post := func(p *env.Portal, verb string, body any) env.Response {
		return call(t, p, http.MethodPost, base+"/"+verb, body)
	}
	status := func(res env.Response, want string) {
		t.Helper()
		expectStatus(t, res, http.StatusOK, "")
		var got findingItem
		if err := res.JSON(&got); err != nil || got.Status != want {
			t.Fatalf("status %s (%v), want %s", res.Body, err, want)
		}
	}

	res := post(operator.Portal, "acknowledge", nil)
	status(res, "acknowledged")
	expectFindingParams(t, expectOneEvent(t, bob, res.RequestID, "finding.acknowledged", "success"), hostname, "open", nil)

	accounts := call(t, operator.Portal, http.MethodGet, "/api/v1/accounts?"+url.Values{"q": {operator.username}}.Encode(), nil)
	expectStatus(t, accounts, http.StatusOK, "")
	var page struct {
		Items []struct {
			ID       string `json:"id"`
			Username string `json:"username"`
			Role     string `json:"role"`
		} `json:"items"`
	}
	if err := accounts.JSON(&page); err != nil || len(page.Items) != 1 || page.Items[0].Role != "org_operator" {
		t.Fatalf("accounts %s: %v", accounts.Body, err)
	}
	res = post(operator.Portal, "assign", map[string]any{"assignee_id": page.Items[0].ID})
	status(res, "in_progress")
	expectFindingParams(t, expectOneEvent(t, bob, res.RequestID, "finding.assigned", "success"), hostname, "acknowledged",
		map[string]any{"assignee": page.Items[0].Username})

	expectRefusal(t, alice, post(operator.Portal, "close", map[string]any{"resolution": "accepted_risk", "reason": "known"}),
		http.StatusForbidden, "forbidden", "finding.closed")
	res = post(operator.Portal, "close", map[string]any{"resolution": "false_positive", "reason": "test file", "external_ref": "CHG-9"})
	status(res, "false_positive")
	expectFindingParams(t, expectOneEvent(t, bob, res.RequestID, "finding.closed", "success"), hostname, "in_progress",
		map[string]any{"resolution": "false_positive", "reason": "test file", "external_ref": "CHG-9"})

	res = post(operator.Portal, "acknowledge", nil)
	expectStatus(t, res, http.StatusConflict, "invalid_state")
	expectOneEvent(t, alice, res.RequestID, "finding.acknowledged", "failure")
	res = post(operator.Portal, "reopen", map[string]any{"reason": ""})
	expectStatus(t, res, http.StatusBadRequest, "invalid_request")
	expectOneEvent(t, alice, res.RequestID, "finding.reopened", "failure")
	res = post(operator.Portal, "reopen", map[string]any{"reason": "seen again"})
	status(res, "open")
	expectFindingParams(t, expectOneEvent(t, bob, res.RequestID, "finding.reopened", "success"), hostname, "false_positive",
		map[string]any{"reason": "seen again"})
	res = post(alice, "close", map[string]any{"resolution": "accepted_risk", "reason": "lab machine"})
	status(res, "accepted_risk")
	expectOneEvent(t, bob, res.RequestID, "finding.closed", "success")

	read := call(t, bob, http.MethodGet, base, nil)
	expectStatus(t, read, http.StatusOK, "")
	var got findingItem
	if err := read.JSON(&got); err != nil || got.Reason == nil || *got.Reason != "lab machine" {
		t.Fatalf("auditor reads %s: %v", read.Body, err)
	}
	expectStatus(t, call(t, carol, http.MethodGet, base, nil), http.StatusNotFound, "not_found")
}

// caseFinding returns an open tamper finding of a new acme device for the audit-once cases; closed closes it first.
func caseFinding(t *testing.T, w *auditWorld, closed bool) string {
	t.Helper()
	d := activeDevice(t, w.alice, "", "a3-finding-"+uniqueSuffix())
	sendSudoersEvent(t, d, 1, "a3-evil")
	id := tamperFindingOf(t, w.alice, d.DeviceID, 1).ID
	if closed {
		res := call(t, w.alice, http.MethodPost, "/api/v1/findings/"+id+"/close", map[string]any{"resolution": "resolved", "reason": "a3"})
		expectStatus(t, res, http.StatusOK, "")
	}
	return id
}

// findingAuditCases are the audit-once cases of the four finding verbs (plan M9 decision 33): success, validation
// failure, wrong role, not found and the conflict of a closed finding (reopen: an open one).
func findingAuditCases() map[string][]auditCase {
	verb := func(name, code string, valid, invalid any, conflictClosed bool) []auditCase {
		path := func(id string) string { return "/api/v1/findings/" + id + "/" + name }
		return []auditCase{
			{"success", func(t *testing.T, w *auditWorld) {
				res := call(t, w.alice, http.MethodPost, path(caseFinding(t, w, !conflictClosed)), valid)
				expectStatus(t, res, http.StatusOK, "")
				expectOneEvent(t, w.alice, res.RequestID, code, "success")
			}},
			{"validation failure", func(t *testing.T, w *auditWorld) {
				id, body := caseFinding(t, w, !conflictClosed), invalid
				if invalid == nil {
					id, body = "not-a-uuid", valid
				}
				res := call(t, w.alice, http.MethodPost, path(id), body)
				expectStatus(t, res, http.StatusBadRequest, "invalid_request")
				expectOneEvent(t, w.alice, res.RequestID, code, "failure")
			}},
			{"wrong role", func(t *testing.T, w *auditWorld) {
				res := call(t, w.bob, http.MethodPost, path(caseFinding(t, w, !conflictClosed)), valid)
				expectStatus(t, res, http.StatusForbidden, "forbidden")
				expectOneEvent(t, w.alice, res.RequestID, code, "denied")
			}},
			{"not found", func(t *testing.T, w *auditWorld) {
				res := call(t, w.alice, http.MethodPost, path(uuid.NewString()), valid)
				expectStatus(t, res, http.StatusNotFound, "not_found")
				expectOneEvent(t, w.alice, res.RequestID, code, "failure")
			}},
			{"conflict", func(t *testing.T, w *auditWorld) {
				res := call(t, w.alice, http.MethodPost, path(caseFinding(t, w, conflictClosed)), valid)
				expectStatus(t, res, http.StatusConflict, "invalid_state")
				expectOneEvent(t, w.alice, res.RequestID, code, "failure")
			}},
		}
	}
	return map[string][]auditCase{
		"POST /api/v1/findings/{id}/acknowledge": verb("acknowledge", "finding.acknowledged", nil, nil, true),
		"POST /api/v1/findings/{id}/assign":      verb("assign", "finding.assigned", map[string]any{"assignee_id": nil}, nil, true),
		"POST /api/v1/findings/{id}/close": verb("close", "finding.closed", map[string]any{"resolution": "resolved", "reason": "a3"},
			map[string]any{"resolution": "resolved", "reason": ""}, true),
		"POST /api/v1/findings/{id}/reopen": verb("reopen", "finding.reopened", map[string]any{"reason": "a3"},
			map[string]any{"reason": ""}, false),
	}
}
