package acceptance

import (
	"net/http"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/test/acceptance/internal/env"
	"github.com/phischl/paddock-mdm/test/acceptance/internal/stack"
)

// auditExport is the part of an evidence export the gate reads.
type auditExport struct {
	ID          string `json:"id"`
	Status      string `json:"status"`
	FromDay     string `json:"from_day"`
	ToDay       string `json:"to_day"`
	Purpose     string `json:"purpose"`
	RequestedBy struct {
		Type    string  `json:"type"`
		Display string  `json:"display"`
		IP      *string `json:"ip"`
		StepUp  bool    `json:"step_up"`
	} `json:"requested_by"`
}

// TestAuditEvidenceExport covers the evidence export gates of plan M10 §9. E1 (PDK-142): an auditor of a fresh
// organization requests an export of a sealed day only after a step-up, every request is recorded as
// audit.export_requested, the refusals carry their problem codes, and another organization does not see the export.
// E2–E4 (package, download, offline verification) follow in this function with PDK-143, PDK-144 and PDK-146.
//
// Like TestAuditIntegrity it uses a fresh organization so the development-only `audit seal --day --org` can seal today
// without sealing other organizations' days early.
func TestAuditEvidenceExport(t *testing.T) {
	ctx := testContext(t, 10*time.Minute)
	root := login(t, env.PlatformAdmin)
	body := newOrg()
	res := call(t, root, http.MethodPost, "/api/platform/v1/organizations", body)
	expectStatus(t, res, http.StatusCreated, "")
	org := responseID(t, res)
	adminName, adminPW := tempUser(t, "export-admin", env.RoleGroup(body["slug"], "admins"))
	admin, err := loginAs(t, adminName, adminPW)
	if err != nil {
		t.Fatalf("login as the new organization's admin: %v", err)
	}
	createGroup(t, admin)
	waitForEvents(t, admin, 2) // admin.login + device_group.created
	today := time.Now().UTC().Format(time.DateOnly)
	tomorrow := time.Now().UTC().AddDate(0, 0, 1).Format(time.DateOnly)
	if code, out, err := stack.PaddockServer(ctx, "audit", "seal", "--day", today, "--org", org.String()); err != nil || code != 0 {
		t.Fatalf("audit seal: exit %d, %v\n%s", code, err, out)
	}
	auditor := mfaTempUser(t, "export-auditor", env.RoleGroup(body["slug"], "auditors"))
	request := func(from, to, purpose string) env.Response {
		return call(t, auditor.Portal, http.MethodPost, "/api/v1/audit/exports",
			map[string]string{"from_day": from, "to_day": to, "purpose": purpose})
	}

	// E1: without a step-up the request is refused and recorded as denied.
	expectRefusal(t, auditor.Portal, request(today, today, "E1 without step-up"), http.StatusForbidden, "step_up_required", "audit.export_requested")

	// E1: with a step-up the auditor's request is pending and recorded with its range and purpose.
	auditor.stepUp(t)
	res = request(today, today, "E1 ISO 27001 surveillance audit")
	expectStatus(t, res, http.StatusAccepted, "")
	var first auditExport
	if err := res.JSON(&first); err != nil {
		t.Fatal(err)
	}
	if first.Status != "pending" || first.FromDay != today || first.ToDay != today || first.Purpose != "E1 ISO 27001 surveillance audit" ||
		first.RequestedBy.Type != "admin" || first.RequestedBy.IP != nil || !first.RequestedBy.StepUp {
		t.Fatalf("E1 export: %s", res.Body)
	}
	ev := expectOneEvent(t, auditor.Portal, res.RequestID, "audit.export_requested", "success")
	if ev.Params["export_id"] != first.ID || ev.Params["from_day"] != today || ev.Params["to_day"] != today ||
		ev.Params["purpose"] != "E1 ISO 27001 surveillance audit" {
		t.Fatalf("E1 event params: %+v", ev.Params)
	}

	// E1 refusals: an unsealed day, too long a range, an empty purpose, an operator.
	auditor.stepUp(t)
	res = request(today, tomorrow, "E1 unsealed")
	expectStatus(t, res, http.StatusUnprocessableEntity, "day_not_sealed")
	expectOneEvent(t, auditor.Portal, res.RequestID, "audit.export_requested", "failure")
	res = request(time.Now().UTC().AddDate(0, 0, -401).Format(time.DateOnly), today, "E1 too long")
	expectStatus(t, res, http.StatusBadRequest, "range_too_large")
	res = request(today, today, "")
	expectStatus(t, res, http.StatusBadRequest, "invalid_request")
	operator := steppedUpTempUser(t, "export-operator", env.RoleGroup(body["slug"], "operators"))
	res = call(t, operator.Portal, http.MethodPost, "/api/v1/audit/exports",
		map[string]string{"from_day": today, "to_day": today, "purpose": "E1 operator"})
	expectRefusal(t, auditor.Portal, res, http.StatusForbidden, "forbidden", "audit.export_requested")

	// E1: at most two exports are pending or running.
	auditor.stepUp(t)
	res = request(today, today, "E1 second")
	expectStatus(t, res, http.StatusAccepted, "")
	res = request(today, today, "E1 third")
	expectStatus(t, res, http.StatusConflict, "too_many_exports")
	expectOneEvent(t, auditor.Portal, res.RequestID, "audit.export_requested", "failure")

	// E1: the organization lists its two exports; another organization's auditor finds neither.
	res = call(t, auditor.Portal, http.MethodGet, "/api/v1/audit/exports?status=pending&page_size=10", nil)
	expectStatus(t, res, http.StatusOK, "")
	var page struct {
		Items []auditExport `json:"items"`
		Total int           `json:"total"`
	}
	if err := res.JSON(&page); err != nil || page.Total != 2 {
		t.Fatalf("E1 list: %v %s", err, res.Body)
	}
	carol := login(t, env.Carol)
	expectStatus(t, call(t, carol, http.MethodGet, "/api/v1/audit/exports/"+first.ID, nil), http.StatusNotFound, "not_found")
	res = call(t, carol, http.MethodGet, "/api/v1/audit/exports?page_size=100", nil)
	expectStatus(t, res, http.StatusOK, "")
	if leaked := containsAny(res.Body, []string{first.ID, org.String()}); leaked != "" {
		t.Fatalf("E1 globex list contains %s: %s", leaked, res.Body)
	}
}
