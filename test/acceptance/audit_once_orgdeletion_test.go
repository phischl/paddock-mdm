package acceptance

import (
	"net/http"
	"testing"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/test/acceptance/internal/env"
)

const orgPath = "/api/platform/v1/organizations/"

// deletionGateOrg creates an organization of the case's own: the deletion cases never touch a shared organization.
func deletionGateOrg(t *testing.T, w *auditWorld) (id, slug string) {
	t.Helper()
	body := newOrg()
	res := createOrg(t, w.root, body)
	expectStatus(t, res, http.StatusCreated, "")
	return responseID(t, res).String(), body["slug"]
}

func deletionBody(slug string) map[string]any {
	return map[string]any{"confirm_slug": slug, "reason": "a3 gate", "grace_days": 30}
}

// requestDeletion asks for the deletion of a gate organization and cancels it again when the case ends, so nothing
// is ever deleted.
func requestDeletion(t *testing.T, root *env.Portal, id, slug string) env.Response {
	t.Helper()
	res := call(t, root, http.MethodPost, orgPath+id+"/delete", deletionBody(slug))
	expectStatus(t, res, http.StatusAccepted, "")
	t.Cleanup(func() {
		// 409: the case cancelled the deletion itself; anything else leaves the gate organization pending deletion.
		if res := call(t, root, http.MethodPost, orgPath+id+"/cancel-deletion", nil); res.Status != http.StatusOK && res.Status != http.StatusConflict {
			t.Errorf("cancel the deletion of gate organization %s: HTTP %d %s", id, res.Status, res.ProblemCode())
		}
	})
	return res
}

// organizationDeletionAuditCases are the A3 cases of the organization deletion routes (ADR 0052); both are recorded
// in the platform pseudo-organization.
var organizationDeletionAuditCases = map[string][]auditCase{
	"POST /api/platform/v1/organizations/{id}/delete": {
		{"no step-up", func(t *testing.T, w *auditWorld) {
			root := login(t, env.PlatformAdmin)
			res := call(t, root, http.MethodPost, orgPath+uuid.NewString()+"/delete", deletionBody("gate-none"))
			expectStatus(t, res, http.StatusForbidden, "step_up_required")
			expectOneIndexEvent(t, w.idx, platformOrg, "correlation_id = $1", res.RequestID, "organization.deletion_requested", "denied", auditPollTimeout)
		}},
		{"wrong role", func(t *testing.T, w *auditWorld) {
			res := call(t, w.alice, http.MethodPost, orgPath+uuid.NewString()+"/delete", deletionBody("gate-none"))
			expectStatus(t, res, http.StatusForbidden, "forbidden")
			expectOneEvent(t, w.alice, res.RequestID, "organization.deletion_requested", "denied")
		}},
		{"validation failure", func(t *testing.T, w *auditWorld) {
			id, slug := deletionGateOrg(t, w)
			root := steppedUpRoot(t)
			for _, body := range []map[string]any{
				{"confirm_slug": slug + "-x", "reason": "a3 gate", "grace_days": 30},
				{"confirm_slug": slug, "reason": "x", "grace_days": 30},
				{"confirm_slug": slug, "reason": "a3 gate", "grace_days": 91},
			} {
				res := call(t, root, http.MethodPost, orgPath+id+"/delete", body)
				expectStatus(t, res, http.StatusBadRequest, "invalid_request")
				expectOneIndexEvent(t, w.idx, platformOrg, "correlation_id = $1", res.RequestID, "organization.deletion_requested", "failure", auditPollTimeout)
			}
		}},
		{"not found", func(t *testing.T, w *auditWorld) {
			res := call(t, steppedUpRoot(t), http.MethodPost, orgPath+uuid.NewString()+"/delete", deletionBody("gate-none"))
			expectStatus(t, res, http.StatusNotFound, "not_found")
			expectOneIndexEvent(t, w.idx, platformOrg, "correlation_id = $1", res.RequestID, "organization.deletion_requested", "failure", auditPollTimeout)
		}},
		{"conflict", func(t *testing.T, w *auditWorld) {
			id, slug := deletionGateOrg(t, w)
			root := steppedUpRoot(t)
			requestDeletion(t, root, id, slug)
			res := call(t, root, http.MethodPost, orgPath+id+"/delete", deletionBody(slug))
			expectStatus(t, res, http.StatusConflict, "invalid_state")
			expectOneIndexEvent(t, w.idx, platformOrg, "correlation_id = $1", res.RequestID, "organization.deletion_requested", "failure", auditPollTimeout)
		}},
		{"success", func(t *testing.T, w *auditWorld) {
			id, slug := deletionGateOrg(t, w)
			res := requestDeletion(t, steppedUpRoot(t), id, slug)
			expectOneIndexEvent(t, w.idx, platformOrg, "correlation_id = $1", res.RequestID, "organization.deletion_requested", "success", auditPollTimeout)
		}},
	},
	"POST /api/platform/v1/organizations/{id}/cancel-deletion": {
		{"wrong role", func(t *testing.T, w *auditWorld) {
			res := call(t, w.alice, http.MethodPost, orgPath+uuid.NewString()+"/cancel-deletion", nil)
			expectStatus(t, res, http.StatusForbidden, "forbidden")
			expectOneEvent(t, w.alice, res.RequestID, "organization.deletion_cancelled", "denied")
		}},
		{"not found", func(t *testing.T, w *auditWorld) {
			res := call(t, w.root, http.MethodPost, orgPath+uuid.NewString()+"/cancel-deletion", nil)
			expectStatus(t, res, http.StatusNotFound, "not_found")
			expectOneIndexEvent(t, w.idx, platformOrg, "correlation_id = $1", res.RequestID, "organization.deletion_cancelled", "failure", auditPollTimeout)
		}},
		{"conflict", func(t *testing.T, w *auditWorld) {
			id, _ := deletionGateOrg(t, w)
			res := call(t, w.root, http.MethodPost, orgPath+id+"/cancel-deletion", nil)
			expectStatus(t, res, http.StatusConflict, "invalid_state")
			expectOneIndexEvent(t, w.idx, platformOrg, "correlation_id = $1", res.RequestID, "organization.deletion_cancelled", "failure", auditPollTimeout)
		}},
		{"success", func(t *testing.T, w *auditWorld) {
			id, slug := deletionGateOrg(t, w)
			requestDeletion(t, steppedUpRoot(t), id, slug)
			res := call(t, w.root, http.MethodPost, orgPath+id+"/cancel-deletion", nil)
			expectStatus(t, res, http.StatusOK, "")
			expectOneIndexEvent(t, w.idx, platformOrg, "correlation_id = $1", res.RequestID, "organization.deletion_cancelled", "success", auditPollTimeout)
		}},
	},
}
