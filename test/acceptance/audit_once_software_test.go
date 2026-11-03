package acceptance

import (
	"net/http"
	"testing"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/test/acceptance/internal/env"
)

// auditSource creates a software source with a stepped-up session for a case and returns its path.
func auditSource(t *testing.T, s stepper) string {
	t.Helper()
	s.stepUp(t)
	res := call(t, s.Portal, http.MethodPost, softwareSources, sourceBody("a3"))
	expectStatus(t, res, http.StatusCreated, "")
	path := softwareSources + "/" + responseID(t, res).String()
	deleteSourceOnCleanup(t, s.Portal, s.stepUp, path)
	return path
}

// sourceItemCases are the cases of a privileged operation on one software source.
func sourceItemCases(code, method string, success int, body func() any) []auditCase {
	return []auditCase{
		{"success", func(t *testing.T, w *auditWorld) {
			s := adminStepper(adminUser(t, "a3-source"))
			path := auditSource(t, s)
			s.stepUp(t)
			res := call(t, s.Portal, method, path, body())
			expectStatus(t, res, success, "")
			expectOneEvent(t, w.alice, res.RequestID, code, "success")
		}},
		{"not found", func(t *testing.T, w *auditWorld) {
			s := adminStepper(adminUser(t, "a3-source"))
			res := call(t, s.Portal, method, softwareSources+"/"+uuid.NewString(), body())
			expectStatus(t, res, http.StatusNotFound, "not_found")
			expectOneEvent(t, w.alice, res.RequestID, code, "failure")
		}},
		{"wrong role", func(t *testing.T, w *auditWorld) {
			res := call(t, w.bob, method, softwareSources+"/"+uuid.NewString(), body())
			expectStatus(t, res, http.StatusForbidden, "forbidden")
			expectOneEvent(t, w.alice, res.RequestID, code, "denied")
		}},
		{"no step-up", func(t *testing.T, w *auditWorld) {
			res := call(t, login(t, env.Alice), method, softwareSources+"/"+uuid.NewString(), body())
			expectStatus(t, res, http.StatusForbidden, "step_up_required")
			expectOneEvent(t, w.alice, res.RequestID, code, "denied")
		}},
	}
}

// softwareAuditCases are the cases of the software source operations (plan M13a §6.3, ticket PDK-408).
var softwareAuditCases = map[string][]auditCase{
	"POST /api/v1/software-sources": {
		{"success", func(t *testing.T, w *auditWorld) {
			s := adminStepper(adminUser(t, "a3-source"))
			s.stepUp(t)
			res := call(t, s.Portal, http.MethodPost, softwareSources, sourceBody("a3"))
			expectStatus(t, res, http.StatusCreated, "")
			deleteSourceOnCleanup(t, s.Portal, s.stepUp, softwareSources+"/"+responseID(t, res).String())
			expectOneEvent(t, w.alice, res.RequestID, "software_source.created", "success")
		}},
		{"fingerprint mismatch", func(t *testing.T, w *auditWorld) {
			s := adminStepper(adminUser(t, "a3-source"))
			s.stepUp(t)
			body := sourceBody("a3")
			body["fingerprint"] = "0000000000000000000000000000000000000000"
			res := call(t, s.Portal, http.MethodPost, softwareSources, body)
			expectStatus(t, res, http.StatusUnprocessableEntity, "fingerprint_mismatch")
			expectOneEvent(t, w.alice, res.RequestID, "software_source.created", "failure")
		}},
		{"no step-up", func(t *testing.T, w *auditWorld) {
			res := call(t, login(t, env.Alice), http.MethodPost, softwareSources, sourceBody("a3"))
			expectStatus(t, res, http.StatusForbidden, "step_up_required")
			expectOneEvent(t, w.alice, res.RequestID, "software_source.created", "denied")
		}},
		{"wrong role", func(t *testing.T, w *auditWorld) {
			res := call(t, w.bob, http.MethodPost, softwareSources, sourceBody("a3"))
			expectStatus(t, res, http.StatusForbidden, "forbidden")
			expectOneEvent(t, w.alice, res.RequestID, "software_source.created", "denied")
		}},
	},
	"PATCH /api/v1/software-sources/{id}": sourceItemCases("software_source.updated", http.MethodPatch, http.StatusOK,
		func() any { return map[string]any{"name": "a3-renamed-" + uniqueSuffix()} }),
	"DELETE /api/v1/software-sources/{id}": sourceItemCases("software_source.deleted", http.MethodDelete,
		http.StatusNoContent, noBody),
}
