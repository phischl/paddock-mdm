package acceptance

import (
	"net/http"
	"strings"
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

// auditEntry creates a catalog entry for a case and returns its path; the entry is deleted when the case ends.
func auditEntry(t *testing.T, p *env.Portal) string {
	t.Helper()
	res := call(t, p, http.MethodPost, softwareCatalog, entryBody("a3"))
	expectStatus(t, res, http.StatusCreated, "")
	return softwareCatalog + "/" + createdID(t, p, softwareCatalog, res)
}

// auditAssignment creates an entry with an organization-wide assignment for a case and returns the assignment's path.
func auditAssignment(t *testing.T, p *env.Portal) string {
	t.Helper()
	entry := strings.TrimPrefix(auditEntry(t, p), softwareCatalog+"/")
	res := call(t, p, http.MethodPost, softwareAssignments, map[string]any{"catalog_entry_id": entry, "intent": "hold"})
	expectStatus(t, res, http.StatusCreated, "")
	return softwareAssignments + "/" + responseID(t, res).String()
}

// catalogItemCases are the cases of a privileged operation on one catalog entry (or assignment): success on a fresh
// resource, a rule violation (invalid), a missing resource and a role that may not write. invalid is nil where the
// operation has no rule to violate.
func catalogItemCases(code, collection, method string, success int, create func(t *testing.T, p *env.Portal) string,
	body, invalid func(t *testing.T) any) []auditCase {
	cases := []auditCase{
		{"success", func(t *testing.T, w *auditWorld) {
			path := create(t, w.alice)
			res := call(t, w.alice, method, path, body(t))
			expectStatus(t, res, success, "")
			expectOneEvent(t, w.alice, res.RequestID, code, "success")
		}},
		{"not found", func(t *testing.T, w *auditWorld) {
			res := call(t, w.alice, method, collection+"/"+uuid.NewString(), body(t))
			expectStatus(t, res, http.StatusNotFound, "not_found")
			expectOneEvent(t, w.alice, res.RequestID, code, "failure")
		}},
		{"wrong role", func(t *testing.T, w *auditWorld) {
			res := call(t, mcpAuditor(t), method, collection+"/"+uuid.NewString(), body(t))
			expectStatus(t, res, http.StatusForbidden, "forbidden")
			expectOneEvent(t, w.alice, res.RequestID, code, "denied")
		}},
	}
	if invalid != nil {
		cases = append(cases, auditCase{"invalid", func(t *testing.T, w *auditWorld) {
			path := create(t, w.alice)
			res := call(t, w.alice, method, path, invalid(t))
			expectStatus(t, res, http.StatusBadRequest, "invalid_request")
			expectOneEvent(t, w.alice, res.RequestID, code, "failure")
		}})
	}
	return cases
}

func entryUpdate(*testing.T) any {
	return map[string]any{"name": "a3-renamed-" + uniqueSuffix(), "packages": entryBody("a3")["packages"]}
}

func assignmentUpdate(*testing.T) any { return map[string]any{"intent": "forbid"} }

// softwareCatalogAuditCases are the cases of the catalog and assignment operations (plan M13a §6.3, ticket PDK-409).
var softwareCatalogAuditCases = map[string][]auditCase{
	"POST /api/v1/software-catalog": {
		{"success", func(t *testing.T, w *auditWorld) {
			res := call(t, w.alice, http.MethodPost, softwareCatalog, entryBody("a3"))
			expectStatus(t, res, http.StatusCreated, "")
			createdID(t, w.alice, softwareCatalog, res)
			expectOneEvent(t, w.alice, res.RequestID, "software_catalog_entry.created", "success")
		}},
		{"invalid", func(t *testing.T, w *auditWorld) {
			body := entryBody("a3")
			body["packages"] = []map[string]any{}
			res := call(t, w.alice, http.MethodPost, softwareCatalog, body)
			expectStatus(t, res, http.StatusBadRequest, "invalid_request")
			expectOneEvent(t, w.alice, res.RequestID, "software_catalog_entry.created", "failure")
		}},
		{"conflict", func(t *testing.T, w *auditWorld) {
			body := entryBody("a3")
			first := call(t, w.alice, http.MethodPost, softwareCatalog, body)
			expectStatus(t, first, http.StatusCreated, "")
			createdID(t, w.alice, softwareCatalog, first)
			res := call(t, w.alice, http.MethodPost, softwareCatalog, body)
			expectStatus(t, res, http.StatusConflict, "already_exists")
			expectOneEvent(t, w.alice, res.RequestID, "software_catalog_entry.created", "failure")
		}},
		{"source not found", func(t *testing.T, w *auditWorld) {
			body := entryBody("a3")
			body["source_id"] = uuid.NewString()
			res := call(t, w.alice, http.MethodPost, softwareCatalog, body)
			expectStatus(t, res, http.StatusNotFound, "not_found")
			expectOneEvent(t, w.alice, res.RequestID, "software_catalog_entry.created", "failure")
		}},
		{"wrong role", func(t *testing.T, w *auditWorld) {
			res := call(t, mcpAuditor(t), http.MethodPost, softwareCatalog, entryBody("a3"))
			expectStatus(t, res, http.StatusForbidden, "forbidden")
			expectOneEvent(t, w.alice, res.RequestID, "software_catalog_entry.created", "denied")
		}},
	},
	"PATCH /api/v1/software-catalog/{id}": catalogItemCases("software_catalog_entry.updated", softwareCatalog,
		http.MethodPatch, http.StatusOK, auditEntry, entryUpdate,
		func(*testing.T) any { return map[string]any{"name": "a3-invalid", "packages": []map[string]any{}} }),
	"DELETE /api/v1/software-catalog/{id}": catalogItemCases("software_catalog_entry.deleted", softwareCatalog,
		http.MethodDelete, http.StatusNoContent, auditEntry, func(*testing.T) any { return noBody() }, nil),
	"PUT /api/v1/software-catalog/{id}/icon": catalogItemCases("software_catalog_entry.updated", softwareCatalog,
		http.MethodPut, http.StatusNoContent, auditEntry, func(t *testing.T) any { return gatePNG(t) },
		func(*testing.T) any { return []byte("not a png") }),
	"POST /api/v1/software-assignments": {
		{"success", func(t *testing.T, w *auditWorld) {
			entry := strings.TrimPrefix(auditEntry(t, w.alice), softwareCatalog+"/")
			res := call(t, w.alice, http.MethodPost, softwareAssignments, map[string]any{"catalog_entry_id": entry, "intent": "required"})
			expectStatus(t, res, http.StatusCreated, "")
			expectOneEvent(t, w.alice, res.RequestID, "software_assignment.created", "success")
		}},
		{"invalid", func(t *testing.T, w *auditWorld) {
			entry := strings.TrimPrefix(auditEntry(t, w.alice), softwareCatalog+"/")
			res := call(t, w.alice, http.MethodPost, softwareAssignments,
				map[string]any{"catalog_entry_id": entry, "intent": "forbid", "version": "1.0"})
			expectStatus(t, res, http.StatusBadRequest, "invalid_request")
			expectOneEvent(t, w.alice, res.RequestID, "software_assignment.created", "failure")
		}},
		{"conflict", func(t *testing.T, w *auditWorld) {
			entry := strings.TrimPrefix(auditEntry(t, w.alice), softwareCatalog+"/")
			body := map[string]any{"catalog_entry_id": entry, "intent": "hold"}
			expectStatus(t, call(t, w.alice, http.MethodPost, softwareAssignments, body), http.StatusCreated, "")
			res := call(t, w.alice, http.MethodPost, softwareAssignments, body)
			expectStatus(t, res, http.StatusConflict, "already_exists")
			expectOneEvent(t, w.alice, res.RequestID, "software_assignment.created", "failure")
		}},
		{"entry not found", func(t *testing.T, w *auditWorld) {
			res := call(t, w.alice, http.MethodPost, softwareAssignments, map[string]any{"catalog_entry_id": uuid.NewString(), "intent": "hold"})
			expectStatus(t, res, http.StatusNotFound, "not_found")
			expectOneEvent(t, w.alice, res.RequestID, "software_assignment.created", "failure")
		}},
		{"wrong role", func(t *testing.T, w *auditWorld) {
			res := call(t, mcpAuditor(t), http.MethodPost, softwareAssignments, map[string]any{"catalog_entry_id": uuid.NewString(), "intent": "hold"})
			expectStatus(t, res, http.StatusForbidden, "forbidden")
			expectOneEvent(t, w.alice, res.RequestID, "software_assignment.created", "denied")
		}},
	},
	"PATCH /api/v1/software-assignments/{id}": catalogItemCases("software_assignment.updated", softwareAssignments,
		http.MethodPatch, http.StatusOK, auditAssignment, assignmentUpdate,
		func(*testing.T) any { return map[string]any{"intent": "forbid", "version": "1.0"} }),
	"DELETE /api/v1/software-assignments/{id}": catalogItemCases("software_assignment.deleted", softwareAssignments,
		http.MethodDelete, http.StatusNoContent, auditAssignment, func(*testing.T) any { return noBody() }, nil),
}
