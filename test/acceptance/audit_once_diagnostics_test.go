package acceptance

import (
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/test/acceptance/internal/env"
)

// requestedDiagnostics asks for a bundle of a device of its own and returns the bundle's ID; the bundle stays requested.
func requestedDiagnostics(t *testing.T, w *auditWorld) string {
	t.Helper()
	d := v2Device(t, w.alice, "", 1, 2)
	res := requestDiagnostics(t, w.alice, d.DeviceID, "A3 "+uniqueSuffix())
	expectStatus(t, res, http.StatusAccepted, "")
	return responseID(t, res).String()
}

// storedDiagnostics returns the ID of a stored bundle of a device of its own, kept past the development stack's
// seconds-long retention.
func storedDiagnostics(t *testing.T, w *auditWorld) string {
	t.Helper()
	d, b := diagnosticsDevice(t, w.alice)
	res := requestDiagnostics(t, w.alice, d.DeviceID, "A3 "+uniqueSuffix())
	expectStatus(t, res, http.StatusAccepted, "")
	id := responseID(t, res).String()
	archive, _ := diagnosticsArchive(t, id)
	uploadDiagnostics(t, d, b, id, archive)
	stored := waitDiagnostics(t, w.alice, id, 2*time.Minute, func(b diagnosticsBundle) bool { return b.State != "requested" && b.State != "uploaded" })
	if stored.State != "stored" {
		t.Fatalf("bundle %+v, want stored", stored)
	}
	keepDiagnostics(t, id)
	return id
}

// diagnosticsAuditCases are the A3 cases of the diagnostics operations (plan M12, ADR 0048).
var diagnosticsAuditCases = map[string][]auditCase{
	"POST /api/v1/devices/{id}/diagnostics": {
		{"success", func(t *testing.T, w *auditWorld) {
			d := v2Device(t, w.alice, "", 1, 2)
			res := requestDiagnostics(t, w.alice, d.DeviceID, "A3 request "+uniqueSuffix())
			expectStatus(t, res, http.StatusAccepted, "")
			expectOneEvent(t, w.alice, res.RequestID, "device.diagnostics_requested", "success")
		}},
		{"wrong role", func(t *testing.T, w *auditWorld) {
			res := requestDiagnostics(t, w.bob, activeID(t, w), "A3 auditor")
			expectStatus(t, res, http.StatusForbidden, "forbidden")
			expectOneEvent(t, w.alice, res.RequestID, "device.diagnostics_requested", "denied")
		}},
		{"validation failure", func(t *testing.T, w *auditWorld) {
			res := requestDiagnostics(t, w.alice, activeID(t, w), "x")
			expectStatus(t, res, http.StatusUnprocessableEntity, "invalid_request")
			expectOneEvent(t, w.alice, res.RequestID, "device.diagnostics_requested", "failure")
		}},
		{"not found", func(t *testing.T, w *auditWorld) {
			res := requestDiagnostics(t, w.alice, uuid.NewString(), "A3 missing device")
			expectStatus(t, res, http.StatusNotFound, "not_found")
			expectOneEvent(t, w.alice, res.RequestID, "device.diagnostics_requested", "failure")
		}},
		{"conflict", func(t *testing.T, w *auditWorld) {
			d := v2Device(t, w.alice, "", 1, 2)
			expectStatus(t, requestDiagnostics(t, w.alice, d.DeviceID, "A3 first"), http.StatusAccepted, "")
			res := requestDiagnostics(t, w.alice, d.DeviceID, "A3 second")
			expectStatus(t, res, http.StatusConflict, "invalid_state")
			expectOneEvent(t, w.alice, res.RequestID, "device.diagnostics_requested", "failure")
		}},
	},
	"GET /api/v1/diagnostics/{id}/download": {
		{"success", func(t *testing.T, w *auditWorld) {
			id := storedDiagnostics(t, w)
			user := w.admins.take()
			admin := login(t, user)
			stepUp(t, admin, user, true)
			res := call(t, admin, http.MethodGet, "/api/v1/diagnostics/"+id+"/download", nil)
			expectStatus(t, res, http.StatusOK, "")
			expectOneEvent(t, w.alice, res.RequestID, "device.diagnostics_downloaded", "success")
		}},
		{"no step-up", func(t *testing.T, w *auditWorld) {
			res := call(t, login(t, env.Alice), http.MethodGet, "/api/v1/diagnostics/"+requestedDiagnostics(t, w)+"/download", nil)
			expectStatus(t, res, http.StatusForbidden, "step_up_required")
			expectOneEvent(t, w.alice, res.RequestID, "device.diagnostics_downloaded", "denied")
		}},
		{"wrong role", func(t *testing.T, w *auditWorld) {
			res := call(t, w.bob, http.MethodGet, "/api/v1/diagnostics/"+requestedDiagnostics(t, w)+"/download", nil)
			expectStatus(t, res, http.StatusForbidden, "forbidden")
			expectOneEvent(t, w.alice, res.RequestID, "device.diagnostics_downloaded", "denied")
		}},
		{"not found", func(t *testing.T, w *auditWorld) {
			user := w.admins.take()
			admin := login(t, user)
			stepUp(t, admin, user, true)
			res := call(t, admin, http.MethodGet, "/api/v1/diagnostics/"+uuid.NewString()+"/download", nil)
			expectStatus(t, res, http.StatusNotFound, "not_found")
			expectOneEvent(t, w.alice, res.RequestID, "device.diagnostics_downloaded", "failure")
		}},
		{"conflict", func(t *testing.T, w *auditWorld) {
			id := requestedDiagnostics(t, w)
			user := w.admins.take()
			admin := login(t, user)
			stepUp(t, admin, user, true)
			res := call(t, admin, http.MethodGet, "/api/v1/diagnostics/"+id+"/download", nil)
			expectStatus(t, res, http.StatusConflict, "invalid_state")
			expectOneEvent(t, w.alice, res.RequestID, "device.diagnostics_downloaded", "failure")
		}},
	},
	"POST /api/v1/diagnostics/{id}/purge": {
		{"success", func(t *testing.T, w *auditWorld) {
			res := call(t, w.alice, http.MethodPost, "/api/v1/diagnostics/"+storedDiagnostics(t, w)+"/purge", nil)
			expectStatus(t, res, http.StatusOK, "")
			expectOneEvent(t, w.alice, res.RequestID, "device.diagnostics_purged", "success")
		}},
		{"wrong role", func(t *testing.T, w *auditWorld) {
			res := call(t, w.bob, http.MethodPost, "/api/v1/diagnostics/"+requestedDiagnostics(t, w)+"/purge", nil)
			expectStatus(t, res, http.StatusForbidden, "forbidden")
			expectOneEvent(t, w.alice, res.RequestID, "device.diagnostics_purged", "denied")
		}},
		{"not found", func(t *testing.T, w *auditWorld) {
			res := call(t, w.alice, http.MethodPost, "/api/v1/diagnostics/"+uuid.NewString()+"/purge", nil)
			expectStatus(t, res, http.StatusNotFound, "not_found")
			expectOneEvent(t, w.alice, res.RequestID, "device.diagnostics_purged", "failure")
		}},
		{"conflict", func(t *testing.T, w *auditWorld) {
			res := call(t, w.alice, http.MethodPost, "/api/v1/diagnostics/"+requestedDiagnostics(t, w)+"/purge", nil)
			expectStatus(t, res, http.StatusConflict, "invalid_state")
			expectOneEvent(t, w.alice, res.RequestID, "device.diagnostics_purged", "failure")
		}},
	},
}
