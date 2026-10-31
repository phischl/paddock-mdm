package acceptance

import (
	"net/http"
	"testing"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/test/acceptance/internal/env"
)

const (
	orgDestinations      = "/api/v1/notification-destinations"
	platformDestinations = "/api/platform/v1/notification-destinations"
)

// auditDestination creates a webhook destination for a case and returns its path; pseudonymize also creates the
// organization's pseudonym key.
func auditDestination(t *testing.T, s stepper, collection string, pseudonymize bool) string {
	t.Helper()
	body := webhookBody(destinationName("a3"), notificationURL)
	body["pseudonymize_users"] = pseudonymize
	d, _ := createDestination(t, s, collection, body)
	return collection + "/" + d.ID
}

func destinationUpdate(heartbeat int) map[string]any {
	return map[string]any{"name": destinationName("a3 upd"), "enabled": true, "filter_mode": "all", "heartbeat_interval_s": heartbeat}
}

// orgDestinationCases are the cases of a privileged operation on one organization destination: suffix follows the
// destination path, success is the expected status, body builds the request body.
func orgDestinationCases(code, suffix, method string, success int, body func() any) []auditCase {
	return []auditCase{
		{"success", func(t *testing.T, w *auditWorld) {
			s := adminStepper(adminUser(t, "a3-notif"))
			path := auditDestination(t, s, orgDestinations, suffix == "/resolve-pseudonym") + suffix
			s.stepUp(t)
			res := call(t, s.Portal, method, path, body())
			expectStatus(t, res, success, "")
			expectOneEvent(t, w.alice, res.RequestID, code, "success")
		}},
		{"not found", func(t *testing.T, w *auditWorld) {
			s := adminStepper(adminUser(t, "a3-notif"))
			res := call(t, s.Portal, method, orgDestinations+"/"+uuid.NewString()+suffix, body())
			expectStatus(t, res, http.StatusNotFound, "not_found")
			expectOneEvent(t, w.alice, res.RequestID, code, "failure")
		}},
		{"wrong role", func(t *testing.T, w *auditWorld) {
			res := call(t, w.bob, method, orgDestinations+"/"+uuid.NewString()+suffix, body())
			expectStatus(t, res, http.StatusForbidden, "forbidden")
			expectOneEvent(t, w.alice, res.RequestID, code, "denied")
		}},
		{"no step-up", func(t *testing.T, w *auditWorld) {
			res := call(t, login(t, env.Alice), method, orgDestinations+"/"+uuid.NewString()+suffix, body())
			expectStatus(t, res, http.StatusForbidden, "step_up_required")
			expectOneEvent(t, w.alice, res.RequestID, code, "denied")
		}},
	}
}

// platformDestinationCases are orgDestinationCases for the platform scope: its events are in the platform
// pseudo-organization, an organization administrator's refusal in the administrator's organization.
func platformDestinationCases(code, suffix, method string, success int, body func() any) []auditCase {
	return []auditCase{
		{"success", func(t *testing.T, w *auditWorld) {
			s := rootStepper(t)
			path := auditDestination(t, s, platformDestinations, false) + suffix
			s.stepUp(t)
			res := call(t, s.Portal, method, path, body())
			expectStatus(t, res, success, "")
			expectOneIndexEvent(t, w.idx, platformOrg, "correlation_id = $1", res.RequestID, code, "success", auditPollTimeout)
		}},
		{"not found", func(t *testing.T, w *auditWorld) {
			res := call(t, steppedUpRoot(t), method, platformDestinations+"/"+uuid.NewString()+suffix, body())
			expectStatus(t, res, http.StatusNotFound, "not_found")
			expectOneIndexEvent(t, w.idx, platformOrg, "correlation_id = $1", res.RequestID, code, "failure", auditPollTimeout)
		}},
		{"wrong role", func(t *testing.T, w *auditWorld) {
			res := call(t, w.alice, method, platformDestinations+"/"+uuid.NewString()+suffix, body())
			expectStatus(t, res, http.StatusForbidden, "forbidden")
			expectOneEvent(t, w.alice, res.RequestID, code, "denied")
		}},
		{"no step-up", func(t *testing.T, w *auditWorld) {
			res := call(t, login(t, env.PlatformAdmin), method, platformDestinations+"/"+uuid.NewString()+suffix, body())
			expectStatus(t, res, http.StatusForbidden, "step_up_required")
			expectOneIndexEvent(t, w.idx, platformOrg, "correlation_id = $1", res.RequestID, code, "denied", auditPollTimeout)
		}},
	}
}

func noBody() any { return nil }

// createDestinationCases are the cases of a destination creation in one scope.
func createDestinationCases(collection string, platform bool) []auditCase {
	const code = "notification.destination_created"
	expect := func(t *testing.T, w *auditWorld, res env.Response, outcome string) {
		t.Helper()
		if platform {
			expectOneIndexEvent(t, w.idx, platformOrg, "correlation_id = $1", res.RequestID, code, outcome, auditPollTimeout)
			return
		}
		expectOneEvent(t, w.alice, res.RequestID, code, outcome)
	}
	stepped := func(t *testing.T) stepper {
		if platform {
			return rootStepper(t)
		}
		return adminStepper(adminUser(t, "a3-notif"))
	}
	return []auditCase{
		{"success", func(t *testing.T, w *auditWorld) {
			_, res := createDestination(t, stepped(t), collection, webhookBody(destinationName("a3"), notificationURL))
			expect(t, w, res, "success")
		}},
		{"validation failure", func(t *testing.T, w *auditWorld) {
			s := stepped(t)
			s.stepUp(t)
			res := call(t, s.Portal, http.MethodPost, collection, webhookBody(destinationName("a3"), "https://user:pw@93.184.215.14/"))
			expectStatus(t, res, http.StatusBadRequest, "invalid_request")
			expect(t, w, res, "failure")
		}},
		{"no step-up", func(t *testing.T, w *auditWorld) {
			user := env.Alice
			if platform {
				user = env.PlatformAdmin
			}
			res := call(t, login(t, user), http.MethodPost, collection, webhookBody(destinationName("a3"), notificationURL))
			expectStatus(t, res, http.StatusForbidden, "step_up_required")
			expect(t, w, res, "denied")
		}},
		{"wrong role", func(t *testing.T, w *auditWorld) {
			viewer := w.bob
			if platform {
				viewer = w.alice
			}
			res := call(t, viewer, http.MethodPost, collection, webhookBody(destinationName("a3"), notificationURL))
			expectStatus(t, res, http.StatusForbidden, "forbidden")
			expectOneEvent(t, w.alice, res.RequestID, code, "denied")
		}},
	}
}

// notificationAuditCases are the cases of the notification destination operations (plan M9 decision 19).
var notificationAuditCases = map[string][]auditCase{
	"POST /api/v1/notification-destinations": createDestinationCases(orgDestinations, false),
	"PUT /api/v1/notification-destinations/{id}": append(
		orgDestinationCases("notification.destination_updated", "", http.MethodPut, http.StatusOK, func() any { return destinationUpdate(0) }),
		auditCase{"validation failure", func(t *testing.T, w *auditWorld) {
			s := adminStepper(adminUser(t, "a3-notif"))
			path := auditDestination(t, s, orgDestinations, false)
			s.stepUp(t)
			res := call(t, s.Portal, http.MethodPut, path, destinationUpdate(30))
			expectStatus(t, res, http.StatusBadRequest, "invalid_request")
			expectOneEvent(t, w.alice, res.RequestID, "notification.destination_updated", "failure")
		}}),
	"DELETE /api/v1/notification-destinations/{id}": orgDestinationCases("notification.destination_deleted", "", http.MethodDelete,
		http.StatusNoContent, noBody),
	"POST /api/v1/notification-destinations/{id}/rotate-secret": orgDestinationCases("notification.destination_secret_rotated",
		"/rotate-secret", http.MethodPost, http.StatusOK, noBody),
	"POST /api/v1/notification-destinations/{id}/test": orgDestinationCases("notification.test_requested", "/test",
		http.MethodPost, http.StatusAccepted, noBody),
	"POST /api/v1/notification-destinations/{id}/resolve-pseudonym": append(
		orgDestinationCases("notification.pseudonym_resolved", "/resolve-pseudonym", http.MethodPost, http.StatusAccepted,
			func() any { return map[string]any{"pseudonym": "u_0123456789abcdef01234567"} }),
		auditCase{"validation failure", func(t *testing.T, w *auditWorld) {
			s := adminStepper(adminUser(t, "a3-notif"))
			path := auditDestination(t, s, orgDestinations, true)
			s.stepUp(t)
			res := call(t, s.Portal, http.MethodPost, path+"/resolve-pseudonym", map[string]any{"pseudonym": "alice"})
			expectStatus(t, res, http.StatusBadRequest, "invalid_request")
			expectOneEvent(t, w.alice, res.RequestID, "notification.pseudonym_resolved", "failure")
		}}),

	"POST /api/platform/v1/notification-destinations": createDestinationCases(platformDestinations, true),
	"PUT /api/platform/v1/notification-destinations/{id}": platformDestinationCases("notification.destination_updated", "",
		http.MethodPut, http.StatusOK, func() any { return destinationUpdate(0) }),
	"DELETE /api/platform/v1/notification-destinations/{id}": platformDestinationCases("notification.destination_deleted", "",
		http.MethodDelete, http.StatusNoContent, noBody),
	"POST /api/platform/v1/notification-destinations/{id}/rotate-secret": platformDestinationCases(
		"notification.destination_secret_rotated", "/rotate-secret", http.MethodPost, http.StatusOK, noBody),
	"POST /api/platform/v1/notification-destinations/{id}/test": platformDestinationCases("notification.test_requested", "/test",
		http.MethodPost, http.StatusAccepted, noBody),
}
