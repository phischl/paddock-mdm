package acceptance

import (
	"net/http"
	"testing"

	"github.com/phischl/paddock-mdm/test/acceptance/internal/env"
)

// accessReviewAuditCases are the cases of the exports and the platform view of the access review (plan M12 decisions
// 25 and 26). The organization view is not listed: it is recorded only under a privacy setting and has no x-paddock-audit.
var accessReviewAuditCases = map[string][]auditCase{
	"GET /api/v1/access-review/export": {
		{"success", func(t *testing.T, w *auditWorld) {
			res := call(t, w.alice, http.MethodGet, "/api/v1/access-review/export?format=csv", nil)
			expectStatus(t, res, http.StatusOK, "")
			expectOneEvent(t, w.alice, res.RequestID, "access_review.exported", "success")
		}},
		{"wrong role", func(t *testing.T, w *auditWorld) {
			operator := tempPortal(t, "a3-ar-op", env.RoleGroup("acme", "operators"))
			res := call(t, operator, http.MethodGet, "/api/v1/access-review/export?format=csv", nil)
			expectStatus(t, res, http.StatusForbidden, "forbidden")
			expectOneEvent(t, w.alice, res.RequestID, "access_review.exported", "denied")
		}},
	},
	"GET /api/platform/v1/access-review": platformAccessReviewCases("platform.access_review_viewed", "/api/platform/v1/access-review"),
	"GET /api/platform/v1/access-review/export": platformAccessReviewCases("platform.access_review_exported",
		"/api/platform/v1/access-review/export?format=csv"),
}

func platformAccessReviewCases(code, path string) []auditCase {
	return []auditCase{
		{"success", func(t *testing.T, w *auditWorld) {
			res := call(t, login(t, env.PlatformAdmin), http.MethodGet, path, nil)
			expectStatus(t, res, http.StatusOK, "")
			expectOneIndexEvent(t, w.idx, platformOrg, "correlation_id = $1", res.RequestID, code, "success", auditPollTimeout)
		}},
		{"wrong role", func(t *testing.T, w *auditWorld) {
			res := call(t, w.alice, http.MethodGet, path, nil)
			expectStatus(t, res, http.StatusForbidden, "forbidden")
			expectOneEvent(t, w.alice, res.RequestID, code, "denied")
		}},
	}
}
