package acceptance

import (
	"net/http"
	"testing"

	"github.com/phischl/paddock-mdm/test/acceptance/internal/env"
)

const backupKeyPath = "/api/platform/v1/backup/key"

// missingBackupKey is a well-formed key ID that no stack ever generates on that day.
const missingBackupKey = "bk-20000101-00000000"

// backupKeyAuditCases are the A3 cases of the backup key (plan M15 decision 7). The key is platform-wide state that the
// backup gates own: here only the cases that leave it as it is.
var backupKeyAuditCases = map[string][]auditCase{
	"POST /api/platform/v1/backup/key": backupKeyRefusals("platform.backup_key_generated", backupKeyPath, nil),
	"POST /api/platform/v1/backup/key/{id}/confirm": append(backupKeyRefusals("platform.backup_key_confirmed",
		backupKeyPath+"/"+missingBackupKey+"/confirm", map[string]any{"answer": "abcdef"}),
		auditCase{"not found", func(t *testing.T, w *auditWorld) {
			res := call(t, steppedUpRoot(t), http.MethodPost, backupKeyPath+"/"+missingBackupKey+"/confirm", map[string]any{"answer": "abcdef"})
			expectStatus(t, res, http.StatusNotFound, "not_found")
			expectOneIndexEvent(t, w.idx, platformOrg, "correlation_id = $1", res.RequestID, "platform.backup_key_confirmed", "failure", auditPollTimeout)
		}},
		auditCase{"validation failure", func(t *testing.T, w *auditWorld) {
			res := call(t, steppedUpRoot(t), http.MethodPost, backupKeyPath+"/"+missingBackupKey+"/confirm", map[string]any{"answer": "abc"})
			expectStatus(t, res, http.StatusBadRequest, "invalid_request")
			expectOneIndexEvent(t, w.idx, platformOrg, "correlation_id = $1", res.RequestID, "platform.backup_key_confirmed", "failure", auditPollTimeout)
		}}),
	"POST /api/platform/v1/backup/key/{id}/discard": append(backupKeyRefusals("platform.backup_key_discarded",
		backupKeyPath+"/"+missingBackupKey+"/discard", nil),
		auditCase{"not found", func(t *testing.T, w *auditWorld) {
			res := call(t, steppedUpRoot(t), http.MethodPost, backupKeyPath+"/"+missingBackupKey+"/discard", nil)
			expectStatus(t, res, http.StatusNotFound, "not_found")
			expectOneIndexEvent(t, w.idx, platformOrg, "correlation_id = $1", res.RequestID, "platform.backup_key_discarded", "failure", auditPollTimeout)
		}}),
}

// backupKeyRefusals are the wrong-role and no-step-up cases of a backup key operation.
func backupKeyRefusals(code, path string, body any) []auditCase {
	return []auditCase{
		{"wrong role", func(t *testing.T, w *auditWorld) {
			res := call(t, w.alice, http.MethodPost, path, body)
			expectStatus(t, res, http.StatusForbidden, "forbidden")
			expectOneEvent(t, w.alice, res.RequestID, code, "denied")
		}},
		{"no step-up", func(t *testing.T, w *auditWorld) {
			res := call(t, login(t, env.PlatformAdmin), http.MethodPost, path, body)
			expectStatus(t, res, http.StatusForbidden, "step_up_required")
			expectOneIndexEvent(t, w.idx, platformOrg, "correlation_id = $1", res.RequestID, code, "denied", auditPollTimeout)
		}},
	}
}
