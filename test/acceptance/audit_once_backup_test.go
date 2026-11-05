package acceptance

import (
	"net/http"
	"testing"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/test/acceptance/internal/env"
)

const backupTargets = "/api/platform/v1/backup/targets"

// backupAuditCases are the A3 cases of the backup targets, schedule and runs (plan M15 decisions 10–14). The backup
// tables and the schedule are platform-wide state that the backup gates own: here only the cases that leave it as it
// is.
var backupAuditCases = map[string][]auditCase{
	"POST /api/platform/v1/backup/targets": append(backupRefusals("platform.backup_target_created", http.MethodPost,
		func() string { return backupTargets }, func() any { return backupTargetBody() }),
		auditCase{"validation failure", func(t *testing.T, w *auditWorld) {
			body := backupTargetBody()
			body["local"] = map[string]any{"path": "/absolute"}
			res := call(t, steppedUpRoot(t), http.MethodPost, backupTargets, body)
			expectStatus(t, res, http.StatusBadRequest, "invalid_request")
			expectOneIndexEvent(t, w.idx, platformOrg, "correlation_id = $1", res.RequestID, "platform.backup_target_created", "failure", auditPollTimeout)
		}}),
	"PUT /api/platform/v1/backup/targets/{id}": backupTargetCases("platform.backup_target_updated", http.MethodPut, "",
		func() any { return backupTargetBody() }),
	"DELETE /api/platform/v1/backup/targets/{id}":    backupTargetCases("platform.backup_target_deleted", http.MethodDelete, "", noBody),
	"POST /api/platform/v1/backup/targets/{id}/test": backupTargetCases("platform.backup_target_tested", http.MethodPost, "/test", noBody),
	"POST /api/platform/v1/backup/targets/{id}/enable": backupTargetCases("platform.backup_target_updated", http.MethodPost, "/enable",
		noBody),
	"POST /api/platform/v1/backup/targets/{id}/disable": backupTargetCases("platform.backup_target_updated", http.MethodPost,
		"/disable", noBody),
	"PUT /api/platform/v1/backup/schedule": append(backupRefusals("platform.backup_schedule_changed", http.MethodPut,
		func() string { return "/api/platform/v1/backup/schedule" }, func() any { return backupScheduleBody(24) }),
		auditCase{"validation failure", func(t *testing.T, w *auditWorld) {
			res := call(t, steppedUpRoot(t), http.MethodPut, "/api/platform/v1/backup/schedule", backupScheduleBody(1))
			expectStatus(t, res, http.StatusBadRequest, "invalid_request")
			expectOneIndexEvent(t, w.idx, platformOrg, "correlation_id = $1", res.RequestID, "platform.backup_schedule_changed", "failure", auditPollTimeout)
		}}),
	"POST /api/platform/v1/backup/run": append(backupRefusals("platform.backup_run_requested", http.MethodPost,
		func() string { return "/api/platform/v1/backup/run" }, func() any { return map[string]any{"kinds": []string{"openbao"}} }),
		auditCase{"validation failure", func(t *testing.T, w *auditWorld) {
			res := call(t, steppedUpRoot(t), http.MethodPost, "/api/platform/v1/backup/run", map[string]any{"kinds": []string{"audit"}})
			expectStatus(t, res, http.StatusBadRequest, "invalid_request")
			expectOneIndexEvent(t, w.idx, platformOrg, "correlation_id = $1", res.RequestID, "platform.backup_run_requested", "failure", auditPollTimeout)
		}}),
}

func backupTargetBody() map[string]any {
	return map[string]any{"name": "a3 backup", "type": "local", "enabled": true, "local": map[string]any{"path": "a3"}}
}

func backupScheduleBody(fullHours int) map[string]any {
	return map[string]any{"full_interval_hours": fullHours, "openbao_interval_hours": 6, "fleet_interval_hours": 24,
		"escrow_interval_hours": 1, "retention_full": 14, "openbao_keep_days": 30, "fleet_keep_days": 30}
}

// backupRefusals are the wrong-role and no-step-up cases of a platform backup operation.
func backupRefusals(code, method string, path func() string, body func() any) []auditCase {
	return []auditCase{
		{"wrong role", func(t *testing.T, w *auditWorld) {
			res := call(t, w.alice, method, path(), body())
			expectStatus(t, res, http.StatusForbidden, "forbidden")
			expectOneEvent(t, w.alice, res.RequestID, code, "denied")
		}},
		{"no step-up", func(t *testing.T, w *auditWorld) {
			res := call(t, login(t, env.PlatformAdmin), method, path(), body())
			expectStatus(t, res, http.StatusForbidden, "step_up_required")
			expectOneIndexEvent(t, w.idx, platformOrg, "correlation_id = $1", res.RequestID, code, "denied", auditPollTimeout)
		}},
	}
}

// backupTargetCases are the cases of an operation on one target: refusals and a target that does not exist.
func backupTargetCases(code, method, suffix string, body func() any) []auditCase {
	path := func() string { return backupTargets + "/" + uuid.NewString() + suffix }
	return append(backupRefusals(code, method, path, body), auditCase{"not found", func(t *testing.T, w *auditWorld) {
		res := call(t, steppedUpRoot(t), method, path(), body())
		expectStatus(t, res, http.StatusNotFound, "not_found")
		expectOneIndexEvent(t, w.idx, platformOrg, "correlation_id = $1", res.RequestID, code, "failure", auditPollTimeout)
	}})
}
