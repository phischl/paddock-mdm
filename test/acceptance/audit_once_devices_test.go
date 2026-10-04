package acceptance

import (
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/paddock-mdm/paddock/pkg/protocol"
	"github.com/paddock-mdm/paddock/test/acceptance/devicesim"
)

// pendingDevice enrolls a device with a manual-approval token and returns its ID.
func pendingDevice(t *testing.T, w *auditWorld) string {
	t.Helper()
	tok := createToken(t, w.alice, tokenOptions{})
	_, s := enroll(t, tok.EnrollmentConfig, "a3-pending-"+uniqueSuffix())
	if s.Status != protocol.EnrollPending {
		t.Fatalf("enrollment %+v, want pending", s)
	}
	return s.DeviceID
}

// quarantinedDevice clones an active device and lets the clone check in with a stale sequence number.
func quarantinedDevice(t *testing.T, w *auditWorld) string {
	t.Helper()
	d := activeDevice(t, w.alice, "", "a3-clone-"+uniqueSuffix())
	clone := d.Clone()
	ctx := testContext(t, time.Minute)
	for _, dev := range []*devicesim.Device{d, d, clone} {
		if _, res, err := dev.Checkin(ctx); err != nil || res.Status != http.StatusOK {
			t.Fatalf("checkin: %v %d", err, res.Status)
		}
	}
	waitDevice(t, w.alice, d.DeviceID, 15*time.Second, func(s deviceState) bool { return s.State == "quarantined" })
	return d.DeviceID
}

// deviceAction returns the cases of POST /api/v1/devices/{id}:<action>: success on a device in a state that allows
// it, denial for the auditor, a missing device, and a conflict on a device in a state that does not.
func deviceAction(action, code string, allowed, refused func(t *testing.T, w *auditWorld) string) []auditCase {
	path := func(id string) string { return "/api/v1/devices/" + id + ":" + action }
	return []auditCase{
		{"success", func(t *testing.T, w *auditWorld) {
			res := call(t, w.alice, http.MethodPost, path(allowed(t, w)), nil)
			expectStatus(t, res, http.StatusOK, "")
			expectOneEvent(t, w.alice, res.RequestID, code, "success")
		}},
		{"wrong role", func(t *testing.T, w *auditWorld) {
			res := call(t, w.bob, http.MethodPost, path(allowed(t, w)), nil)
			expectStatus(t, res, http.StatusForbidden, "forbidden")
			expectOneEvent(t, w.alice, res.RequestID, code, "denied")
		}},
		{"not found", func(t *testing.T, w *auditWorld) {
			res := call(t, w.alice, http.MethodPost, path(uuid.NewString()), nil)
			expectStatus(t, res, http.StatusNotFound, "not_found")
			expectOneEvent(t, w.alice, res.RequestID, code, "failure")
		}},
		{"conflict", func(t *testing.T, w *auditWorld) {
			res := call(t, w.alice, http.MethodPost, path(refused(t, w)), nil)
			expectStatus(t, res, http.StatusConflict, "invalid_state")
			expectOneEvent(t, w.alice, res.RequestID, code, "failure")
		}},
	}
}

func activeID(t *testing.T, w *auditWorld) string {
	return activeDevice(t, w.alice, "", "a3-active-"+uniqueSuffix()).DeviceID
}

func tokenBody(maxUses int) map[string]any {
	return map[string]any{"name": uniqueName("a3 token"), "max_uses": maxUses, "auto_approve": false,
		"expires_at": time.Now().Add(time.Hour).UTC().Format(time.RFC3339)}
}

// managedCases returns the cases of the managed file or unit operations below collection.
func managedCases(collection, kind string, valid func() map[string]any, invalid map[string]any, invalidCode string, invalidStatus int) map[string][]auditCase {
	create := func(t *testing.T, w *auditWorld) string {
		res := call(t, w.alice, http.MethodPost, collection, valid())
		expectStatus(t, res, http.StatusCreated, "")
		return responseID(t, res).String()
	}
	return map[string][]auditCase{
		"POST " + collection: {
			{"success", func(t *testing.T, w *auditWorld) {
				res := call(t, w.alice, http.MethodPost, collection, valid())
				expectStatus(t, res, http.StatusCreated, "")
				expectOneEvent(t, w.alice, res.RequestID, kind+".created", "success")
			}},
			{"validation failure", func(t *testing.T, w *auditWorld) {
				res := call(t, w.alice, http.MethodPost, collection, invalid)
				expectStatus(t, res, invalidStatus, invalidCode)
				expectOneEvent(t, w.alice, res.RequestID, kind+".created", "failure")
			}},
			{"wrong role", func(t *testing.T, w *auditWorld) {
				res := call(t, w.bob, http.MethodPost, collection, valid())
				expectStatus(t, res, http.StatusForbidden, "forbidden")
				expectOneEvent(t, w.alice, res.RequestID, kind+".created", "denied")
			}},
			{"conflict", func(t *testing.T, w *auditWorld) {
				body := valid()
				expectStatus(t, call(t, w.alice, http.MethodPost, collection, body), http.StatusCreated, "")
				res := call(t, w.alice, http.MethodPost, collection, body)
				expectStatus(t, res, http.StatusConflict, "already_exists")
				expectOneEvent(t, w.alice, res.RequestID, kind+".created", "failure")
			}},
		},
		"PATCH " + collection + "/{id}": {
			{"success", func(t *testing.T, w *auditWorld) {
				res := call(t, w.alice, http.MethodPatch, collection+"/"+create(t, w), valid())
				expectStatus(t, res, http.StatusOK, "")
				expectOneEvent(t, w.alice, res.RequestID, kind+".updated", "success")
			}},
			{"validation failure", func(t *testing.T, w *auditWorld) {
				res := call(t, w.alice, http.MethodPatch, collection+"/"+create(t, w), invalid)
				expectStatus(t, res, invalidStatus, invalidCode)
				expectOneEvent(t, w.alice, res.RequestID, kind+".updated", "failure")
			}},
			{"wrong role", func(t *testing.T, w *auditWorld) {
				res := call(t, w.bob, http.MethodPatch, collection+"/"+create(t, w), valid())
				expectStatus(t, res, http.StatusForbidden, "forbidden")
				expectOneEvent(t, w.alice, res.RequestID, kind+".updated", "denied")
			}},
			{"not found", func(t *testing.T, w *auditWorld) {
				res := call(t, w.alice, http.MethodPatch, collection+"/"+uuid.NewString(), valid())
				expectStatus(t, res, http.StatusNotFound, "not_found")
				expectOneEvent(t, w.alice, res.RequestID, kind+".updated", "failure")
			}},
		},
		"DELETE " + collection + "/{id}": {
			{"success", func(t *testing.T, w *auditWorld) {
				res := call(t, w.alice, http.MethodDelete, collection+"/"+create(t, w), nil)
				expectStatus(t, res, http.StatusNoContent, "")
				expectOneEvent(t, w.alice, res.RequestID, kind+".deleted", "success")
			}},
			{"validation failure", func(t *testing.T, w *auditWorld) {
				res := call(t, w.alice, http.MethodDelete, collection+"/not-a-uuid", nil)
				expectStatus(t, res, http.StatusBadRequest, "invalid_request")
				expectOneEvent(t, w.alice, res.RequestID, kind+".deleted", "failure")
			}},
			{"wrong role", func(t *testing.T, w *auditWorld) {
				res := call(t, w.bob, http.MethodDelete, collection+"/"+create(t, w), nil)
				expectStatus(t, res, http.StatusForbidden, "forbidden")
				expectOneEvent(t, w.alice, res.RequestID, kind+".deleted", "denied")
			}},
			{"not found", func(t *testing.T, w *auditWorld) {
				res := call(t, w.alice, http.MethodDelete, collection+"/"+uuid.NewString(), nil)
				expectStatus(t, res, http.StatusNotFound, "not_found")
				expectOneEvent(t, w.alice, res.RequestID, kind+".deleted", "failure")
			}},
		},
	}
}

// deviceAuditCases are the A3 cases of the M2a operations (plan M2a §8: the existing gates include them).
var deviceAuditCases = func() map[string][]auditCase {
	cases := map[string][]auditCase{
		"POST /api/v1/enrollment-tokens": {
			{"success", func(t *testing.T, w *auditWorld) {
				res := call(t, w.alice, http.MethodPost, "/api/v1/enrollment-tokens", tokenBody(1))
				expectStatus(t, res, http.StatusCreated, "")
				expectOneEvent(t, w.alice, res.RequestID, "enrollment_token.created", "success")
			}},
			{"validation failure", func(t *testing.T, w *auditWorld) {
				res := call(t, w.alice, http.MethodPost, "/api/v1/enrollment-tokens", tokenBody(0))
				expectStatus(t, res, http.StatusBadRequest, "invalid_request")
				expectOneEvent(t, w.alice, res.RequestID, "enrollment_token.created", "failure")
			}},
			{"wrong role", func(t *testing.T, w *auditWorld) {
				res := call(t, w.bob, http.MethodPost, "/api/v1/enrollment-tokens", tokenBody(1))
				expectStatus(t, res, http.StatusForbidden, "forbidden")
				expectOneEvent(t, w.alice, res.RequestID, "enrollment_token.created", "denied")
			}},
		},
		"POST /api/v1/enrollment-tokens/{id}:revoke": {
			{"success", func(t *testing.T, w *auditWorld) {
				res := call(t, w.alice, http.MethodPost, "/api/v1/enrollment-tokens/"+createToken(t, w.alice, tokenOptions{}).Token.ID+":revoke", nil)
				expectStatus(t, res, http.StatusOK, "")
				expectOneEvent(t, w.alice, res.RequestID, "enrollment_token.revoked", "success")
			}},
			{"validation failure", func(t *testing.T, w *auditWorld) {
				res := call(t, w.alice, http.MethodPost, "/api/v1/enrollment-tokens/not-a-uuid:revoke", nil)
				expectStatus(t, res, http.StatusBadRequest, "invalid_request")
				expectOneEvent(t, w.alice, res.RequestID, "enrollment_token.revoked", "failure")
			}},
			{"wrong role", func(t *testing.T, w *auditWorld) {
				res := call(t, w.bob, http.MethodPost, "/api/v1/enrollment-tokens/"+createToken(t, w.alice, tokenOptions{}).Token.ID+":revoke", nil)
				expectStatus(t, res, http.StatusForbidden, "forbidden")
				expectOneEvent(t, w.alice, res.RequestID, "enrollment_token.revoked", "denied")
			}},
			{"not found", func(t *testing.T, w *auditWorld) {
				res := call(t, w.alice, http.MethodPost, "/api/v1/enrollment-tokens/"+uuid.NewString()+":revoke", nil)
				expectStatus(t, res, http.StatusNotFound, "not_found")
				expectOneEvent(t, w.alice, res.RequestID, "enrollment_token.revoked", "failure")
			}},
		},
		"POST /api/v1/devices/{id}:approve":            deviceAction("approve", "device.approved", pendingDevice, activeID),
		"POST /api/v1/devices/{id}:reject":             deviceAction("reject", "device.rejected", pendingDevice, activeID),
		"POST /api/v1/devices/{id}:release-quarantine": deviceAction("release-quarantine", "device.quarantine_released", quarantinedDevice, activeID),
		"POST /api/v1/devices/{id}:retire":             deviceAction("retire", "device.retired", activeID, pendingDevice),
		"PUT /api/v1/devices/{id}/groups": {
			{"success", func(t *testing.T, w *auditWorld) {
				res := call(t, w.alice, http.MethodPut, "/api/v1/devices/"+activeID(t, w)+"/groups",
					map[string]any{"device_group_ids": []string{createGroup(t, w.alice).id}})
				expectStatus(t, res, http.StatusOK, "")
				expectOneEvent(t, w.alice, res.RequestID, "device.groups_changed", "success")
			}},
			{"validation failure", func(t *testing.T, w *auditWorld) {
				res := call(t, w.alice, http.MethodPut, "/api/v1/devices/"+activeID(t, w)+"/groups",
					map[string]any{"device_group_ids": []string{uuid.NewString()}})
				expectStatus(t, res, http.StatusBadRequest, "invalid_request")
				expectOneEvent(t, w.alice, res.RequestID, "device.groups_changed", "failure")
			}},
			{"wrong role", func(t *testing.T, w *auditWorld) {
				res := call(t, w.bob, http.MethodPut, "/api/v1/devices/"+activeID(t, w)+"/groups", map[string]any{"device_group_ids": []string{}})
				expectStatus(t, res, http.StatusForbidden, "forbidden")
				expectOneEvent(t, w.alice, res.RequestID, "device.groups_changed", "denied")
			}},
			{"not found", func(t *testing.T, w *auditWorld) {
				res := call(t, w.alice, http.MethodPut, "/api/v1/devices/"+uuid.NewString()+"/groups", map[string]any{"device_group_ids": []string{}})
				expectStatus(t, res, http.StatusNotFound, "not_found")
				expectOneEvent(t, w.alice, res.RequestID, "device.groups_changed", "failure")
			}},
		},
	}
	files := managedCases("/api/v1/managed-files", "managed_file",
		func() map[string]any {
			return map[string]any{"path": "/etc/a3-" + uniqueSuffix() + ".conf", "content": "a3"}
		},
		map[string]any{"path": "/etc/sudoers.d/a3", "content": "a3"}, "path_not_allowed", http.StatusUnprocessableEntity)
	units := managedCases("/api/v1/managed-units", "managed_unit",
		func() map[string]any { return map[string]any{"unit": "a3-" + uniqueSuffix() + ".service"} },
		map[string]any{"unit": "sshd.service"}, "unit_not_allowed", http.StatusUnprocessableEntity)
	for _, m := range []map[string][]auditCase{files, units} {
		for k, v := range m {
			cases[k] = v
		}
	}
	return cases
}()
