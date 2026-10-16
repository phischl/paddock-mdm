package acceptance

import (
	"net/http"
	"testing"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/test/acceptance/internal/env"
)

// localUser creates a local acme user (deleted when the case ends) and returns its ID.
func localUser(t *testing.T, w *auditWorld) string { return createLocalUser(t, w.alice, "a3").ID }

// userGroup creates a local acme user group (deleted when the case ends) and returns its ID.
func userGroup(t *testing.T, p *env.Portal) string {
	t.Helper()
	res := call(t, p, http.MethodPost, "/api/v1/user-groups", map[string]string{"slug": "a3-" + uniqueSuffix(), "name": uniqueName("a3 group")})
	expectStatus(t, res, http.StatusCreated, "")
	return createdID(t, p, "/api/v1/user-groups", res)
}

// profile creates a permission profile (deleted when the case ends) and returns its ID.
func profile(t *testing.T, p *env.Portal, class string, commands ...string) string {
	t.Helper()
	body := map[string]any{"name": uniqueName("a3 profile"), "class": class}
	if len(commands) > 0 {
		body["commands"] = commands
	}
	res := call(t, p, http.MethodPost, "/api/v1/permission-profiles", body)
	expectStatus(t, res, http.StatusCreated, "")
	return createdID(t, p, "/api/v1/permission-profiles", res)
}

// assignment assigns a new restricted profile to a new group (deleted when the case ends) and returns its ID.
func assignment(t *testing.T, p *env.Portal) string {
	t.Helper()
	prof := profile(t, p, "restricted", "/usr/bin/systemctl restart a3.service")
	res := call(t, p, http.MethodPost, "/api/v1/profile-assignments", map[string]any{
		"profile_id": prof, "subject_type": "group", "subject_id": userGroup(t, p),
	})
	expectStatus(t, res, http.StatusCreated, "")
	return createdID(t, p, "/api/v1/profile-assignments", res)
}

// itemCases are the standard cases of an operation on one item: success, malformed ID, auditor (denied), missing.
func itemCases(method, collection, suffix, code string, okStatus int, create func(t *testing.T, w *auditWorld) string,
	body func(t *testing.T, w *auditWorld) any) []auditCase {
	path := func(id string) string { return collection + "/" + id + suffix }
	payload := func(t *testing.T, w *auditWorld) any {
		if body == nil {
			return nil
		}
		return body(t, w)
	}
	return []auditCase{
		{"success", func(t *testing.T, w *auditWorld) {
			res := call(t, w.alice, method, path(create(t, w)), payload(t, w))
			expectStatus(t, res, okStatus, "")
			expectOneEvent(t, w.alice, res.RequestID, code, "success")
		}},
		{"validation failure", func(t *testing.T, w *auditWorld) {
			res := call(t, w.alice, method, path("not-a-uuid"), payload(t, w))
			expectStatus(t, res, http.StatusBadRequest, "invalid_request")
			expectOneEvent(t, w.alice, res.RequestID, code, "failure")
		}},
		{"wrong role", func(t *testing.T, w *auditWorld) {
			res := call(t, w.bob, method, path(create(t, w)), payload(t, w))
			expectStatus(t, res, http.StatusForbidden, "forbidden")
			expectOneEvent(t, w.alice, res.RequestID, code, "denied")
		}},
		{"not found", func(t *testing.T, w *auditWorld) {
			res := call(t, w.alice, method, path(uuid.NewString()), payload(t, w))
			expectStatus(t, res, http.StatusNotFound, "not_found")
			expectOneEvent(t, w.alice, res.RequestID, code, "failure")
		}},
	}
}

// identityAuditCases are the A3 cases of the M3a operations (plan M3a §6: the existing gates cover all new endpoints).
var identityAuditCases = map[string][]auditCase{
	"PATCH /api/platform/v1/organizations/{id}": {
		{"success", func(t *testing.T, w *auditWorld) {
			res := call(t, w.root, http.MethodPatch, "/api/platform/v1/organizations/"+w.acme.String(), map[string]any{"domains": []string{"acme.test"}})
			expectStatus(t, res, http.StatusOK, "")
			expectOneIndexEvent(t, w.idx, w.acme, "correlation_id = $1", res.RequestID, "organization.domains_changed", "success", auditPollTimeout)
		}},
		{"validation failure", func(t *testing.T, w *auditWorld) {
			res := call(t, w.root, http.MethodPatch, "/api/platform/v1/organizations/"+w.acme.String(), map[string]any{"domains": []string{"Not A Domain"}})
			expectStatus(t, res, http.StatusBadRequest, "invalid_request")
			expectOneIndexEvent(t, w.idx, w.acme, "correlation_id = $1", res.RequestID, "organization.domains_changed", "failure", auditPollTimeout)
		}},
		{"wrong role", func(t *testing.T, w *auditWorld) {
			res := call(t, w.alice, http.MethodPatch, "/api/platform/v1/organizations/"+w.acme.String(), map[string]any{"domains": []string{"acme.test"}})
			expectStatus(t, res, http.StatusForbidden, "forbidden")
			expectOneEvent(t, w.alice, res.RequestID, "organization.domains_changed", "denied")
		}},
		{"not found", func(t *testing.T, w *auditWorld) {
			res := call(t, w.root, http.MethodPatch, "/api/platform/v1/organizations/"+uuid.NewString(), map[string]any{"domains": []string{}})
			expectStatus(t, res, http.StatusNotFound, "not_found")
			expectOneIndexEvent(t, w.idx, platformOrg, "correlation_id = $1", res.RequestID, "organization.domains_changed", "failure", auditPollTimeout)
		}},
		{"conflict", func(t *testing.T, w *auditWorld) {
			res := call(t, w.root, http.MethodPatch, "/api/platform/v1/organizations/"+w.acme.String(), map[string]any{"domains": []string{"acme.test", "globex.test"}})
			expectStatus(t, res, http.StatusConflict, "domain_taken")
			expectOneIndexEvent(t, w.idx, w.acme, "correlation_id = $1", res.RequestID, "organization.domains_changed", "failure", auditPollTimeout)
		}},
	},

	"POST /api/v1/users": {
		{"success", func(t *testing.T, w *auditWorld) {
			res := call(t, w.alice, http.MethodPost, "/api/v1/users", map[string]string{"username": "a3-" + uniqueSuffix() + "@acme.test", "display_name": "A3"})
			expectStatus(t, res, http.StatusCreated, "")
			var out struct {
				User struct {
					ID string `json:"id"`
				} `json:"user"`
			}
			if err := res.JSON(&out); err != nil {
				t.Fatal(err)
			}
			deleteOnCleanup(t, w.alice, "/api/v1/users/"+out.User.ID)
			expectOneEvent(t, w.alice, res.RequestID, "user.created", "success")
		}},
		{"validation failure", func(t *testing.T, w *auditWorld) {
			res := call(t, w.alice, http.MethodPost, "/api/v1/users", map[string]string{"username": "a3@elsewhere.test", "display_name": "A3"})
			expectStatus(t, res, http.StatusBadRequest, "invalid_request")
			expectOneEvent(t, w.alice, res.RequestID, "user.created", "failure")
		}},
		{"wrong role", func(t *testing.T, w *auditWorld) {
			res := call(t, w.bob, http.MethodPost, "/api/v1/users", map[string]string{"username": "a3-" + uniqueSuffix() + "@acme.test", "display_name": "A3"})
			expectStatus(t, res, http.StatusForbidden, "forbidden")
			expectOneEvent(t, w.alice, res.RequestID, "user.created", "denied")
		}},
		{"conflict", func(t *testing.T, w *auditWorld) {
			// The dev admin alice exists in Authentik (not as a Paddock user): the username is taken.
			res := call(t, w.alice, http.MethodPost, "/api/v1/users", map[string]string{"username": env.Alice, "display_name": "A3"})
			expectStatus(t, res, http.StatusConflict, "username_taken")
			expectOneEvent(t, w.alice, res.RequestID, "user.created", "failure")
		}},
	},
	"PATCH /api/v1/users/{id}": itemCases(http.MethodPatch, "/api/v1/users", "", "user.updated", http.StatusOK, localUser,
		func(*testing.T, *auditWorld) any { return map[string]string{"display_name": "A3 renamed"} }),
	"DELETE /api/v1/users/{id}":      itemCases(http.MethodDelete, "/api/v1/users", "", "user.deleted", http.StatusNoContent, localUser, nil),
	"POST /api/v1/users/{id}/lock":   itemCases(http.MethodPost, "/api/v1/users", "/lock", "user.locked", http.StatusOK, localUser, nil),
	"POST /api/v1/users/{id}/unlock": itemCases(http.MethodPost, "/api/v1/users", "/unlock", "user.unlocked", http.StatusOK, localUser, nil),

	"POST /api/v1/user-groups": {
		{"success", func(t *testing.T, w *auditWorld) {
			res := call(t, w.alice, http.MethodPost, "/api/v1/user-groups", map[string]string{"slug": "a3-" + uniqueSuffix(), "name": "A3"})
			expectStatus(t, res, http.StatusCreated, "")
			createdID(t, w.alice, "/api/v1/user-groups", res)
			expectOneEvent(t, w.alice, res.RequestID, "user_group.created", "success")
		}},
		{"validation failure", func(t *testing.T, w *auditWorld) {
			res := call(t, w.alice, http.MethodPost, "/api/v1/user-groups", map[string]string{"slug": "Not A Slug", "name": "A3"})
			expectStatus(t, res, http.StatusBadRequest, "invalid_request")
			expectOneEvent(t, w.alice, res.RequestID, "user_group.created", "failure")
		}},
		{"wrong role", func(t *testing.T, w *auditWorld) {
			res := call(t, w.bob, http.MethodPost, "/api/v1/user-groups", map[string]string{"slug": "a3-" + uniqueSuffix(), "name": "A3"})
			expectStatus(t, res, http.StatusForbidden, "forbidden")
			expectOneEvent(t, w.alice, res.RequestID, "user_group.created", "denied")
		}},
		{"conflict", func(t *testing.T, w *auditWorld) {
			slug := "a3-" + uniqueSuffix()
			createdID(t, w.alice, "/api/v1/user-groups", call(t, w.alice, http.MethodPost, "/api/v1/user-groups", map[string]string{"slug": slug, "name": "A3"}))
			res := call(t, w.alice, http.MethodPost, "/api/v1/user-groups", map[string]string{"slug": slug, "name": "A3 again"})
			expectStatus(t, res, http.StatusConflict, "slug_taken")
			expectOneEvent(t, w.alice, res.RequestID, "user_group.created", "failure")
		}},
	},
	"PATCH /api/v1/user-groups/{id}": itemCases(http.MethodPatch, "/api/v1/user-groups", "", "user_group.updated", http.StatusOK,
		func(t *testing.T, w *auditWorld) string { return userGroup(t, w.alice) },
		func(*testing.T, *auditWorld) any { return map[string]string{"name": "A3 renamed"} }),
	"DELETE /api/v1/user-groups/{id}": itemCases(http.MethodDelete, "/api/v1/user-groups", "", "user_group.deleted", http.StatusNoContent,
		func(t *testing.T, w *auditWorld) string { return userGroup(t, w.alice) }, nil),
	"POST /api/v1/user-groups/{id}/members": itemCases(http.MethodPost, "/api/v1/user-groups", "/members", "user_group.member_added", http.StatusNoContent,
		func(t *testing.T, w *auditWorld) string { return userGroup(t, w.alice) },
		func(t *testing.T, w *auditWorld) any { return map[string]string{"user_id": localUser(t, w)} }),
	"DELETE /api/v1/user-groups/{id}/members/{user_id}": {
		{"success", func(t *testing.T, w *auditWorld) {
			g, u := userGroup(t, w.alice), localUser(t, w)
			expectStatus(t, call(t, w.alice, http.MethodPost, "/api/v1/user-groups/"+g+"/members", map[string]string{"user_id": u}), http.StatusNoContent, "")
			res := call(t, w.alice, http.MethodDelete, "/api/v1/user-groups/"+g+"/members/"+u, nil)
			expectStatus(t, res, http.StatusNoContent, "")
			expectOneEvent(t, w.alice, res.RequestID, "user_group.member_removed", "success")
		}},
		{"validation failure", func(t *testing.T, w *auditWorld) {
			res := call(t, w.alice, http.MethodDelete, "/api/v1/user-groups/"+userGroup(t, w.alice)+"/members/not-a-uuid", nil)
			expectStatus(t, res, http.StatusBadRequest, "invalid_request")
			expectOneEvent(t, w.alice, res.RequestID, "user_group.member_removed", "failure")
		}},
		{"wrong role", func(t *testing.T, w *auditWorld) {
			res := call(t, w.bob, http.MethodDelete, "/api/v1/user-groups/"+userGroup(t, w.alice)+"/members/"+localUser(t, w), nil)
			expectStatus(t, res, http.StatusForbidden, "forbidden")
			expectOneEvent(t, w.alice, res.RequestID, "user_group.member_removed", "denied")
		}},
		{"not found", func(t *testing.T, w *auditWorld) {
			res := call(t, w.alice, http.MethodDelete, "/api/v1/user-groups/"+uuid.NewString()+"/members/"+uuid.NewString(), nil)
			expectStatus(t, res, http.StatusNotFound, "not_found")
			expectOneEvent(t, w.alice, res.RequestID, "user_group.member_removed", "failure")
		}},
	},

	"PUT /api/v1/settings/login": {
		{"success", func(t *testing.T, w *auditWorld) {
			res := call(t, w.alice, http.MethodPut, "/api/v1/settings/login", currentLoginSettings(t, w.alice))
			expectStatus(t, res, http.StatusOK, "")
			expectOneEvent(t, w.alice, res.RequestID, "settings.login_changed", "success")
		}},
		{"validation failure", func(t *testing.T, w *auditWorld) {
			s := currentLoginSettings(t, w.alice)
			s["sudoers_d_allowlist"] = []string{"x.conf"}
			res := call(t, w.alice, http.MethodPut, "/api/v1/settings/login", s)
			expectStatus(t, res, http.StatusBadRequest, "invalid_request")
			expectOneEvent(t, w.alice, res.RequestID, "settings.login_changed", "failure")
		}},
		{"wrong role", func(t *testing.T, w *auditWorld) {
			res := call(t, w.bob, http.MethodPut, "/api/v1/settings/login", currentLoginSettings(t, w.alice))
			expectStatus(t, res, http.StatusForbidden, "forbidden")
			expectOneEvent(t, w.alice, res.RequestID, "settings.login_changed", "denied")
		}},
	},

	"PUT /api/v1/devices/{id}/login-assignment": itemCases(http.MethodPut, "/api/v1/devices", "/login-assignment",
		"device.login_assignment_changed", http.StatusOK, activeID,
		func(*testing.T, *auditWorld) any { return map[string]any{"users": []string{}, "groups": []string{}} }),
	"POST /api/v1/devices/{id}/suspend-logins": itemCases(http.MethodPost, "/api/v1/devices", "/suspend-logins",
		"device.logins_suspended", http.StatusOK, activeID, nil),
	"POST /api/v1/devices/{id}/resume-logins": itemCases(http.MethodPost, "/api/v1/devices", "/resume-logins",
		"device.logins_resumed", http.StatusOK, activeID, nil),

	"POST /api/v1/permission-profiles": {
		{"success", func(t *testing.T, w *auditWorld) {
			res := call(t, w.alice, http.MethodPost, "/api/v1/permission-profiles", map[string]any{"name": uniqueName("a3 profile"), "class": "none"})
			expectStatus(t, res, http.StatusCreated, "")
			createdID(t, w.alice, "/api/v1/permission-profiles", res)
			expectOneEvent(t, w.alice, res.RequestID, "permission_profile.created", "success")
		}},
		{"validation failure", func(t *testing.T, w *auditWorld) {
			res := call(t, w.alice, http.MethodPost, "/api/v1/permission-profiles", map[string]any{
				"name": uniqueName("a3 profile"), "class": "restricted", "commands": []string{"/usr/bin/a, /usr/bin/b"},
			})
			expectStatus(t, res, http.StatusUnprocessableEntity, "invalid_command")
			expectOneEvent(t, w.alice, res.RequestID, "permission_profile.created", "failure")
		}},
		{"wrong role", func(t *testing.T, w *auditWorld) {
			res := call(t, w.bob, http.MethodPost, "/api/v1/permission-profiles", map[string]any{"name": uniqueName("a3 profile"), "class": "none"})
			expectStatus(t, res, http.StatusForbidden, "forbidden")
			expectOneEvent(t, w.alice, res.RequestID, "permission_profile.created", "denied")
		}},
		{"conflict", func(t *testing.T, w *auditWorld) {
			name := uniqueName("a3 profile")
			createdID(t, w.alice, "/api/v1/permission-profiles", call(t, w.alice, http.MethodPost, "/api/v1/permission-profiles", map[string]any{"name": name, "class": "none"}))
			res := call(t, w.alice, http.MethodPost, "/api/v1/permission-profiles", map[string]any{"name": name, "class": "none"})
			expectStatus(t, res, http.StatusConflict, "name_taken")
			expectOneEvent(t, w.alice, res.RequestID, "permission_profile.created", "failure")
		}},
	},
	"PATCH /api/v1/permission-profiles/{id}": itemCases(http.MethodPatch, "/api/v1/permission-profiles", "", "permission_profile.updated", http.StatusOK,
		func(t *testing.T, w *auditWorld) string { return profile(t, w.alice, "none") },
		func(*testing.T, *auditWorld) any { return map[string]any{"lecture": "always"} }),
	"DELETE /api/v1/permission-profiles/{id}": append(itemCases(http.MethodDelete, "/api/v1/permission-profiles", "", "permission_profile.deleted",
		http.StatusNoContent, func(t *testing.T, w *auditWorld) string { return profile(t, w.alice, "none") }, nil),
		auditCase{"conflict", func(t *testing.T, w *auditWorld) {
			prof := profile(t, w.alice, "none")
			res := call(t, w.alice, http.MethodPost, "/api/v1/profile-assignments", map[string]any{"profile_id": prof, "subject_type": "global"})
			expectStatus(t, res, http.StatusCreated, "")
			createdID(t, w.alice, "/api/v1/profile-assignments", res)
			res = call(t, w.alice, http.MethodDelete, "/api/v1/permission-profiles/"+prof, nil)
			expectStatus(t, res, http.StatusConflict, "in_use")
			expectOneEvent(t, w.alice, res.RequestID, "permission_profile.deleted", "failure")
		}}),

	"POST /api/v1/profile-assignments": {
		{"success", func(t *testing.T, w *auditWorld) {
			res := call(t, w.alice, http.MethodPost, "/api/v1/profile-assignments", map[string]any{
				"profile_id": profile(t, w.alice, "none"), "subject_type": "user", "subject_id": localUser(t, w),
			})
			expectStatus(t, res, http.StatusCreated, "")
			createdID(t, w.alice, "/api/v1/profile-assignments", res)
			expectOneEvent(t, w.alice, res.RequestID, "profile_assignment.created", "success")
		}},
		{"validation failure", func(t *testing.T, w *auditWorld) {
			res := call(t, w.alice, http.MethodPost, "/api/v1/profile-assignments", map[string]any{
				"profile_id": profile(t, w.alice, "none"), "subject_type": "user",
			})
			expectStatus(t, res, http.StatusBadRequest, "invalid_request")
			expectOneEvent(t, w.alice, res.RequestID, "profile_assignment.created", "failure")
		}},
		{"wrong role", func(t *testing.T, w *auditWorld) {
			res := call(t, w.bob, http.MethodPost, "/api/v1/profile-assignments", map[string]any{
				"profile_id": profile(t, w.alice, "none"), "subject_type": "global",
			})
			expectStatus(t, res, http.StatusForbidden, "forbidden")
			expectOneEvent(t, w.alice, res.RequestID, "profile_assignment.created", "denied")
		}},
		{"conflict", func(t *testing.T, w *auditWorld) {
			body := map[string]any{"profile_id": profile(t, w.alice, "none"), "subject_type": "global"}
			createdID(t, w.alice, "/api/v1/profile-assignments", call(t, w.alice, http.MethodPost, "/api/v1/profile-assignments", body))
			res := call(t, w.alice, http.MethodPost, "/api/v1/profile-assignments", body)
			expectStatus(t, res, http.StatusConflict, "already_exists")
			expectOneEvent(t, w.alice, res.RequestID, "profile_assignment.created", "failure")
		}},
	},
	"PATCH /api/v1/profile-assignments/{id}": itemCases(http.MethodPatch, "/api/v1/profile-assignments", "", "profile_assignment.updated", http.StatusOK,
		func(t *testing.T, w *auditWorld) string { return assignment(t, w.alice) },
		func(t *testing.T, w *auditWorld) any {
			return map[string]any{"device_group_id": createGroup(t, w.alice).id}
		}),
	"DELETE /api/v1/profile-assignments/{id}": itemCases(http.MethodDelete, "/api/v1/profile-assignments", "", "profile_assignment.deleted",
		http.StatusNoContent, func(t *testing.T, w *auditWorld) string { return assignment(t, w.alice) }, nil),
	"PUT /api/v1/settings/managed-files": {
		// The success case writes the current roots back, so the roots every gate relies on stay.
		{"success", func(t *testing.T, w *auditWorld) {
			a := adminUser(t, "a3-roots")
			res := call(t, a.Portal, http.MethodGet, "/api/v1/settings/managed-files", nil)
			var cur map[string]any
			if err := res.JSON(&cur); err != nil {
				t.Fatal(err)
			}
			a.stepUp(t)
			res = call(t, a.Portal, http.MethodPut, "/api/v1/settings/managed-files", map[string]any{"operator_roots": cur["operator_roots"]})
			expectStatus(t, res, http.StatusOK, "")
			expectOneEvent(t, w.alice, res.RequestID, "settings.managed_files_changed", "success")
		}},
		{"validation failure", func(t *testing.T, w *auditWorld) {
			a := adminUser(t, "a3-roots")
			res := call(t, a.Portal, http.MethodPut, "/api/v1/settings/managed-files", map[string]any{"operator_roots": []string{"/etc/apt/"}})
			expectStatus(t, res, http.StatusUnprocessableEntity, "path_not_allowed")
			expectOneEvent(t, w.alice, res.RequestID, "settings.managed_files_changed", "failure")
		}},
		{"no step-up", func(t *testing.T, w *auditWorld) {
			res := call(t, login(t, env.Alice), http.MethodPut, "/api/v1/settings/managed-files", map[string]any{"operator_roots": gateOperatorRoots})
			expectStatus(t, res, http.StatusForbidden, "step_up_required")
			expectOneEvent(t, w.alice, res.RequestID, "settings.managed_files_changed", "denied")
		}},
		{"wrong role", func(t *testing.T, w *auditWorld) {
			res := call(t, w.bob, http.MethodPut, "/api/v1/settings/managed-files", map[string]any{"operator_roots": gateOperatorRoots})
			expectStatus(t, res, http.StatusForbidden, "forbidden")
			expectOneEvent(t, w.alice, res.RequestID, "settings.managed_files_changed", "denied")
		}},
	},
	"POST /api/v1/permission-profiles/{id}/confirm-root-grant": confirmCases("/api/v1/permission-profiles", "/confirm-root-grant",
		"permission_profile.root_grant_confirmed", map[string]any{"name": "a3 root", "class": "full"},
		map[string]any{"name": "a3 none", "class": "none"}),
	"POST /api/v1/managed-files/{id}/confirm-sensitive": confirmCases("/api/v1/managed-files", "/confirm-sensitive",
		"managed_file.sensitive_confirmed", map[string]any{"path": "/etc/cron.d/a3-", "content": "a3"},
		map[string]any{"path": "/etc/paddock-gates/a3-", "content": "a3"}),
}

// confirmCases are the cases of a confirmation of the security review (ADR 0034 decision 7): a stepped-up temporary
// administrator creates the item (granting or ordinary) and confirms it. A "name" or "path" in the bodies gets a
// unique suffix.
func confirmCases(collection, suffix, code string, granting, ordinary map[string]any) []auditCase {
	create := func(t *testing.T, p *env.Portal, body map[string]any) string {
		t.Helper()
		b := map[string]any{}
		for k, v := range body {
			b[k] = v
		}
		if name, ok := b["name"].(string); ok {
			b["name"] = uniqueName(name)
		}
		if path, ok := b["path"].(string); ok {
			b["path"] = path + uniqueSuffix() + ".conf"
		}
		res := call(t, p, http.MethodPost, collection, b)
		expectStatus(t, res, http.StatusCreated, "")
		return createdID(t, p, collection, res)
	}
	admin := func(t *testing.T) *mfaUser {
		return steppedUpTempUser(t, "a3-confirm", env.RoleGroup("acme", "admins"))
	}
	return []auditCase{
		{"success", func(t *testing.T, w *auditWorld) {
			a := admin(t)
			id := create(t, a.Portal, granting)
			a.stepUp(t)
			res := call(t, a.Portal, http.MethodPost, collection+"/"+id+suffix, nil)
			expectStatus(t, res, http.StatusOK, "")
			expectOneEvent(t, w.alice, res.RequestID, code, "success")
		}},
		{"no step-up", func(t *testing.T, w *auditWorld) {
			res := call(t, login(t, env.Alice), http.MethodPost, collection+"/"+uuid.NewString()+suffix, nil)
			expectStatus(t, res, http.StatusForbidden, "step_up_required")
			expectOneEvent(t, w.alice, res.RequestID, code, "denied")
		}},
		{"wrong role", func(t *testing.T, w *auditWorld) {
			res := call(t, w.bob, http.MethodPost, collection+"/"+uuid.NewString()+suffix, nil)
			expectStatus(t, res, http.StatusForbidden, "forbidden")
			expectOneEvent(t, w.alice, res.RequestID, code, "denied")
		}},
		{"not found", func(t *testing.T, w *auditWorld) {
			a := admin(t)
			res := call(t, a.Portal, http.MethodPost, collection+"/"+uuid.NewString()+suffix, nil)
			expectStatus(t, res, http.StatusNotFound, "not_found")
			expectOneEvent(t, w.alice, res.RequestID, code, "failure")
		}},
		{"conflict", func(t *testing.T, w *auditWorld) {
			a := admin(t)
			id := create(t, a.Portal, ordinary)
			a.stepUp(t)
			res := call(t, a.Portal, http.MethodPost, collection+"/"+id+suffix, nil)
			expectStatus(t, res, http.StatusConflict, "invalid_state")
			expectOneEvent(t, w.alice, res.RequestID, code, "failure")
		}},
	}
}
