package acceptance

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/test/acceptance/internal/env"
)

// TestCombinedRootGrant is the acceptance case of plan M8s decision 7k: two profiles that are each restricted but
// combine into root (a writer and the executable it writes) are assigned to one user; the second assignment is
// refused for an operator (403 forbidden) and an API token (step_up_required with the token detail), needs a step-up
// from an administrator and is then recorded with effective_class full. Adding a user to a Paddock group that carries
// the second half follows the same rule, and so does an enrollment token into the device group of the combination. All
// grants are scoped to an empty device group and reach no device.
func TestCombinedRootGrant(t *testing.T) {
	admin := adminUser(t, "s9")
	noStepUp := withoutStepUp(t, admin)
	operator := operatorUser(t)
	alice := login(t, env.Alice)
	token := tokenPortal(t, createAPIToken(t, alice, env.Alice, "org_operator").Secret)
	dir := "/opt/s9-" + uniqueSuffix()
	group := namedGroup(t, admin.Portal, "s9 empty")
	profile := func(name string, commands ...string) string {
		res := call(t, operator.Portal, http.MethodPost, "/api/v1/permission-profiles", map[string]any{
			"name": uniqueName(name), "class": "restricted", "commands": commands,
		})
		expectStatus(t, res, http.StatusCreated, "")
		return createdID(t, admin.Portal, "/api/v1/permission-profiles", res)
	}
	writer := profile("s9 writer", "/usr/bin/tee "+dir+"/run.sh")
	runner := profile("s9 runner", dir+"/run.sh")

	t.Run("assignment", func(t *testing.T) {
		user := createLocalUser(t, admin.Portal, "s9")
		assign := func(p *env.Portal, profileID string) env.Response {
			return call(t, p, http.MethodPost, "/api/v1/profile-assignments", map[string]any{
				"profile_id": profileID, "subject_type": "user", "subject_id": user.ID, "device_group_id": group,
			})
		}
		res := assign(operator.Portal, writer)
		expectStatus(t, res, http.StatusCreated, "")
		createdID(t, admin.Portal, "/api/v1/profile-assignments", res)

		expectRefusal(t, admin.Portal, assign(operator.Portal, runner), http.StatusForbidden, "forbidden", "profile_assignment.created")
		res = assign(token, runner)
		expectRefusal(t, admin.Portal, res, http.StatusForbidden, "step_up_required", "profile_assignment.created")
		if d := problemDetail(t, res); !strings.Contains(d, "API tokens") {
			t.Fatalf("token detail %q", d)
		}
		expectRefusal(t, admin.Portal, assign(noStepUp, runner), http.StatusForbidden, "step_up_required", "profile_assignment.created")

		admin.stepUp(t)
		res = assign(admin.Portal, runner)
		expectStatus(t, res, http.StatusCreated, "")
		createdID(t, admin.Portal, "/api/v1/profile-assignments", res)
		if ev := expectOneEvent(t, admin.Portal, res.RequestID, "profile_assignment.created", "success"); ev.Params["effective_class"] != "full" || !ev.Actor.StepUp {
			t.Fatalf("event %+v", ev)
		}
	})

	// A device enrolled with a token into the device group of the combination would receive it (plan M8s decision
	// 7g-ter); runs after "assignment" completed the pair in that group.
	t.Run("enrollment token", func(t *testing.T) {
		body := map[string]any{"name": uniqueName("s9 token"), "max_uses": 1, "auto_approve": true, "device_group_id": group,
			"expires_at": time.Now().Add(time.Hour).UTC().Format(time.RFC3339)}
		expectRefusal(t, admin.Portal, call(t, noStepUp, http.MethodPost, "/api/v1/enrollment-tokens", body),
			http.StatusForbidden, "step_up_required", "enrollment_token.created")
		admin.stepUp(t)
		res := call(t, admin.Portal, http.MethodPost, "/api/v1/enrollment-tokens", body)
		expectStatus(t, res, http.StatusCreated, "")
		createdTokenOf(t, admin.Portal, res)
		if ev := expectOneEvent(t, admin.Portal, res.RequestID, "enrollment_token.created", "success"); !ev.Actor.StepUp {
			t.Fatalf("event %+v", ev)
		}
	})

	t.Run("group membership", func(t *testing.T) {
		user := createLocalUser(t, admin.Portal, "s9-member")
		res := call(t, operator.Portal, http.MethodPost, "/api/v1/profile-assignments", map[string]any{
			"profile_id": writer, "subject_type": "user", "subject_id": user.ID, "device_group_id": group,
		})
		expectStatus(t, res, http.StatusCreated, "")
		createdID(t, admin.Portal, "/api/v1/profile-assignments", res)
		grp := userGroup(t, admin.Portal)
		admin.stepUp(t)
		res = call(t, admin.Portal, http.MethodPost, "/api/v1/profile-assignments", map[string]any{
			"profile_id": runner, "subject_type": "group", "subject_id": grp, "device_group_id": group,
		})
		expectStatus(t, res, http.StatusCreated, "")
		createdID(t, admin.Portal, "/api/v1/profile-assignments", res)

		members := "/api/v1/user-groups/" + grp + "/members"
		expectRefusal(t, admin.Portal, call(t, operator.Portal, http.MethodPost, members, map[string]string{"user_id": user.ID}),
			http.StatusForbidden, "forbidden", "user_group.member_added")
		expectRefusal(t, admin.Portal, call(t, noStepUp, http.MethodPost, members, map[string]string{"user_id": user.ID}),
			http.StatusForbidden, "step_up_required", "user_group.member_added")
		// effective_class_after counts active devices only; the grant is scoped to an empty device group.
		admin.stepUp(t)
		res = call(t, admin.Portal, http.MethodPost, members, map[string]string{"user_id": user.ID})
		expectStatus(t, res, http.StatusNoContent, "")
		if ev := expectOneEvent(t, admin.Portal, res.RequestID, "user_group.member_added", "success"); !ev.Actor.StepUp {
			t.Fatalf("event %+v", ev)
		}
	})
}
