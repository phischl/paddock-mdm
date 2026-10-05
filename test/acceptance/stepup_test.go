package acceptance

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/paddock-mdm/paddock/test/acceptance/internal/env"
)

// stepUp runs a step-up of p as user and fails the test unless the outcome matches ok.
func stepUp(t *testing.T, p *env.Portal, user string, ok bool) time.Time {
	t.Helper()
	at := time.Now()
	final, err := p.StepUp(testContext(t, 3*time.Minute), user, "/settings")
	if err != nil {
		t.Fatalf("step-up as %s: %v", user, err)
	}
	if failed := strings.Contains(final, "stepup=failed"); failed == ok {
		t.Fatalf("step-up as %s returned to %s", user, final)
	}
	return at
}

// TestStepUp is gate U1 of plan M4a: revealing the local administrator password, assigning a full profile and
// changing a profile to class full need a step-up of the session's own user within the last 300 s; every refusal
// is one denied audit event with error code step_up_required, the permitted action's event marks the actor as
// stepped up.
func TestStepUp(t *testing.T) {
	alice := login(t, env.Alice)
	device, password := escrowedDevice(t, alice)
	revealPath := "/api/v1/devices/" + device.DeviceID + "/local-admin/reveal"
	reveal := func(status int, code string) env.Response {
		t.Helper()
		res := call(t, alice, http.MethodPost, revealPath, map[string]any{"confirm_hostname": getDevice(t, alice, device.DeviceID).Hostname})
		expectStatus(t, res, status, code)
		return res
	}
	group := namedGroup(t, alice, "u1 empty")
	full := createdID(t, alice, "/api/v1/permission-profiles",
		expectCreated(t, call(t, alice, http.MethodPost, "/api/v1/permission-profiles", map[string]any{"name": uniqueName("u1 full"), "class": "full"})))
	restricted := createdID(t, alice, "/api/v1/permission-profiles", expectCreated(t, call(t, alice, http.MethodPost,
		"/api/v1/permission-profiles", map[string]any{"name": uniqueName("u1 restricted"), "class": "restricted", "commands": []string{"/usr/bin/true"}})))
	// Global within an empty device group: the assignment reaches no device.
	assignment := map[string]any{"profile_id": full, "subject_type": "global", "device_group_id": group}
	assign := func(status int, code string) env.Response {
		t.Helper()
		res := call(t, alice, http.MethodPost, "/api/v1/profile-assignments", assignment)
		expectStatus(t, res, status, code)
		if status == http.StatusCreated {
			createdID(t, alice, "/api/v1/profile-assignments", res)
		}
		return res
	}
	denied := func(res env.Response, code string) {
		t.Helper()
		if ev := expectOneEvent(t, alice, res.RequestID, code, "denied"); ev.ErrorCode != "step_up_required" || ev.Actor.StepUp {
			t.Fatalf("event %+v", ev)
		}
	}

	denied(assign(http.StatusForbidden, "step_up_required"), "profile_assignment.created")
	denied(reveal(http.StatusForbidden, "step_up_required"), "local_admin.revealed")
	toFull := call(t, alice, http.MethodPatch, "/api/v1/permission-profiles/"+restricted, map[string]any{"class": "full"})
	expectStatus(t, toFull, http.StatusForbidden, "step_up_required")
	denied(toFull, "permission_profile.updated")

	// Another user's credentials in alice's session: refused, alice still has no step-up. Authentik then keeps the
	// other user's login, which it re-authenticates only once it is older than max_age (60 s).
	stepUp(t, alice, env.Carol, false)
	carolDone := time.Now()
	denied(assign(http.StatusForbidden, "step_up_required"), "profile_assignment.created")
	time.Sleep(time.Until(carolDone.Add(61 * time.Second)))

	at := stepUp(t, alice, env.Alice, true)
	revealed := reveal(http.StatusOK, "")
	var out struct {
		Passwords []struct {
			Generation int    `json:"generation"`
			State      string `json:"state"`
			Password   string `json:"password"`
		} `json:"passwords"`
	}
	if err := revealed.JSON(&out); err != nil || len(out.Passwords) != 1 || out.Passwords[0].Password != password ||
		out.Passwords[0].State != "active" || revealed.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("reveal %s %v (%v)", revealed.Body, revealed.Header, err)
	}
	if ev := expectOneEvent(t, alice, revealed.RequestID, "local_admin.revealed", "success"); !ev.Actor.StepUp ||
		strings.Contains(fmt.Sprint(ev.Params), password) {
		t.Fatalf("reveal event %+v", ev)
	}
	res := assign(http.StatusCreated, "")
	if ev := expectOneEvent(t, alice, res.RequestID, "profile_assignment.created", "success"); !ev.Actor.StepUp {
		t.Fatalf("event %+v does not mark the step-up", ev)
	}
	toFull = call(t, alice, http.MethodPatch, "/api/v1/permission-profiles/"+restricted, map[string]any{"class": "full"})
	expectStatus(t, toFull, http.StatusOK, "")

	// 300 s later the step-up no longer counts; a second step-up of the same Authentik session authenticates again.
	time.Sleep(time.Until(at.Add(301 * time.Second)))
	res = call(t, alice, http.MethodDelete, "/api/v1/profile-assignments/"+responseID(t, res).String(), nil)
	expectStatus(t, res, http.StatusNoContent, "")
	denied(assign(http.StatusForbidden, "step_up_required"), "profile_assignment.created")
	denied(reveal(http.StatusForbidden, "step_up_required"), "local_admin.revealed")
	stepUp(t, alice, env.Alice, true)
	assign(http.StatusCreated, "")
}

func expectCreated(t *testing.T, res env.Response) env.Response {
	t.Helper()
	expectStatus(t, res, http.StatusCreated, "")
	return res
}
