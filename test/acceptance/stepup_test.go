package acceptance

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/test/acceptance/internal/env"
)

// stepUpState is the development-only step_up of GET /api/v1/me: the session's last step-up as the server recorded
// it and the server's step-up timing.
type stepUpState struct {
	At         *time.Time
	Window     time.Duration
	MaxAuthAge time.Duration
}

func serverStepUp(t *testing.T, p *env.Portal) stepUpState {
	t.Helper()
	var me struct {
		StepUp *struct {
			At                *time.Time `json:"at"`
			WindowSeconds     int        `json:"window_seconds"`
			MaxAuthAgeSeconds int        `json:"max_auth_age_seconds"`
		} `json:"step_up"`
	}
	res := call(t, p, http.MethodGet, "/api/v1/me", nil)
	expectStatus(t, res, http.StatusOK, "")
	if err := res.JSON(&me); err != nil || me.StepUp == nil {
		t.Fatalf("GET /api/v1/me has no step_up (needs PADDOCK_ENV=development): %v %s", err, res.Body)
	}
	return stepUpState{At: me.StepUp.At, Window: time.Duration(me.StepUp.WindowSeconds) * time.Second,
		MaxAuthAge: time.Duration(me.StepUp.MaxAuthAgeSeconds) * time.Second}
}

// freshStepUp steps up as user unless the session's step-up has at least 10 s of its window left, so a gate that
// runs longer than the (development) window keeps a valid step-up.
func freshStepUp(t *testing.T, p *env.Portal, user string) {
	t.Helper()
	if s := serverStepUp(t, p); s.At != nil && time.Until(s.At.Add(s.Window)) > 10*time.Second {
		return
	}
	stepUp(t, p, user, true)
}

// expirySlack is added to every wait for a server-side expiry: the server stores whole seconds and compares with
// its own clock.
const expirySlack = 2 * time.Second

// TestStepUp is gate U1 of plan M4a: revealing the local administrator password, assigning a full profile and
// changing a profile to class full need a step-up of the session's own user within the step-up window (300 s; the
// development stack shortens it, GET /api/v1/me reports it); every refusal is one denied audit event with error code
// step_up_required, the permitted action's event marks the actor as stepped up. The waits for Authentik's max_age
// and for the window are measured from the server's step-up time; the audit event checks run during them.
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
		if res.Status == http.StatusCreated {
			// Also an assignment that should have been refused: it must not keep the profile from being deleted.
			createdID(t, alice, "/api/v1/profile-assignments", res)
		}
		expectStatus(t, res, status, code)
		return res
	}
	// The audit event checks (each waits for delivery and 5 s more) are collected and run during the next wait.
	var checks []func()
	later := func(check func()) { checks = append(checks, check) }
	waitUntil := func(deadline time.Time) {
		for _, check := range checks {
			check()
		}
		checks = nil
		time.Sleep(time.Until(deadline))
	}
	denied := func(res env.Response, code string) {
		later(func() {
			if ev := expectOneEvent(t, alice, res.RequestID, code, "denied"); ev.ErrorCode != "step_up_required" || ev.Actor.StepUp {
				t.Fatalf("event %+v", ev)
			}
		})
	}

	denied(assign(http.StatusForbidden, "step_up_required"), "profile_assignment.created")
	denied(reveal(http.StatusForbidden, "step_up_required"), "local_admin.revealed")
	toFull := call(t, alice, http.MethodPatch, "/api/v1/permission-profiles/"+restricted, map[string]any{"class": "full"})
	expectStatus(t, toFull, http.StatusForbidden, "step_up_required")
	denied(toFull, "permission_profile.updated")

	// Another user's credentials in alice's session: refused, alice still has no step-up. Authentik then keeps the
	// other user's login, which it re-authenticates only once it is older than max_age; the login happened before
	// the step-up returned.
	stepUp(t, alice, env.Carol, false)
	carolDone := time.Now()
	timing := serverStepUp(t, alice)
	if timing.At != nil {
		t.Fatalf("carol's step-up gave alice's session a step-up at %s", timing.At)
	}
	denied(assign(http.StatusForbidden, "step_up_required"), "profile_assignment.created")
	waitUntil(carolDone.Add(timing.MaxAuthAge + expirySlack))

	stepUp(t, alice, env.Alice, true)
	steppedUp := serverStepUp(t, alice).At
	if steppedUp == nil {
		t.Fatal("no step-up recorded after alice's step-up")
	}
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
	later(func() {
		if ev := expectOneEvent(t, alice, revealed.RequestID, "local_admin.revealed", "success"); !ev.Actor.StepUp ||
			strings.Contains(fmt.Sprint(ev.Params), password) {
			t.Fatalf("reveal event %+v", ev)
		}
	})
	res := assign(http.StatusCreated, "")
	later(func() {
		if ev := expectOneEvent(t, alice, res.RequestID, "profile_assignment.created", "success"); !ev.Actor.StepUp {
			t.Fatalf("event %+v does not mark the step-up", ev)
		}
	})
	toFull = call(t, alice, http.MethodPatch, "/api/v1/permission-profiles/"+restricted, map[string]any{"class": "full"})
	expectStatus(t, toFull, http.StatusOK, "")

	// After the window the step-up no longer counts; a second step-up of the same Authentik session authenticates
	// again.
	waitUntil(steppedUp.Add(timing.Window + expirySlack))
	expectStatus(t, call(t, alice, http.MethodDelete, "/api/v1/profile-assignments/"+responseID(t, res).String(), nil), http.StatusNoContent, "")
	denied(assign(http.StatusForbidden, "step_up_required"), "profile_assignment.created")
	denied(reveal(http.StatusForbidden, "step_up_required"), "local_admin.revealed")
	stepUp(t, alice, env.Alice, true)
	assign(http.StatusCreated, "")
	waitUntil(time.Now())
}

func expectCreated(t *testing.T, res env.Response) env.Response {
	t.Helper()
	expectStatus(t, res, http.StatusCreated, "")
	return res
}
