package acceptance

import (
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/test/acceptance/internal/authflow"
	"github.com/phischl/paddock-mdm/test/acceptance/internal/env"
	"github.com/phischl/paddock-mdm/test/acceptance/internal/stack"
)

// stepUpState is the development-only step_up of GET /api/v1/me: the session's last step-up as the server recorded
// it and the server's step-up timing.
type stepUpState struct {
	At         *time.Time
	Window     time.Duration
	MaxAuthAge time.Duration
	// MFAClasses are the authenticator classes the session's last step-up validated (plan M8f decision 10).
	MFAClasses []string
}

func serverStepUp(t *testing.T, p *env.Portal) stepUpState {
	t.Helper()
	var me struct {
		StepUp *struct {
			At                *time.Time `json:"at"`
			WindowSeconds     int        `json:"window_seconds"`
			MaxAuthAgeSeconds int        `json:"max_auth_age_seconds"`
			MFAClasses        []string   `json:"mfa_classes"`
		} `json:"step_up"`
	}
	res := call(t, p, http.MethodGet, "/api/v1/me", nil)
	expectStatus(t, res, http.StatusOK, "")
	if err := res.JSON(&me); err != nil || me.StepUp == nil {
		t.Fatalf("GET /api/v1/me has no step_up (needs PADDOCK_ENV=development): %v %s", err, res.Body)
	}
	return stepUpState{At: me.StepUp.At, Window: time.Duration(me.StepUp.WindowSeconds) * time.Second,
		MaxAuthAge: time.Duration(me.StepUp.MaxAuthAgeSeconds) * time.Second, MFAClasses: me.StepUp.MFAClasses}
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
	// Creating a full profile needs a step-up too (ADR 0034); another administrator creates it so that alice's
	// session starts without one.
	creator := steppedUpTempUser(t, "u1", env.RoleGroup("acme", "admins"))
	full := createdID(t, alice, "/api/v1/permission-profiles",
		expectCreated(t, call(t, creator.Portal, http.MethodPost, "/api/v1/permission-profiles", map[string]any{"name": uniqueName("u1 full"), "class": "full"})))
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

// TestStepUpFactor is gate S16 of plan M8s (decision 40): the shipped step-up flow validates with WebAuthn only at
// order 30, the development blueprint adds the stage at order 31 that also accepts TOTP, and both blueprints applied.
// The portal sign-in validates any existing authenticator at order 30 and enrols WebAuthn at order 31 for an account
// without a WebAuthn device (plan M8f decision 13 as amended on 2026-10-18); development skips both.
func TestStepUpFactor(t *testing.T) {
	ctx := testContext(t, time.Minute)
	ak, err := env.NewAuthentik()
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"paddock/paddock-stepup.yaml", "paddock-dev/paddock-dev.yaml"} {
		b, ok, err := ak.Blueprint(ctx, path)
		if err != nil || !ok || b.Status != "successful" {
			t.Errorf("blueprint %s: %+v found %v, %v", path, b, ok, err)
		}
	}
	var flows struct {
		Results []struct {
			PK string `json:"pk"`
		} `json:"results"`
	}
	if err := ak.Get(ctx, "/flows/instances/?slug=paddock-stepup", &flows); err != nil || len(flows.Results) != 1 {
		t.Fatalf("flow paddock-stepup: %+v %v", flows, err)
	}
	var bindings struct {
		Results []struct {
			Order int    `json:"order"`
			Stage string `json:"stage"`
		} `json:"results"`
	}
	if err := ak.Get(ctx, "/flows/bindings/?target="+flows.Results[0].PK, &bindings); err != nil {
		t.Fatal(err)
	}
	stages := map[int]string{}
	for _, b := range bindings.Results {
		stages[b.Order] = b.Stage
	}
	classes := func(order int) []string {
		t.Helper()
		stage, ok := stages[order]
		if !ok {
			t.Fatalf("no stage binding at order %d: %+v", order, bindings.Results)
		}
		var v struct {
			DeviceClasses []string `json:"device_classes"`
		}
		if err := ak.Get(ctx, "/stages/authenticator/validate/"+stage+"/", &v); err != nil {
			t.Fatal(err)
		}
		return v.DeviceClasses
	}
	if got := classes(30); fmt.Sprint(got) != "[webauthn]" {
		t.Errorf("order 30 validates %v, want [webauthn]", got)
	}
	if got := classes(31); fmt.Sprint(got) != "[webauthn totp]" {
		t.Errorf("order 31 (development) validates %v, want [webauthn totp]", got)
	}
	type validateStage struct {
		DeviceClasses       []string `json:"device_classes"`
		NotConfiguredAction string   `json:"not_configured_action"`
		ConfigurationStages []string `json:"configuration_stages"`
	}
	for _, c := range []struct{ name, classes string }{
		{"paddock-admin-login-mfa", "[webauthn totp]"},
		{"paddock-admin-login-webauthn", "[webauthn]"},
	} {
		var login struct {
			Results []validateStage `json:"results"`
		}
		if err := ak.Get(ctx, "/stages/authenticator/validate/?name="+c.name, &login); err != nil || len(login.Results) != 1 {
			t.Fatalf("stage %s: %+v %v", c.name, login, err)
		}
		if s := login.Results[0]; fmt.Sprint(s.DeviceClasses) != c.classes || s.NotConfiguredAction != "configure" ||
			len(s.ConfigurationStages) != 1 {
			t.Errorf("%s: %+v, want %s, configure and one configuration stage", c.name, s, c.classes)
		}
	}
	if err := ak.Get(ctx, "/flows/instances/?slug=paddock-admin-login", &flows); err != nil || len(flows.Results) != 1 {
		t.Fatalf("flow paddock-admin-login: %+v %v", flows, err)
	}
	var loginBindings struct {
		Results []struct {
			Order      int    `json:"order"`
			PolicyPK   string `json:"policybindingmodel_ptr_id"`
			EngineMode string `json:"policy_engine_mode"`
			StageObj   struct {
				Name string `json:"name"`
			} `json:"stage_obj"`
		} `json:"results"`
	}
	if err := ak.Get(ctx, "/flows/bindings/?target="+flows.Results[0].PK, &loginBindings); err != nil {
		t.Fatal(err)
	}
	var policies []string
	for _, b := range loginBindings.Results {
		if b.Order != 31 {
			continue
		}
		if b.StageObj.Name != "paddock-admin-login-webauthn" || b.EngineMode != "all" {
			t.Errorf("paddock-admin-login order 31: %+v, want paddock-admin-login-webauthn in mode all", b)
		}
		var pb struct {
			Results []struct {
				PolicyObj struct {
					Name string `json:"name"`
				} `json:"policy_obj"`
			} `json:"results"`
		}
		if err := ak.Get(ctx, "/policies/bindings/?target="+b.PolicyPK, &pb); err != nil {
			t.Fatal(err)
		}
		for _, p := range pb.Results {
			policies = append(policies, p.PolicyObj.Name)
		}
	}
	slices.Sort(policies)
	if fmt.Sprint(policies) != "[paddock-admin-login-webauthn-administrator paddock-admin-login-webauthn-missing paddock-dev-skip-mfa]" {
		t.Errorf("paddock-admin-login order 31 policies %v, want the administrator and WebAuthn-missing policies and the development skip", policies)
	}
}

// TestPortalLoginPasskeyEnrolmentScope (ADR 0034 amendment 2026-10-29, PDK-498): paddock-admin-login is also the
// default brand's authentication flow, which the device-code page runs for every device user, so its passkey
// enrolment (stage B at order 31) applies only to members of Paddock administrator groups. The development blueprint
// skips stage B for everybody, so the gate evaluates the shipped policies of the binding (all except the development
// skip; the binding's mode is "all") through Authentik's policy test endpoint for users without a WebAuthn device.
func TestPortalLoginPasskeyEnrolmentScope(t *testing.T) {
	ctx := testContext(t, 2*time.Minute)
	ak, err := env.NewAuthentik()
	if err != nil {
		t.Fatal(err)
	}
	var flows struct {
		Results []struct {
			PK string `json:"pk"`
		} `json:"results"`
	}
	if err := ak.Get(ctx, "/flows/instances/?slug=paddock-admin-login", &flows); err != nil || len(flows.Results) != 1 {
		t.Fatalf("flow paddock-admin-login: %+v %v", flows, err)
	}
	var bindings struct {
		Results []struct {
			Order      int    `json:"order"`
			PolicyPK   string `json:"policybindingmodel_ptr_id"`
			EngineMode string `json:"policy_engine_mode"`
		} `json:"results"`
	}
	if err := ak.Get(ctx, "/flows/bindings/?target="+flows.Results[0].PK, &bindings); err != nil {
		t.Fatal(err)
	}
	target := ""
	for _, b := range bindings.Results {
		if b.Order == 31 {
			if b.EngineMode != "all" {
				t.Fatalf("paddock-admin-login order 31 policy engine mode %q, want all", b.EngineMode)
			}
			target = b.PolicyPK
		}
	}
	if target == "" {
		t.Fatalf("paddock-admin-login has no stage binding at order 31: %+v", bindings.Results)
	}
	var pb struct {
		Results []struct {
			Policy        string `json:"policy"`
			Enabled       bool   `json:"enabled"`
			Negate        bool   `json:"negate"`
			FailureResult bool   `json:"failure_result"`
			PolicyObj     struct {
				Name string `json:"name"`
			} `json:"policy_obj"`
		} `json:"results"`
	}
	if err := ak.Get(ctx, "/policies/bindings/?target="+target, &pb); err != nil {
		t.Fatal(err)
	}
	var shipped, names []string
	for _, p := range pb.Results {
		if p.PolicyObj.Name == "paddock-dev-skip-mfa" {
			continue
		}
		if !p.Enabled || p.Negate {
			t.Errorf("policy binding of %s: enabled %v, negate %v", p.PolicyObj.Name, p.Enabled, p.Negate)
		}
		if p.PolicyObj.Name == "paddock-admin-login-webauthn-administrator" && !p.FailureResult {
			t.Error("paddock-admin-login-webauthn-administrator does not fail closed (failure_result false)")
		}
		shipped = append(shipped, p.Policy)
		names = append(names, p.PolicyObj.Name)
	}
	slices.Sort(names)
	if fmt.Sprint(names) != "[paddock-admin-login-webauthn-administrator paddock-admin-login-webauthn-missing]" {
		t.Fatalf("shipped policies of paddock-admin-login order 31: %v", names)
	}
	enrols := func(t *testing.T, username string) bool {
		t.Helper()
		pk, err := ak.UserPK(ctx, username)
		if err != nil || pk == 0 {
			t.Fatalf("user %s: pk %d, %v", username, pk, err)
		}
		for _, policy := range shipped {
			pass, err := ak.TestPolicy(ctx, policy, pk)
			if err != nil {
				t.Fatal(err)
			}
			if !pass {
				return false
			}
		}
		return true
	}
	for _, c := range []struct {
		name   string
		groups []string
		want   bool
	}{
		{"device user, no Paddock group", nil, false},
		{"device user, organization member", []string{env.RootGroup("acme")}, false},
		{"organization administrator", []string{env.RootGroup("acme"), env.RoleGroup("acme", "admins")}, true},
		{"organization operator", []string{env.RoleGroup("acme", "operators")}, true},
		{"organization auditor", []string{env.RoleGroup("acme", "auditors")}, true},
		{"platform administrator", []string{"paddock.platform.admins"}, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			user, _ := tempUser(t, "pdk498", c.groups...)
			if got := enrols(t, user); got != c.want {
				t.Errorf("stage B (passkey enrolment) runs for %s without a WebAuthn device: %v, want %v", c.name, got, c.want)
			}
		})
	}
}

// TestStepUpValidUntilInMe (plan M8x decision 36): GET /api/v1/me names the end of the session's step-up window for the
// portal's freshness indicator: null in a new session, within the next 300 s after a step-up.
func TestStepUpValidUntilInMe(t *testing.T) {
	p := login(t, env.Alice)
	validUntil := func() *time.Time {
		t.Helper()
		var me struct {
			ValidUntil *time.Time `json:"step_up_valid_until"`
		}
		res := call(t, p, http.MethodGet, "/api/v1/me", nil)
		expectStatus(t, res, http.StatusOK, "")
		if err := res.JSON(&me); err != nil {
			t.Fatal(err)
		}
		return me.ValidUntil
	}
	if v := validUntil(); v != nil {
		t.Fatalf("new session: step_up_valid_until %v, want null", v)
	}
	stepUp(t, p, env.Alice, true)
	now := time.Now()
	if v := validUntil(); v == nil || v.Before(now.Add(-expirySlack)) || v.After(now.Add(300*time.Second+expirySlack)) {
		t.Fatalf("after a step-up: step_up_valid_until %v, want within [now, now+300 s]", v)
	}
}

// totpClass is the authenticator class the development stack's step-up accepts (PADDOCK_STEPUP_MFA_CLASS).
const totpClass = "authentik_stages_authenticator_totp.totpdevice"

// TestStepUpFactorClaim (plan M8f decision 11): the step-up token names the authenticator classes the step-up
// validated (claim paddock_mfa_classes of the mapping io.paddock/scope-stepup-mfa), and the api records them: the
// development users step up with TOTP. An Authentik upgrade that changes the login event fails this gate.
func TestStepUpFactorClaim(t *testing.T) {
	alice := login(t, env.Alice)
	stepUp(t, alice, env.Alice, true)
	if got := serverStepUp(t, alice).MFAClasses; fmt.Sprint(got) != "["+totpClass+"]" {
		t.Fatalf("step_up.mfa_classes %v, want [%s]", got, totpClass)
	}
}

// TestStepUpHeldAuthorizeURL (plan M8f decisions 5 and 11) opens the authorization URL of a started step-up after a
// sign-in through another Authentik flow of the same browser: it records whether Authentik answered it without
// running paddock-stepup and, when the api accepted it, that the api names the factor of the login it received, so
// that the production class check refuses a TOTP login (unit tests of stepup.go).
func TestStepUpHeldAuthorizeURL(t *testing.T) {
	u := steppedUpTempUser(t, "pdk297", env.RoleGroup("acme", "admins"))
	ctx := testContext(t, 3*time.Minute)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, stack.AdminURL()+"/api/auth/stepup?return_to=%2Fsettings", nil)
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now().Truncate(time.Second)
	resp, err := u.Client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	held := resp.Header.Get("Location")
	if resp.StatusCode != http.StatusFound || !strings.Contains(held, "/application/o/authorize/") {
		t.Fatalf("step-up start: %d %s", resp.StatusCode, held)
	}
	// Another flow of the same browser, after the start: Authentik's default authentication flow with password and
	// TOTP (the development blueprint skips Paddock's stage at order 31; Authentik's own stage validates TOTP).
	flow := stack.AuthURL() + "/if/flow/default-authentication-flow/"
	if _, err := authflow.RunFlow(ctx, u.Client, flow, u.username, u.password, u.totp); err != nil {
		t.Fatalf("sign-in through %s: %v", flow, err)
	}
	r, err := http.NewRequestWithContext(ctx, http.MethodGet, held, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err = u.Client.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	next := resp.Header.Get("Location")
	if resp.StatusCode != http.StatusFound || next == "" {
		t.Fatalf("held authorization URL: HTTP %d, Location %q", resp.StatusCode, next)
	}
	skipped := !strings.Contains(next, "/if/flow/")
	res, err := authflow.Follow(ctx, u.Client, stack.AdminURL(), next, u.username, u.password, u.totp)
	if err != nil {
		t.Fatalf("follow the held authorization URL: %v", err)
	}
	passed := !strings.Contains(res.Final, "stepup=failed")
	t.Logf("held authorization URL: Authentik skipped paddock-stepup %v (redirect %s), step-up accepted %v (returned to %s)",
		skipped, next, passed, res.Final)
	if !passed {
		return
	}
	s := serverStepUp(t, u.Portal)
	if s.At == nil || s.At.Before(started) {
		t.Fatalf("step_up.at %v, want after the start %s", s.At, started)
	}
	if fmt.Sprint(s.MFAClasses) != "["+totpClass+"]" {
		t.Fatalf("step_up.mfa_classes %v, want [%s]", s.MFAClasses, totpClass)
	}
}
