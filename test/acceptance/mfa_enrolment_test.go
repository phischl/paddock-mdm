package acceptance

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/test/acceptance/internal/authflow"
	"github.com/phischl/paddock-mdm/test/acceptance/internal/env"
	"github.com/phischl/paddock-mdm/test/acceptance/internal/stack"
)

// boundStage is a stage binding of a flow with the policies bound to it.
type boundStage struct {
	Order      int
	EngineMode string
	// Policies are the names of the bound policies, sorted.
	Policies []string
	// PolicyPKs are the bound policies by name; Negated and FailClosed name the bindings with negate and
	// failure_result set.
	PolicyPKs  map[string]string
	Negated    map[string]bool
	FailClosed map[string]bool
	// Stage is the stage's pk.
	Stage string
}

// flowStages reads the stage bindings of the flow slug keyed by stage name, with their policy bindings.
func flowStages(ctx context.Context, t *testing.T, ak *env.Authentik, slug string) map[string]boundStage {
	t.Helper()
	var flows struct {
		Results []struct {
			PK string `json:"pk"`
		} `json:"results"`
	}
	if err := ak.Get(ctx, "/flows/instances/?slug="+slug, &flows); err != nil || len(flows.Results) != 1 {
		t.Fatalf("flow %s: %+v %v", slug, flows, err)
	}
	var bindings struct {
		Results []struct {
			Order      int    `json:"order"`
			Stage      string `json:"stage"`
			PolicyPK   string `json:"policybindingmodel_ptr_id"`
			EngineMode string `json:"policy_engine_mode"`
			StageObj   struct {
				Name string `json:"name"`
			} `json:"stage_obj"`
		} `json:"results"`
	}
	if err := ak.Get(ctx, "/flows/bindings/?page_size=100&target="+flows.Results[0].PK, &bindings); err != nil {
		t.Fatal(err)
	}
	out := map[string]boundStage{}
	for _, b := range bindings.Results {
		var pb struct {
			Results []struct {
				Policy        string `json:"policy"`
				Negate        bool   `json:"negate"`
				FailureResult bool   `json:"failure_result"`
				PolicyObj     struct {
					Name string `json:"name"`
				} `json:"policy_obj"`
			} `json:"results"`
		}
		if err := ak.Get(ctx, "/policies/bindings/?target="+b.PolicyPK, &pb); err != nil {
			t.Fatal(err)
		}
		s := boundStage{Order: b.Order, EngineMode: b.EngineMode, Stage: b.Stage, PolicyPKs: map[string]string{},
			Negated: map[string]bool{}, FailClosed: map[string]bool{}}
		for _, p := range pb.Results {
			s.Policies = append(s.Policies, p.PolicyObj.Name)
			s.PolicyPKs[p.PolicyObj.Name] = p.Policy
			s.Negated[p.PolicyObj.Name] = p.Negate
			s.FailClosed[p.PolicyObj.Name] = p.FailureResult
		}
		slices.Sort(s.Policies)
		out[b.StageObj.Name] = s
	}
	return out
}

// stagesAt returns the stage names of stages by order, sorted.
func stagesAt(stages map[string]boundStage) map[int][]string {
	out := map[int][]string{}
	for name, b := range stages {
		out[b.Order] = append(out[b.Order], name)
	}
	for order := range out {
		slices.Sort(out[order])
	}
	return out
}

// expectStagesAt fails unless the flow binds exactly the stages want at each of the orders of want.
func expectStagesAt(t *testing.T, flow string, stages map[string]boundStage, want map[int][]string) {
	t.Helper()
	got := stagesAt(stages)
	for order, names := range want {
		if w := slices.Sorted(slices.Values(names)); !slices.Equal(got[order], w) {
			t.Errorf("%s order %d binds %v, want exactly %v", flow, order, got[order], w)
		}
	}
}

// enforceMFA gives the account the test attribute paddock_dev_enforce_mfa, which turns the development blueprint's
// skip of the second-factor stages off for it, so that the gate meets the shipped deny and enrolment paths.
func enforceMFA(ctx context.Context, t *testing.T, ak *env.Authentik, username string, marked bool) int {
	t.Helper()
	pk, err := ak.UserPK(ctx, username)
	if err != nil || pk == 0 {
		t.Fatalf("user %s: pk %d, %v", username, pk, err)
	}
	if err := ak.SetUserAttribute(ctx, pk, "paddock_dev_enforce_mfa", true); err != nil {
		t.Fatal(err)
	}
	if marked {
		if err := ak.SetUserAttribute(ctx, pk, "paddock_mfa_enrol_at_login", true); err != nil {
			t.Fatal(err)
		}
	}
	return pk
}

// passes evaluates the shipped policies of a binding (all except the development skip; the binding's mode is "all")
// for the user pk through Authentik's policy test endpoint.
func (s boundStage) passes(ctx context.Context, t *testing.T, ak *env.Authentik, pk int) bool {
	t.Helper()
	for name, policy := range s.PolicyPKs {
		if name == "paddock-dev-skip-mfa" {
			continue
		}
		pass, err := ak.TestPolicy(ctx, policy, pk)
		if err != nil {
			t.Fatal(err)
		}
		if s.Negated[name] {
			pass = !pass
		}
		if !pass {
			return false
		}
	}
	return true
}

// TestMFAEnrolmentSignInBindings is gate MF1/MF2's structure (plan M12h-2 decision 7, amendment c point 1): each
// second-factor stage of the portal sign-in and of Authentik's default flow denies an account without a factor, and a
// sibling at the same order enrols one; both evaluate their policies when reached, in mode "all", so the development
// blueprint's skip still applies to every one of them.
func TestMFAEnrolmentSignInBindings(t *testing.T) {
	ctx := testContext(t, time.Minute)
	ak, err := env.NewAuthentik()
	if err != nil {
		t.Fatal(err)
	}
	const (
		absent  = "paddock-mfa-enrol-at-login-absent"
		enrol   = "paddock-mfa-enrol-at-login"
		admin   = "paddock-admin-login-webauthn-administrator"
		missing = "paddock-admin-login-webauthn-missing"
		skip    = "paddock-dev-skip-mfa"
		factor  = "paddock-default-login-mfa-missing"
	)
	expectStagesAt(t, "paddock-admin-login", flowStages(ctx, t, ak, "paddock-admin-login"), map[int][]string{
		30: {"paddock-admin-login-mfa", "paddock-admin-login-mfa-enrol"},
		31: {"paddock-admin-login-webauthn", "paddock-admin-login-webauthn-enrol"},
		32: {"paddock-admin-login-webauthn-confirm"},
	})
	expectStagesAt(t, "default-authentication-flow", flowStages(ctx, t, ak, "default-authentication-flow"), map[int][]string{
		31: {"paddock-default-login-mfa", "paddock-default-login-mfa-enrol"},
	})
	for _, c := range []struct {
		flow, stage, action string
		order               int
		policies            []string
	}{
		{"paddock-admin-login", "paddock-admin-login-mfa", "deny", 30, []string{admin, skip, absent}},
		{"paddock-admin-login", "paddock-admin-login-mfa-enrol", "configure", 30, []string{skip, enrol}},
		{"paddock-admin-login", "paddock-admin-login-webauthn", "deny", 31, []string{admin, missing, skip, absent}},
		{"paddock-admin-login", "paddock-admin-login-webauthn-enrol", "configure", 31, []string{admin, missing, skip, enrol}},
		{"default-authentication-flow", "paddock-default-login-mfa", "deny", 31, []string{admin, factor, skip, absent}},
		{"default-authentication-flow", "paddock-default-login-mfa-enrol", "configure", 31, []string{factor, skip, enrol}},
	} {
		t.Run(c.stage, func(t *testing.T) {
			b, ok := flowStages(ctx, t, ak, c.flow)[c.stage]
			if !ok {
				t.Fatalf("%s has no binding of %s", c.flow, c.stage)
			}
			want := slices.Sorted(slices.Values(c.policies))
			if b.Order != c.order || b.EngineMode != "all" || fmt.Sprint(b.Policies) != fmt.Sprint(want) {
				t.Errorf("binding: order %d, mode %q, policies %v; want order %d, mode all, policies %v", b.Order, b.EngineMode,
					b.Policies, c.order, want)
			}
			for name, negated := range b.Negated {
				if negated {
					t.Errorf("policy %s is negated", name)
				}
			}
			if c.action == "deny" && (!b.FailClosed[admin] || !b.FailClosed[absent]) {
				t.Errorf("the deny stage's policies do not fail closed: %v", b.FailClosed)
			}
			var v struct {
				NotConfiguredAction string `json:"not_configured_action"`
			}
			if err := ak.Get(ctx, "/stages/authenticator/validate/"+b.Stage+"/", &v); err != nil {
				t.Fatal(err)
			}
			if v.NotConfiguredAction != c.action {
				t.Errorf("not_configured_action %q, want %s", v.NotConfiguredAction, c.action)
			}
		})
	}
}

// TestMFAEnrolmentSignInScope is gate MF1/MF2's truth table (plan M12h-2 amendment c point 1), through Authentik's
// policy test endpoint because the development blueprint skips the stages for everybody: for an account without a
// factor, exactly one stage of each pair runs; an unmarked administrator meets the deny stage (MF1), a marked one the
// enrolment (MF2), and a device user without a portal role keeps today's enrolment.
func TestMFAEnrolmentSignInScope(t *testing.T) {
	ctx := testContext(t, 2*time.Minute)
	ak, err := env.NewAuthentik()
	if err != nil {
		t.Fatal(err)
	}
	login := flowStages(ctx, t, ak, "paddock-admin-login")
	def := flowStages(ctx, t, ak, "default-authentication-flow")
	pairs := []struct {
		name        string
		deny, enrol boundStage
	}{
		{"stage A", login["paddock-admin-login-mfa"], login["paddock-admin-login-mfa-enrol"]},
		{"default flow", def["paddock-default-login-mfa"], def["paddock-default-login-mfa-enrol"]},
	}
	stageB := login["paddock-admin-login-webauthn"]
	stageBEnrol := login["paddock-admin-login-webauthn-enrol"]
	for _, b := range []boundStage{pairs[0].deny, pairs[0].enrol, pairs[1].deny, pairs[1].enrol, stageB, stageBEnrol} {
		if b.Stage == "" || len(b.PolicyPKs) == 0 {
			t.Fatal("a stage binding of the sign-in or its policies are missing (TestMFAEnrolmentSignInBindings names it)")
		}
	}
	for _, c := range []struct {
		name   string
		groups []string
		marked bool
		enrols bool // stage A and the default flow
		stageB string
	}{
		{"device user, no Paddock group", nil, false, true, "none"},
		{"device user, organization member", []string{env.RootGroup("acme")}, false, true, "none"},
		{"organization administrator", []string{env.RootGroup("acme"), env.RoleGroup("acme", "admins")}, false, false, "deny"},
		{"organization operator", []string{env.RoleGroup("acme", "operators")}, false, false, "deny"},
		{"platform administrator", []string{"paddock.platform.admins"}, false, false, "deny"},
		{"marked organization administrator", []string{env.RoleGroup("acme", "admins")}, true, true, "enrol"},
		{"marked platform administrator", []string{"paddock.platform.admins"}, true, true, "enrol"},
		{"marked device user", nil, true, true, "none"},
	} {
		t.Run(c.name, func(t *testing.T) {
			user, _ := tempUser(t, "mf1", c.groups...)
			pk, err := ak.UserPK(ctx, user)
			if err != nil || pk == 0 {
				t.Fatalf("user %s: pk %d, %v", user, pk, err)
			}
			if c.marked {
				if err := ak.SetUserAttribute(ctx, pk, "paddock_mfa_enrol_at_login", true); err != nil {
					t.Fatal(err)
				}
			}
			for _, p := range pairs {
				deny, enrolls := p.deny.passes(ctx, t, ak, pk), p.enrol.passes(ctx, t, ak, pk)
				if deny == enrolls || enrolls != c.enrols {
					t.Errorf("%s: deny stage runs %v, enrolment runs %v; want enrolment %v and exactly one", p.name, deny, enrolls, c.enrols)
				}
			}
			got := "none"
			switch b, e := stageB.passes(ctx, t, ak, pk), stageBEnrol.passes(ctx, t, ak, pk); {
			case b && e:
				got = "both"
			case b:
				got = "deny"
			case e:
				got = "enrol"
			}
			if got != c.stageB {
				t.Errorf("stage B for an account without a passkey: %s, want %s", got, c.stageB)
			}
		})
	}
}

// TestMFAEnrolmentRecoveryFlow is the structure of the sign-in setup link's flow (ADR 0053 decision 2 and amendment d,
// gate MF3's flow part): the password stages only for an account without a password, then the passkey, all behind the
// link token, and no authenticator app stage.
func TestMFAEnrolmentRecoveryFlow(t *testing.T) {
	ctx := testContext(t, time.Minute)
	ak, err := env.NewAuthentik()
	if err != nil {
		t.Fatal(err)
	}
	var flow struct {
		Results []struct {
			Title string `json:"title"`
		} `json:"results"`
	}
	if err := ak.Get(ctx, "/flows/instances/?slug=paddock-recovery", &flow); err != nil || len(flow.Results) != 1 ||
		flow.Results[0].Title != "Set up your sign-in" {
		t.Fatalf("flow paddock-recovery: %+v %v", flow, err)
	}
	stages := flowStages(ctx, t, ak, "paddock-recovery")
	for name, want := range map[string]struct {
		order    int
		policies []string
	}{
		"paddock-recovery-password":            {10, []string{"paddock-recovery-link-token", "paddock-recovery-password-missing"}},
		"paddock-recovery-user-write":          {20, []string{"paddock-recovery-link-token", "paddock-recovery-password-missing"}},
		"default-authenticator-webauthn-setup": {30, []string{"paddock-recovery-link-token", "paddock-recovery-webauthn-missing"}},
	} {
		b, ok := stages[name]
		if !ok {
			t.Errorf("paddock-recovery has no binding of %s", name)
			continue
		}
		if b.Order != want.order || fmt.Sprint(b.Policies) != fmt.Sprint(want.policies) {
			t.Errorf("%s: order %d, policies %v; want %d, %v", name, b.Order, b.Policies, want.order, want.policies)
		}
		if len(b.Policies) > 1 && b.EngineMode != "all" {
			t.Errorf("%s evaluates its policies in mode %q, want all", name, b.EngineMode)
		}
	}
	// Without a one-time link the flow has no user: a visitor sees neither the password prompt nor the passkey setup.
	hc, err := env.NewHTTPClient()
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, stack.AuthURL()+"/api/v3/flows/executor/paddock-recovery/?query=", nil)
	if err != nil {
		t.Fatal(err)
	}
	res, err := hc.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var ch struct {
		Component string `json:"component"`
	}
	err = json.NewDecoder(res.Body).Decode(&ch)
	_ = res.Body.Close()
	if err != nil || ch.Component == "ak-stage-prompt" || ch.Component == "ak-stage-authenticator-webauthn" {
		t.Errorf("paddock-recovery without a link answers %q (%d, %v), want no prompt and no passkey setup", ch.Component,
			res.StatusCode, err)
	}
	names := slices.Sorted(maps.Keys(stages))
	want := []string{"default-authenticator-webauthn-setup", "paddock-recovery-password", "paddock-recovery-user-write"}
	if !slices.Equal(names, want) {
		t.Errorf("paddock-recovery binds %v, want exactly %v (no authenticator app stage)", names, want)
	}
}

// TestMFAEnrolmentSignInFlow is gate MF1/MF2 at flow level (plan M12h-2 amendment c points 1 and 3) with accounts the
// development blueprint does not skip (enforceMFA): Authentik denies a new administrator without a factor in the
// portal sign-in, so no portal session and no successful admin.login exist; a marked administrator is sent to the
// passkey setup instead; and a new device user without a factor still reaches the passkey setup through /device.
func TestMFAEnrolmentSignInFlow(t *testing.T) {
	ctx := testContext(t, 3*time.Minute)
	ak, err := env.NewAuthentik()
	if err != nil {
		t.Fatal(err)
	}
	signIn := func(t *testing.T, username, password string) (*http.Client, error) {
		t.Helper()
		client, err := env.NewHTTPClient()
		if err != nil {
			t.Fatal(err)
		}
		_, err = authflow.Login(ctx, client, stack.AdminURL(), username, password)
		return client, err
	}
	t.Run("new administrator without a factor is denied", func(t *testing.T) {
		user, password := tempUser(t, "mf1", env.RootGroup("acme"), env.RoleGroup("acme", "admins"))
		enforceMFA(ctx, t, ak, user, false)
		client, err := signIn(t, user, password)
		if !errors.Is(err, authflow.ErrAccessDenied) {
			t.Fatalf("sign-in: %v, want Authentik's access denial", err)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, stack.AdminURL()+"/api/v1/me", nil)
		if err != nil {
			t.Fatal(err)
		}
		res, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = res.Body.Close()
		if res.StatusCode != http.StatusUnauthorized {
			t.Errorf("GET /api/v1/me after the denial: %d, want 401 (no portal session)", res.StatusCode)
		}
		// An organization administrator's admin.login is recorded in its organization. Positive control: an acme
		// administrator's sign-in after the denial must appear there, so the index has caught up past the denial and
		// the query would have found the denied administrator's success.
		idx := auditIndex(t)
		const success = "code = 'admin.login' AND outcome = 'success' AND actor->>'display' = $1"
		acme := orgOf(t, login(t, env.Alice))
		before, err := idx.Events(ctx, acme, success, env.Alice)
		if err != nil {
			t.Fatal(err)
		}
		login(t, env.Alice)
		eventually(t, "a new control sign-in's admin.login in acme", roleAuditWait, func() bool {
			control, err := idx.Events(ctx, acme, success, env.Alice)
			return err == nil && len(control) > len(before)
		})
		for _, org := range []uuid.UUID{acme, platformOrg} {
			events, err := idx.Events(ctx, org, success, user)
			if err != nil {
				t.Fatal(err)
			}
			if len(events) != 0 {
				t.Errorf("admin.login success recorded in %s for the denied administrator: %+v", org, events)
			}
		}
	})
	t.Run("marked administrator is sent to the passkey setup", func(t *testing.T) {
		user, password := tempUser(t, "mf2", env.RootGroup("acme"), env.RoleGroup("acme", "admins"))
		enforceMFA(ctx, t, ak, user, true)
		_, err := signIn(t, user, password)
		var stage *authflow.StageError
		if !errors.As(err, &stage) || stage.Flow != "paddock-admin-login" || stage.Component != "ak-stage-authenticator-webauthn" {
			t.Fatalf("sign-in: %v, want the passkey setup of paddock-admin-login", err)
		}
	})
	t.Run("new device user without a factor reaches the passkey setup on /device", func(t *testing.T) {
		u := newDeviceUser(t, ak, "mf1-device", "acme.test", env.RootGroup("acme"))
		enforceMFA(ctx, t, ak, u.name, false)
		_, stages, err := deviceLogin(t, "paddock-device-acme", u)
		var stage *authflow.StageError
		if !errors.As(err, &stage) || stage.Component != "ak-stage-authenticator-webauthn" {
			t.Fatalf("device approval: %v (stages %v), want the passkey setup", err, stages)
		}
		if !slices.Contains(stages, "paddock-admin-login ak-stage-authenticator-webauthn") ||
			slices.ContainsFunc(stages, func(s string) bool { return strings.HasSuffix(s, " ak-stage-access-denied") }) {
			t.Errorf("stages %v, want the brand flow's passkey setup and no denial", stages)
		}
	})
}

// TestMFAEnrolmentDeviceSignIn is the regression gate of plan M12h-2 amendment e: administrators set up their second
// factor only through the setup link, in every device sign-in flow, and device users still set theirs up at their
// first device sign-in.
//   - Structure: both device flows bind the deny stage and its enrolment sibling at the same order, as the portal
//     sign-in does.
//   - paddock-device-authentication, with accounts the development blueprint does not skip (enforceMFA): an
//     administrator without a factor and without the mark is denied; a device user and a marked administrator get the
//     authenticator setup.
//   - paddock-device-authorization, which the development blueprint does not skip: an administrator without a factor
//     signs in through the skipped portal sign-in and is denied at the device approval, without a setup.
func TestMFAEnrolmentDeviceSignIn(t *testing.T) {
	ctx := testContext(t, 3*time.Minute)
	ak, err := env.NewAuthentik()
	if err != nil {
		t.Fatal(err)
	}
	const (
		absent = "paddock-mfa-enrol-at-login-absent"
		enrol  = "paddock-mfa-enrol-at-login"
		admin  = "paddock-admin-login-webauthn-administrator"
		skip   = "paddock-dev-skip-mfa"
		authn  = "paddock-device-authentication"
		authz  = "paddock-device-authorization"
	)
	t.Run("structure", func(t *testing.T) {
		signIn, approval := flowStages(ctx, t, ak, authn), flowStages(ctx, t, ak, authz)
		expectStagesAt(t, authn, signIn, map[int][]string{30: {"paddock-device-mfa", "paddock-device-mfa-enrol"}})
		expectStagesAt(t, authz, approval, map[int][]string{10: {"paddock-device-mfa", "paddock-device-mfa-enrol"}})
		for _, c := range []struct {
			flow     string
			stages   map[string]boundStage
			stage    string
			action   string
			policies []string
		}{
			{authn, signIn, "paddock-device-mfa", "deny", []string{admin, skip, absent}},
			{authn, signIn, "paddock-device-mfa-enrol", "configure", []string{skip, enrol}},
			{authz, approval, "paddock-device-mfa", "deny", []string{admin, absent}},
			{authz, approval, "paddock-device-mfa-enrol", "configure", []string{enrol}},
		} {
			b, ok := c.stages[c.stage]
			if !ok {
				t.Errorf("%s has no binding of %s", c.flow, c.stage)
				continue
			}
			want := slices.Sorted(slices.Values(c.policies))
			if b.EngineMode != "all" || fmt.Sprint(b.Policies) != fmt.Sprint(want) {
				t.Errorf("%s %s: mode %q, policies %v; want mode all, policies %v", c.flow, c.stage, b.EngineMode, b.Policies, want)
			}
			if c.action == "deny" && (!b.FailClosed[admin] || !b.FailClosed[absent]) {
				t.Errorf("%s %s: the deny stage's policies do not fail closed: %v", c.flow, c.stage, b.FailClosed)
			}
			var v struct {
				NotConfiguredAction string `json:"not_configured_action"`
			}
			if err := ak.Get(ctx, "/stages/authenticator/validate/"+b.Stage+"/", &v); err != nil {
				t.Fatal(err)
			}
			if v.NotConfiguredAction != c.action {
				t.Errorf("%s %s: not_configured_action %q, want %s", c.flow, c.stage, v.NotConfiguredAction, c.action)
			}
		}
	})
	signIn := func(t *testing.T, username, password string) error {
		t.Helper()
		client, err := env.NewHTTPClient()
		if err != nil {
			t.Fatal(err)
		}
		_, err = authflow.RunFlow(ctx, client, stack.AuthURL()+"/if/flow/"+authn+"/", username, password, &authflow.TOTP{})
		return err
	}
	expectSetup := func(t *testing.T, err error) {
		t.Helper()
		var stage *authflow.StageError
		if !errors.As(err, &stage) || stage.Flow != authn || stage.Component != "ak-stage-authenticator-totp" {
			t.Fatalf("device sign-in: %v, want the authenticator setup of %s", err, authn)
		}
	}
	t.Run("administrator without a factor is denied in the device sign-in", func(t *testing.T) {
		user, password := tempUser(t, "mf5", env.RootGroup("acme"), env.RoleGroup("acme", "admins"))
		enforceMFA(ctx, t, ak, user, false)
		if err := signIn(t, user, password); !errors.Is(err, authflow.ErrAccessDenied) {
			t.Fatalf("device sign-in: %v, want Authentik's access denial", err)
		}
	})
	t.Run("platform administrator without a factor is denied in the device sign-in", func(t *testing.T) {
		user, password := tempUser(t, "mf5", "paddock.platform.admins")
		enforceMFA(ctx, t, ak, user, false)
		if err := signIn(t, user, password); !errors.Is(err, authflow.ErrAccessDenied) {
			t.Fatalf("device sign-in: %v, want Authentik's access denial", err)
		}
	})
	t.Run("device user without a factor gets the setup in the device sign-in", func(t *testing.T) {
		user, password := tempUser(t, "mf5-device", env.RootGroup("acme"))
		enforceMFA(ctx, t, ak, user, false)
		expectSetup(t, signIn(t, user, password))
	})
	t.Run("marked administrator gets the setup in the device sign-in", func(t *testing.T) {
		user, password := tempUser(t, "mf5", env.RootGroup("acme"), env.RoleGroup("acme", "admins"))
		enforceMFA(ctx, t, ak, user, true)
		expectSetup(t, signIn(t, user, password))
	})
	t.Run("administrator without a factor is denied at the device approval", func(t *testing.T) {
		u := newDeviceUser(t, ak, "mf5-approval", "acme.test", env.RootGroup("acme"), env.RoleGroup("acme", "admins"))
		_, stages, err := deviceLogin(t, "paddock-device-acme", u)
		if !errors.Is(err, authflow.ErrAccessDenied) {
			t.Fatalf("device approval: %v (stages %v), want Authentik's access denial", err, stages)
		}
		if !slices.Contains(stages, authz+" ak-stage-access-denied") ||
			slices.ContainsFunc(stages, func(s string) bool { return strings.HasSuffix(s, " ak-stage-authenticator-totp") }) ||
			u.totp.Secret != "" {
			t.Errorf("stages %v, want the denial in %s and no authenticator setup", stages, authz)
		}
	})
}

// seedState reads the seed's row of platform_mfa_enrolment (test-only database access): the first attempt's time and,
// once the seed completed, its time; ok is false while the worker has not tried yet.
func seedState(t *testing.T) (first, seeded time.Time, ok bool) {
	t.Helper()
	const layout = `'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'`
	out := paddockSQL(t, "SELECT to_char(first_attempt_at AT TIME ZONE 'UTC', "+layout+") || '|' || "+
		"coalesce(to_char(seeded_at AT TIME ZONE 'UTC', "+layout+"), '') FROM platform_mfa_enrolment")
	if out == "" {
		return time.Time{}, time.Time{}, false
	}
	parts := strings.SplitN(out, "|", 2)
	first, err := time.Parse(time.RFC3339Nano, parts[0])
	if err != nil {
		t.Fatalf("first_attempt_at %q: %v", out, err)
	}
	if len(parts) == 2 && parts[1] != "" {
		if seeded, err = time.Parse(time.RFC3339Nano, parts[1]); err != nil {
			t.Fatalf("seeded_at %q: %v", out, err)
		}
	}
	return first, seeded, true
}

// seedAccount is what the seed decides on for one account: its creation, whether it has a passkey and the mark.
type seedAccount struct {
	joined          time.Time
	passkey, marked bool
}

func readSeedAccount(ctx context.Context, t *testing.T, ak *env.Authentik, username string) seedAccount {
	t.Helper()
	pk, err := ak.UserPK(ctx, username)
	if err != nil || pk == 0 {
		t.Fatalf("user %s: pk %d, %v", username, pk, err)
	}
	var u struct {
		DateJoined time.Time      `json:"date_joined"`
		Attributes map[string]any `json:"attributes"`
	}
	if err := ak.Get(ctx, fmt.Sprintf("/core/users/%d/", pk), &u); err != nil {
		t.Fatal(err)
	}
	var devices []struct {
		Type string `json:"type"`
	}
	if err := ak.Get(ctx, fmt.Sprintf("/authenticators/admin/all/?user=%d", pk), &devices); err != nil {
		t.Fatal(err)
	}
	a := seedAccount{joined: u.DateJoined}
	a.marked, _ = u.Attributes["paddock_mfa_enrol_at_login"].(bool)
	for _, d := range devices {
		if strings.EqualFold(d.Type, "authentik_stages_authenticator_webauthn.webauthndevice") {
			a.passkey = true
		}
	}
	if a.joined.IsZero() {
		t.Fatalf("user %s without date_joined", username)
	}
	return a
}

// TestMFAEnrolmentSeed is gate MF4 (ADR 0053 decision 4 as amended). It asserts exactly what the seed's cutoff
// predicts and never passes without a marked administrator:
//   - The platform administrator is created in paddock.platform.admins in one step by the development blueprint, so
//     its membership is as old as the account. Created before the first attempt (first_attempt_at) and without a
//     passkey, it MUST be marked; created after it, it MUST be unmarked.
//   - When no administrator of before the cutoff exists (a fresh stack whose worker tried before the blueprint
//     created the platform administrator), the gate creates one and re-arms the seed through its test-only database
//     path (the row of platform_mfa_enrolment removed, as on a fresh install): the next round's seed MUST mark it.
//   - Exactly one seed event is recorded at or after the current first attempt.
//   - An administrator created after the cutoff stays unmarked after the round that granted its role.
//
// Accounts that dev-seed adds to role groups after their creation (Alice) are not asserted: date_joined is not their
// membership's time.
func TestMFAEnrolmentSeed(t *testing.T) {
	ctx := testContext(t, 15*time.Minute)
	ak, err := env.NewAuthentik()
	if err != nil {
		t.Fatal(err)
	}
	idx := auditIndex(t)
	var first, seeded time.Time
	var ok bool
	eventually(t, "the worker's seed", 2*syncRound, func() bool {
		first, seeded, ok = seedState(t)
		return ok && !seeded.IsZero()
	})
	if seeded.Before(first) {
		t.Fatalf("seeded_at %s before first_attempt_at %s", seeded, first)
	}
	asserted, adminAfterRearm := false, false
	admin := readSeedAccount(ctx, t, ak, env.PlatformAdmin)
	switch {
	case admin.joined.Before(first) && !admin.passkey && admin.marked:
		asserted = true
	case admin.joined.Before(first) && !admin.passkey:
		// Authentik applies the dev blueprint in one transaction and sets date_joined before its commit, so a first
		// attempt inside that window cannot see the admin yet; the re-armed seed below must then mark it too.
		adminAfterRearm = true
	case !admin.joined.Before(first) && admin.marked:
		t.Errorf("%s (created %s, after the first attempt %s) is marked", env.PlatformAdmin, admin.joined, first)
	}
	if !asserted {
		early, _ := tempUser(t, "mf4-early", env.RoleGroup("acme", "admins"))
		joined := readSeedAccount(ctx, t, ak, early).joined
		// Re-arming also marks the other dev admins without a passkey (Alice, Bob, Dave); the dev blueprint's MFA skip
		// keeps their sign-ins unchanged.
		paddockSQL(t, "DELETE FROM platform_mfa_enrolment")
		eventually(t, "the re-armed seed", 2*syncRound, func() bool {
			first, seeded, ok = seedState(t)
			return ok && !seeded.IsZero()
		})
		if !joined.Before(first) {
			t.Fatalf("the re-armed seed's first attempt %s is not after %s's creation %s", first, early, joined)
		}
		if a := readSeedAccount(ctx, t, ak, early); !a.marked {
			t.Errorf("%s (created %s, before the re-armed first attempt %s, no passkey) is not marked", early, a.joined, first)
		}
		if adminAfterRearm {
			if a := readSeedAccount(ctx, t, ak, env.PlatformAdmin); !a.marked {
				t.Errorf("%s (created %s, before the re-armed first attempt %s, no passkey) is not marked",
					env.PlatformAdmin, a.joined, first)
			}
		}
	}
	const seedEvents = "code = 'platform.mfa_enrol_marks_seeded' AND occurred_at >= $1"
	eventually(t, "the seed's audit event", roleAuditWait, func() bool {
		events, err := idx.Events(ctx, platformOrg, seedEvents, first)
		return err == nil && len(events) > 0
	})
	events, err := idx.Events(ctx, platformOrg, seedEvents, first)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].Outcome != "success" || events[0].Params["marked"] == nil {
		t.Fatalf("seed events since the first attempt: %+v, want exactly one success with the count marked", events)
	}

	acme := orgOf(t, login(t, env.Alice))
	late, _ := tempUser(t, "mf4", env.RootGroup("acme"), env.RoleGroup("acme", "admins"))
	if a := readSeedAccount(ctx, t, ak, late); a.joined.Before(first) {
		t.Fatalf("%s created %s, not after the first attempt %s", late, a.joined, first)
	}
	// The seed runs before the organizations of an admin-accounts round; once a round has recorded the new
	// administrator's grant, any seed of that round would have marked it.
	waitRoleEvents(t, idx, acme, "admin.role_granted", late, roleEventWait)
	if a := readSeedAccount(ctx, t, ak, late); a.marked {
		t.Errorf("%s, created after the first attempt, was marked", late)
	}
	if again, err := idx.Events(ctx, platformOrg, seedEvents, first); err != nil || len(again) != 1 {
		t.Errorf("seed events after a later round: %d (%v), want 1", len(again), err)
	}
}

// TestMF3EnrolmentLink is gate MF3 (plan M12h-2 §8, ADR 0053 decision 1 and amendment d): an organization administrator
// creates a one-time sign-in setup link only with a step-up; an operator never gets one. The link opens the setup
// flow, which sets the password of the new local user and registers a passkey and asks for no authenticator app;
// afterwards the new administrator signs in to the portal with that passkey. The same link used again, after the
// passkey was removed, is refused instead of offering the passkey setup, while a new link does offer it; the audit
// event names the user but never carries the link.
func TestMF3EnrolmentLink(t *testing.T) {
	ctx := testContext(t, 8*time.Minute)
	ak, err := env.NewAuthentik()
	if err != nil {
		t.Fatal(err)
	}
	alice := login(t, env.Alice)
	u := createLocalUser(t, alice, "mf3")
	// The administrator role comes before the link (the advice of the user page), and the development skip of the
	// second factor is off for this account, so its sign-in needs the passkey the link sets up.
	if err := ak.AddToGroup(ctx, u.Username, env.RoleGroup("acme", "admins")); err != nil {
		t.Fatal(err)
	}
	enforceMFA(ctx, t, ak, u.Username, false)
	path := "/api/v1/users/" + u.ID + "/enrolment-link"

	opName, opPassword := tempUser(t, "mf3-operator", env.RootGroup("acme"), env.RoleGroup("acme", "operators"))
	operator, err := loginAs(t, opName, opPassword)
	if err != nil {
		t.Fatalf("operator sign-in: %v", err)
	}
	expectStatus(t, call(t, operator, http.MethodPost, path, nil), http.StatusForbidden, "forbidden")

	res := call(t, alice, http.MethodPost, path, nil)
	expectStatus(t, res, http.StatusForbidden, "step_up_required")
	expectOneEvent(t, alice, res.RequestID, "user.enrolment_link_created", "denied")

	stepUp(t, alice, env.Alice, true)
	requested := time.Now()
	res = call(t, alice, http.MethodPost, path, nil)
	expectStatus(t, res, http.StatusCreated, "")
	var link struct {
		Link      string    `json:"link"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	if err := res.JSON(&link); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(link.Link, "/if/flow/paddock-recovery/") ||
		link.ExpiresAt.Before(requested.Add(24*time.Hour-time.Minute)) || link.ExpiresAt.After(time.Now().Add(24*time.Hour)) {
		t.Fatalf("link %q expiring %s, want the setup flow for 24 hours", link.Link, link.ExpiresAt)
	}
	ev := expectOneEvent(t, alice, res.RequestID, "user.enrolment_link_created", "success")
	params, _ := json.Marshal(ev.Params)
	token := link.Link[strings.LastIndex(link.Link, "=")+1:]
	if ev.Params["username"] != u.Username || ev.Params["link"] != nil || strings.Contains(string(params), token) {
		t.Fatalf("audit params %s, want the username and never the link", params)
	}

	browser, err := env.NewHTTPClient()
	if err != nil {
		t.Fatal(err)
	}
	password := "pw-" + uuid.NewString()
	passkey, err := authflow.NewWebAuthn()
	if err != nil {
		t.Fatal(err)
	}
	seen, err := authflow.SetupLink(ctx, browser, link.Link, password, passkey)
	want := []string{"ak-stage-prompt", "ak-stage-authenticator-webauthn", "xak-flow-redirect"}
	if err != nil || !slices.Equal(seen, want) {
		t.Fatalf("setup link: %v, stages %v, want %v (password, passkey, no authenticator app)", err, seen, want)
	}

	client, err := env.NewHTTPClient()
	if err != nil {
		t.Fatal(err)
	}
	signedIn, err := authflow.LoginMFA(ctx, client, stack.AdminURL(), u.Username, password, passkey)
	if err != nil {
		t.Fatalf("sign-in with the new passkey: %v", err)
	}
	if got := whoami(t, &env.Portal{User: u.Username, Client: signedIn.Client}); got.Role != "org_admin" {
		t.Fatalf("signed in as %+v, want the acme administrator", got)
	}

	// Single use, decided by the passkey step: once the account's passkey is removed, a link whose token were still
	// valid would show the passkey setup again (the password step stays skipped, the account has one now).
	accountPK, err := ak.UserPK(ctx, u.Username)
	if err != nil || accountPK == 0 {
		t.Fatalf("user %s: pk %d, %v", u.Username, accountPK, err)
	}
	removePasskeys(ctx, t, ak, accountPK)
	again, err := env.NewHTTPClient()
	if err != nil {
		t.Fatal(err)
	}
	seen, err = authflow.SetupLink(ctx, again, link.Link, "pw-"+uuid.NewString(), nil)
	if slices.Contains(seen, "ak-stage-authenticator-webauthn") || slices.Contains(seen, "ak-stage-prompt") {
		t.Fatalf("the link used twice: %v, stages %v, want it refused: no passkey and no password step", err, seen)
	}
	// Only a refusal Authentik answered counts: a transport error or timeout says nothing about the token.
	var stageErr *authflow.StageError
	var execErr *authflow.ExecutorError
	if !errors.Is(err, authflow.ErrAccessDenied) && !errors.As(err, &stageErr) && !errors.As(err, &execErr) {
		t.Fatalf("the link used twice: %v, stages %v, want a refusal by Authentik", err, seen)
	}
	// Positive control: a new link for the same account, still without a passkey, does show the passkey setup, so the
	// check above fails for a link that still works.
	stepUp(t, alice, env.Alice, true)
	res = call(t, alice, http.MethodPost, path, nil)
	expectStatus(t, res, http.StatusCreated, "")
	var fresh struct {
		Link string `json:"link"`
	}
	if err := res.JSON(&fresh); err != nil {
		t.Fatal(err)
	}
	control, err := env.NewHTTPClient()
	if err != nil {
		t.Fatal(err)
	}
	seen, err = authflow.SetupLink(ctx, control, fresh.Link, "", nil)
	var stage *authflow.StageError
	if !errors.As(err, &stage) || stage.Component != "ak-stage-authenticator-webauthn" || slices.Contains(seen, "ak-stage-prompt") {
		t.Fatalf("a new link without a passkey: %v, stages %v, want the passkey setup and no password step", err, seen)
	}
}

// TestMF3EnrolmentLinkPlatformAdministrator (plan M12h-2 amendment f point 4, ADR 0045): an account of acme that is
// also a direct member of paddock.platform.admins gets no setup link from acme's administrator. The request answers
// 409 invalid_state, records exactly one failure and returns no link; the host command issues that account's link.
func TestMF3EnrolmentLinkPlatformAdministrator(t *testing.T) {
	ctx := testContext(t, 2*time.Minute)
	ak, err := env.NewAuthentik()
	if err != nil {
		t.Fatal(err)
	}
	alice := login(t, env.Alice)
	u := createLocalUser(t, alice, "mf3-dual")
	for _, group := range []string{env.RoleGroup("acme", "admins"), platformAdminsGroup} {
		if err := ak.AddToGroup(ctx, u.Username, group); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { _ = ak.RemoveFromGroup(context.Background(), u.Username, platformAdminsGroup) })

	stepUp(t, alice, env.Alice, true)
	res := call(t, alice, http.MethodPost, "/api/v1/users/"+u.ID+"/enrolment-link", nil)
	expectStatus(t, res, http.StatusConflict, "invalid_state")
	if !strings.Contains(string(res.Body), "platform administrators receive their setup link from the host operator") ||
		strings.Contains(string(res.Body), "/if/flow/") {
		t.Fatalf("refusal %s, want the host operator detail and no link", res.Body)
	}
	if ev := expectOneEvent(t, alice, res.RequestID, "user.enrolment_link_created", "failure"); ev.ErrorCode != "invalid_state" {
		t.Fatalf("event error code %q, want invalid_state", ev.ErrorCode)
	}
}

// removePasskeys deletes every WebAuthn device of the Authentik user pk and confirms that none is left.
func removePasskeys(ctx context.Context, t *testing.T, ak *env.Authentik, pk int) {
	t.Helper()
	list := func() []string {
		var devices []struct {
			PK   any    `json:"pk"`
			Type string `json:"type"`
		}
		if err := ak.Get(ctx, fmt.Sprintf("/authenticators/admin/all/?user=%d", pk), &devices); err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, d := range devices {
			if strings.EqualFold(d.Type, "authentik_stages_authenticator_webauthn.webauthndevice") {
				out = append(out, fmt.Sprint(d.PK))
			}
		}
		return out
	}
	passkeys := list()
	if len(passkeys) == 0 {
		t.Fatalf("user %d has no passkey to remove", pk)
	}
	for _, d := range passkeys {
		if err := ak.Delete(ctx, "/authenticators/admin/webauthn/"+d+"/"); err != nil {
			t.Fatal(err)
		}
	}
	if left := list(); len(left) != 0 {
		t.Fatalf("user %d still has the passkeys %v", pk, left)
	}
}
