package acceptance

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/test/acceptance/internal/authflow"
	"github.com/phischl/paddock-mdm/test/acceptance/internal/env"
	"github.com/phischl/paddock-mdm/test/acceptance/internal/stack"
)

// platformOrg is the platform pseudo-organization of the audit log.
var platformOrg = uuid.Nil

// TestLoginGate is gate A4 (plan M0 §8, AC6): only members of exactly one Paddock admin group get a session;
// every rejected login is audited as admin.login denied; platform and organization scopes are separated.
func TestLoginGate(t *testing.T) {
	idx := auditIndex(t)

	t.Run("user without a Paddock admin group is denied", func(t *testing.T) {
		// Member of the organization's root group only: Authentik admits the user to the application, Paddock
		// finds no admin role.
		user, pw := tempUser(t, "member", env.RootGroup("acme"))
		p, err := loginAs(t, user, pw)
		if !errors.Is(err, authflow.ErrDenied) || p == nil || p.Final != "/login-denied?reason=no_role" {
			t.Fatalf("login = %v (final %q), want /login-denied?reason=no_role", err, finalOf(p))
		}
		expectNoSession(t, p)
		ev := expectOneIndexEvent(t, idx, platformOrg, "correlation_id = $1", p.LoginRequestID, "admin.login", "denied", auditPollTimeout)
		if ev.ActorDisplay != user || ev.Params["denial_reason"] != "no_role" {
			t.Fatalf("denied login recorded for %q with denial_reason %v, want %q and no_role", ev.ActorDisplay,
				ev.Params["denial_reason"], user)
		}
	})

	t.Run("user without any Paddock group is stopped by Authentik", func(t *testing.T) {
		user, pw := tempUser(t, "outsider")
		p, err := loginAs(t, user, pw)
		if err == nil {
			t.Fatalf("login succeeded (final %q)", finalOf(p))
		}
		expectNoSession(t, p)
	})

	t.Run("user in admin groups of two organizations is denied", func(t *testing.T) {
		user, pw := tempUser(t, "twoorgs", env.RoleGroup("acme", "admins"), env.RoleGroup("globex", "admins"))
		p, err := loginAs(t, user, pw)
		if !errors.Is(err, authflow.ErrDenied) || p == nil || p.Final != "/login-denied?reason=multiple_organizations" {
			t.Fatalf("login = %v (final %q), want /login-denied?reason=multiple_organizations", err, finalOf(p))
		}
		expectNoSession(t, p)
		ev := expectOneIndexEvent(t, idx, platformOrg, "correlation_id = $1", p.LoginRequestID, "admin.login", "denied", auditPollTimeout)
		if ev.Params["denial_reason"] != "multiple_organizations" {
			t.Fatalf("denial_reason %v, want multiple_organizations", ev.Params["denial_reason"])
		}
		// The platform role does not make an ambiguous organization part acceptable (ADR 0045 decision 1).
		user, pw = tempUser(t, "twoorgsplat", "paddock.platform.admins", env.RoleGroup("acme", "admins"), env.RoleGroup("globex", "admins"))
		p, err = loginAs(t, user, pw)
		if !errors.Is(err, authflow.ErrDenied) || p == nil || p.Final != "/login-denied?reason=multiple_organizations" {
			t.Fatalf("login with the platform role = %v (final %q), want /login-denied?reason=multiple_organizations", err, finalOf(p))
		}
		expectNoSession(t, p)
		ev = expectOneIndexEvent(t, idx, platformOrg, "correlation_id = $1", p.LoginRequestID, "admin.login", "denied", auditPollTimeout)
		if ev.Params["denial_reason"] != "multiple_organizations" {
			t.Fatalf("denial_reason %v, want multiple_organizations", ev.Params["denial_reason"])
		}
	})

	t.Run("user with two roles in one organization is denied", func(t *testing.T) {
		user, pw := tempUser(t, "tworoles", env.RoleGroup("acme", "admins"), env.RoleGroup("acme", "auditors"))
		p, err := loginAs(t, user, pw)
		if !errors.Is(err, authflow.ErrDenied) || p == nil || p.Final != "/login-denied?reason=multiple_roles" {
			t.Fatalf("login = %v (final %q), want /login-denied?reason=multiple_roles", err, finalOf(p))
		}
		expectNoSession(t, p)
		// Exactly one named organization resolves: the denial is recorded in acme.
		acme := orgOf(t, login(t, env.Alice))
		ev := expectOneIndexEvent(t, idx, acme, "correlation_id = $1", p.LoginRequestID, "admin.login",
			"denied", auditPollTimeout)
		if ev.Params["denial_reason"] != "multiple_roles" {
			t.Fatalf("denial_reason %v, want multiple_roles", ev.Params["denial_reason"])
		}
		// The platform role does not make an ambiguous organization part acceptable (ADR 0045 decision 1).
		user, pw = tempUser(t, "tworolesplat", "paddock.platform.admins", env.RoleGroup("acme", "admins"), env.RoleGroup("acme", "auditors"))
		p, err = loginAs(t, user, pw)
		if !errors.Is(err, authflow.ErrDenied) || p == nil || p.Final != "/login-denied?reason=multiple_roles" {
			t.Fatalf("login with the platform role = %v (final %q), want /login-denied?reason=multiple_roles", err, finalOf(p))
		}
		expectNoSession(t, p)
		ev = expectOneIndexEvent(t, idx, acme, "correlation_id = $1", p.LoginRequestID, "admin.login", "denied", auditPollTimeout)
		if ev.Params["denial_reason"] != "multiple_roles" {
			t.Fatalf("denial_reason %v, want multiple_roles", ev.Params["denial_reason"])
		}
	})

	t.Run("platform admin with an organization role signs in to the organization and switches", func(t *testing.T) {
		testRoleSwitch(t, idx)
	})

	t.Run("platform admin has no organization data", func(t *testing.T) {
		root := login(t, env.PlatformAdmin)
		res := call(t, root, http.MethodGet, "/api/v1/device-groups", nil)
		expectStatus(t, res, http.StatusForbidden, "no_organization")
		res = call(t, root, http.MethodGet, "/api/v1/audit-events", nil)
		expectStatus(t, res, http.StatusForbidden, "no_organization")
	})

	t.Run("organization admin has no platform access", func(t *testing.T) {
		alice := login(t, env.Alice)
		res := call(t, alice, http.MethodGet, "/api/platform/v1/organizations", nil)
		expectStatus(t, res, http.StatusForbidden, "forbidden")
	})
}

// TestLoginMFAPath (plan M8x decision 7d): the portal sign-in sends no prompt, so that Authentik never skips the flow of a
// later step-up (an existing Authentik session may satisfy the sign-in, the callback still requires MFA in amr), and
// Authentik's default authentication flow asks for a second factor at order 31, enrolling one when missing.
func TestLoginMFAPath(t *testing.T) {
	ctx := testContext(t, time.Minute)
	client, err := env.NewHTTPClient()
	if err != nil {
		t.Fatal(err)
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, stack.AdminURL()+"/api/auth/login", nil)
	if err != nil {
		t.Fatal(err)
	}
	res, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	if loc, err := url.Parse(res.Header.Get("Location")); res.StatusCode != http.StatusFound || err != nil ||
		loc.Query().Has("prompt") {
		t.Fatalf("GET /api/auth/login: %d %q", res.StatusCode, res.Header.Get("Location"))
	}

	ak, err := env.NewAuthentik()
	if err != nil {
		t.Fatal(err)
	}
	var flows struct {
		Results []struct {
			PK string `json:"pk"`
		} `json:"results"`
	}
	if err := ak.Get(ctx, "/flows/instances/?slug=default-authentication-flow", &flows); err != nil || len(flows.Results) != 1 {
		t.Fatalf("flow default-authentication-flow: %+v %v", flows, err)
	}
	var bindings struct {
		Results []struct {
			Order      int    `json:"order"`
			Stage      string `json:"stage"`
			PolicyPK   string `json:"policybindingmodel_ptr_id"`
			EngineMode string `json:"policy_engine_mode"`
		} `json:"results"`
	}
	if err := ak.Get(ctx, "/flows/bindings/?target="+flows.Results[0].PK, &bindings); err != nil {
		t.Fatal(err)
	}
	stage, policyPK := "", ""
	for _, b := range bindings.Results {
		if b.Order == 31 {
			stage, policyPK = b.Stage, b.PolicyPK
			if b.EngineMode != "all" {
				t.Errorf("order 31 evaluates its policies in mode %q, want all", b.EngineMode)
			}
		}
	}
	if stage == "" {
		t.Fatalf("no stage binding at order 31: %+v", bindings.Results)
	}
	// The stage is skipped only after a WebAuthn or TOTP validation at order 30 in the same sign-in (PDK-324); the
	// development blueprint skips it entirely.
	var pb struct {
		Results []struct {
			PolicyObj struct {
				Name string `json:"name"`
			} `json:"policy_obj"`
		} `json:"results"`
	}
	if err := ak.Get(ctx, "/policies/bindings/?target="+policyPK, &pb); err != nil {
		t.Fatal(err)
	}
	var policies []string
	for _, p := range pb.Results {
		policies = append(policies, p.PolicyObj.Name)
	}
	slices.Sort(policies)
	if fmt.Sprint(policies) != "[paddock-default-login-mfa-missing paddock-dev-skip-mfa]" {
		t.Errorf("order 31 policies %v, want the authenticator-missing policy and the development skip", policies)
	}
	var v struct {
		Name                string `json:"name"`
		NotConfiguredAction string `json:"not_configured_action"`
	}
	if err := ak.Get(ctx, "/stages/authenticator/validate/"+stage+"/", &v); err != nil {
		t.Fatal(err)
	}
	if v.Name != "paddock-default-login-mfa" || v.NotConfiguredAction != "configure" {
		t.Fatalf("order 31 stage %+v, want paddock-default-login-mfa with not_configured_action configure", v)
	}
}

// switchMe is the part of GET /api/v1/me the role switch gate reads (ADR 0045).
type switchMe struct {
	Role         string `json:"role"`
	Organization *struct {
		ID   string `json:"id"`
		Slug string `json:"slug"`
	} `json:"organization"`
	AlternateRole *struct {
		Role             string `json:"role"`
		OrganizationSlug string `json:"organization_slug"`
	} `json:"alternate_role"`
	StepUpValidUntil *time.Time `json:"step_up_valid_until"`
}

func switchWhoami(t *testing.T, p *env.Portal) switchMe {
	t.Helper()
	res := call(t, p, http.MethodGet, "/api/v1/me", nil)
	expectStatus(t, res, http.StatusOK, "")
	var m switchMe
	if err := res.JSON(&m); err != nil {
		t.Fatal(err)
	}
	return m
}

// switchRole runs POST /api/auth/switch and follows the authorization URL through Authentik back into the portal; it
// returns the callback's request ID, the correlation ID of the new session's admin.login.
func switchRole(t *testing.T, u *mfaUser, role string) string {
	t.Helper()
	res := call(t, u.Portal, http.MethodPost, "/api/auth/switch", map[string]string{"role": role})
	expectStatus(t, res, http.StatusOK, "")
	var body struct {
		AuthorizeURL string `json:"authorize_url"`
	}
	if err := res.JSON(&body); err != nil || body.AuthorizeURL == "" {
		t.Fatalf("switch answer %s: %v", res.Body, err)
	}
	fin, err := authflow.Follow(testContext(t, 3*time.Minute), u.Client, stack.AdminURL(), body.AuthorizeURL, u.username, u.password, u.totp)
	if err != nil || fin.Final != "/" {
		t.Fatalf("switch to %s: %v (final %q)", role, err, finalOfResult(fin))
	}
	return fin.CallbackRequestID
}

func finalOfResult(r *authflow.Result) string {
	if r == nil {
		return ""
	}
	return r.Final
}

// testRoleSwitch is the two-role case of gate A4 (ADR 0045): the sign-in lands in the organization role, the switch is
// a new sign-in that ends the previous session and is recorded once with previous_role, in the scope it enters.
// The temporary user gets a TOTP authenticator (mfaTempUser), which the step-up flow requires.
func testRoleSwitch(t *testing.T, idx *env.AuditIndex) {
	u := mfaTempUser(t, "platorg", "paddock.platform.admins", env.RoleGroup("acme", "admins"))
	acme := orgOf(t, u.Portal)
	m := switchWhoami(t, u.Portal)
	if m.Role != "org_admin" || m.Organization == nil || m.AlternateRole == nil || m.AlternateRole.Role != "platform_admin" ||
		m.AlternateRole.OrganizationSlug != "" {
		t.Fatalf("after sign-in: %+v alternate %+v", m, m.AlternateRole)
	}
	acmeSlug := m.Organization.Slug
	expectStatus(t, call(t, u.Portal, http.MethodGet, "/api/platform/v1/organizations", nil), http.StatusForbidden, "forbidden")
	u.stepUp(t)
	if m := switchWhoami(t, u.Portal); m.StepUpValidUntil == nil {
		t.Fatal("step_up_valid_until is null after the step-up")
	}
	old := cookieCopy(t, u.Portal)

	callback := switchRole(t, u, "platform")
	m = switchWhoami(t, u.Portal)
	if m.Role != "platform_admin" || m.Organization != nil || m.AlternateRole == nil || m.AlternateRole.Role != "org_admin" ||
		m.AlternateRole.OrganizationSlug != acmeSlug || m.StepUpValidUntil != nil {
		t.Fatalf("after the switch: %+v alternate %+v", m, m.AlternateRole)
	}
	expectStatus(t, call(t, u.Portal, http.MethodGet, "/api/v1/device-groups", nil), http.StatusForbidden, "no_organization")
	expectStatus(t, call(t, old, http.MethodGet, "/api/v1/me", nil), http.StatusUnauthorized, "unauthenticated")
	ev := expectOneIndexEvent(t, idx, platformOrg, "correlation_id = $1", callback, "admin.login", "success", auditPollTimeout)
	if ev.Params["previous_role"] != "org_admin" || ev.Params["role"] != "platform_admin" {
		t.Fatalf("switch event params %v, want role platform_admin and previous_role org_admin", ev.Params)
	}

	callback = switchRole(t, u, "organization")
	m = switchWhoami(t, u.Portal)
	if m.Role != "org_admin" || m.Organization == nil || m.Organization.ID != acme.String() || m.AlternateRole == nil ||
		m.AlternateRole.Role != "platform_admin" {
		t.Fatalf("after the switch back: %+v alternate %+v", m, m.AlternateRole)
	}
	ev = expectOneIndexEvent(t, idx, acme, "correlation_id = $1", callback, "admin.login", "success", auditPollTimeout)
	if ev.Params["previous_role"] != "platform_admin" {
		t.Fatalf("switch back event params %v, want previous_role platform_admin", ev.Params)
	}
	// A switch ends the previous session as a logout does, not as a revocation.
	ctx := testContext(t, time.Minute)
	for _, org := range []uuid.UUID{acme, platformOrg} {
		events, err := idx.Events(ctx, org, "code = 'admin.sessions_revoked' AND target->>'display' = $1", u.username)
		if err != nil {
			t.Fatal(err)
		}
		if len(events) != 0 {
			t.Fatalf("admin.sessions_revoked of %s in %s: %+v", u.username, org, events)
		}
	}
}

func finalOf(p *env.Portal) string {
	if p == nil {
		return ""
	}
	return p.Final
}

// expectNoSession checks that a rejected login left no usable portal session behind.
func expectNoSession(t *testing.T, p *env.Portal) {
	t.Helper()
	if p == nil {
		return
	}
	res, err := p.Do(testContext(t, time.Minute), http.MethodGet, "/api/v1/me", nil)
	if err != nil {
		t.Fatal(err)
	}
	expectStatus(t, res, http.StatusUnauthorized, "unauthenticated")
}
