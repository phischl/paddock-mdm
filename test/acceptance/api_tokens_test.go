package acceptance

import (
	"crypto/rand"
	"encoding/base32"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/test/acceptance/internal/authflow"
	"github.com/phischl/paddock-mdm/test/acceptance/internal/env"
	"github.com/phischl/paddock-mdm/test/acceptance/internal/stack"
)

// createAPIToken creates a token as p with a fresh step-up of user and revokes it when the test ends.
func createAPIToken(t *testing.T, p *env.Portal, user, role string) apiTokenCreated {
	t.Helper()
	freshStepUp(t, p, user)
	res := postAPIToken(t, p, apiTokenName("acceptance"), role, 2*time.Hour)
	expectStatus(t, res, http.StatusCreated, "")
	var created apiTokenCreated
	if err := res.JSON(&created); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = p.Do(testContext(t, time.Minute), http.MethodPost, "/api/v1/api-tokens/"+created.Token.ID+"/revoke", nil)
	})
	return created
}

// steppedUpTempUser creates an Authentik user in groups with a TOTP authenticator, signs it in and completes a
// step-up. The step-up flow denies users without an authenticator (not_configured_action: deny), so the gate installs
// one the way `make dev-seed` does for the dev users; the key travels on stdin.
func steppedUpTempUser(t *testing.T, prefix string, groups ...string) (*env.Portal, string) {
	t.Helper()
	user, password := tempUser(t, prefix, groups...)
	key := make([]byte, 20)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	script := "from authentik.core.models import User\n" +
		"from authentik.stages.authenticator_totp.models import TOTPDevice\n" +
		fmt.Sprintf("TOTPDevice.objects.update_or_create(user=User.objects.get(username=%q), name=\"paddock-acceptance\", "+
			"defaults={\"key\": %q, \"confirmed\": True})\n", user, hex.EncodeToString(key)) +
		"print(\"paddock-acceptance totp ok\")\n"
	ctx := testContext(t, 3*time.Minute)
	out, err := stack.ComposeInput(ctx, strings.NewReader(script), "exec", "-T", "authentik-worker", "ak", "shell")
	if err != nil || !strings.Contains(out, "paddock-acceptance totp ok") {
		t.Fatalf("install TOTP authenticator of %s: %v: %s", user, err, out)
	}
	p, err := loginAs(t, user, password)
	if err != nil {
		t.Fatalf("login %s: %v", user, err)
	}
	totp := &authflow.TOTP{Secret: base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(key)}
	res, err := authflow.StepUp(ctx, p.Client, stack.AdminURL(), "/settings", user, password, totp, false)
	if err != nil || strings.Contains(res.Final, "stepup=failed") {
		t.Fatalf("step-up of %s: %v", user, err)
	}
	return p, user
}

// TestAPITokens is gate T1 of plan M6c: token creation needs a fresh step-up and is audited without the secret, the
// role ceiling and the expiry window hold, a token cannot create tokens, its actions are attributed to it, and a
// revoked token is refused with exactly one api_token.use_denied event.
func TestAPITokens(t *testing.T) {
	alice := login(t, env.Alice)
	acme := orgOf(t, alice)

	t.Run("creation needs a step-up", func(t *testing.T) {
		fresh := login(t, env.Alice)
		res := postAPIToken(t, fresh, apiTokenName("no step-up"), "org_auditor", 2*time.Hour)
		expectStatus(t, res, http.StatusForbidden, "step_up_required")
		expectOneEvent(t, alice, res.RequestID, "api_token.created", "denied")
	})

	stepUp(t, alice, env.Alice, true)
	name := apiTokenName("t1 admin")
	res := postAPIToken(t, alice, name, "org_admin", 2*time.Hour)
	expectStatus(t, res, http.StatusCreated, "")
	var created apiTokenCreated
	if err := res.JSON(&created); err != nil {
		t.Fatal(err)
	}
	if len(created.Secret) != 47 || !strings.HasPrefix(created.Secret, "pdk_") || created.Token.Prefix != created.Secret[:12] {
		t.Fatalf("secret of %d characters, prefix %q", len(created.Secret), created.Token.Prefix)
	}
	ev := expectOneEvent(t, alice, res.RequestID, "api_token.created", "success")
	if !ev.Actor.StepUp || ev.Params["name"] != name || ev.Params["role"] != "org_admin" {
		t.Fatalf("api_token.created event %+v", ev)
	}
	for k, v := range ev.Params {
		if s, ok := v.(string); ok && strings.Contains(s, created.Secret[12:]) {
			t.Fatalf("audit param %s carries the secret", k)
		}
	}
	get := call(t, alice, http.MethodGet, "/api/v1/api-tokens/"+created.Token.ID, nil)
	expectStatus(t, get, http.StatusOK, "")
	if strings.Contains(string(get.Body), created.Secret) || strings.Contains(string(get.Body), "\"secret\"") {
		t.Fatalf("GET returns the secret: %s", get.Body)
	}

	token := tokenPortal(t, created.Secret)
	me := call(t, token, http.MethodGet, "/api/v1/me", nil)
	expectStatus(t, me, http.StatusOK, "")
	var m struct {
		Role         string `json:"role"`
		Organization struct {
			ID   string `json:"id"`
			Slug string `json:"slug"`
		} `json:"organization"`
		APIToken *struct {
			Name string `json:"name"`
		} `json:"api_token"`
	}
	if err := me.JSON(&m); err != nil {
		t.Fatal(err)
	}
	if m.APIToken == nil || m.APIToken.Name != name || m.Role != "org_admin" || m.Organization.Slug != "acme" || m.Organization.ID != acme.String() {
		t.Fatalf("GET /api/v1/me with the token: %s", me.Body)
	}

	t.Run("a token cannot create tokens", func(t *testing.T) {
		res := postAPIToken(t, token, apiTokenName("by token"), "org_auditor", 2*time.Hour)
		expectStatus(t, res, http.StatusForbidden, "step_up_required")
		ev := expectOneEvent(t, alice, res.RequestID, "api_token.created", "denied")
		if ev.Actor.Type != "api_token" || ev.Actor.Display != name {
			t.Fatalf("actor %+v", ev.Actor)
		}
	})

	t.Run("operator above its role", func(t *testing.T) {
		operator, _ := steppedUpTempUser(t, "t1-operator", env.RoleGroup("acme", "operators"))
		res := postAPIToken(t, operator, apiTokenName("operator admin"), "org_admin", 2*time.Hour)
		expectStatus(t, res, http.StatusForbidden, "forbidden")
		expectOneEvent(t, alice, res.RequestID, "api_token.created", "denied")
	})

	t.Run("an auditor token is refused writes and attributed", func(t *testing.T) {
		auditor := tokenPortal(t, createAPIToken(t, alice, env.Alice, "org_auditor").Secret)
		res := call(t, auditor, http.MethodPost, "/api/v1/device-groups", map[string]string{"name": uniqueName("t1 auditor token")})
		expectStatus(t, res, http.StatusForbidden, "forbidden")
		ev := expectOneEvent(t, alice, res.RequestID, "device_group.created", "denied")
		if ev.Actor.Type != "api_token" {
			t.Fatalf("actor %+v, want api_token", ev.Actor)
		}
	})

	t.Run("expiry window", func(t *testing.T) {
		freshStepUp(t, alice, env.Alice)
		res := postAPIToken(t, alice, apiTokenName("thirty minutes"), "org_auditor", 30*time.Minute)
		expectStatus(t, res, http.StatusBadRequest, "invalid_request")
		freshStepUp(t, alice, env.Alice)
		// One hour plus a margin for the request's travel: the server compares with its own clock.
		res = postAPIToken(t, alice, apiTokenName("one hour"), "org_auditor", time.Hour+time.Minute)
		expectStatus(t, res, http.StatusCreated, "")
		_ = call(t, alice, http.MethodPost, "/api/v1/api-tokens/"+responseID(t, res).String()+"/revoke", nil)
	})

	t.Run("revocation", func(t *testing.T) {
		res := call(t, alice, http.MethodPost, "/api/v1/api-tokens/"+created.Token.ID+"/revoke", nil)
		expectStatus(t, res, http.StatusOK, "")
		expectOneEvent(t, alice, res.RequestID, "api_token.revoked", "success")
		res = call(t, alice, http.MethodPost, "/api/v1/api-tokens/"+created.Token.ID+"/revoke", nil)
		expectStatus(t, res, http.StatusConflict, "invalid_state")
		res = call(t, token, http.MethodGet, "/api/v1/device-groups", nil)
		expectStatus(t, res, http.StatusUnauthorized, "unauthenticated")
		ev := expectOneEvent(t, alice, res.RequestID, "api_token.use_denied", "denied")
		if ev.Params["reason"] != "revoked" || ev.Params["name"] != name || ev.Actor.Type != "anonymous" {
			t.Fatalf("api_token.use_denied event %+v", ev)
		}
	})
}
