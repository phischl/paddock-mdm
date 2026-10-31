package acceptance

import (
	"crypto/rand"
	"encoding/base32"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
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

// mfaUser is an Authentik user with a TOTP authenticator, signed in to the portal.
type mfaUser struct {
	*env.Portal
	username, password string
	totp               *authflow.TOTP
}

// stepUp completes a step-up of the session, or renews it unless it has at least 10 s of its window left.
func (u *mfaUser) stepUp(t *testing.T) {
	t.Helper()
	if s := serverStepUp(t, u.Portal); s.At != nil && time.Until(s.At.Add(s.Window)) > 10*time.Second {
		return
	}
	res, err := authflow.StepUp(testContext(t, 3*time.Minute), u.Client, stack.AdminURL(), "/settings", u.username, u.password, u.totp, false)
	if err != nil || strings.Contains(res.Final, "stepup=failed") {
		t.Fatalf("step-up of %s: %v", u.username, err)
	}
}

// steppedUpTempUser creates an Authentik user in groups with a TOTP authenticator, signs it in and completes a
// step-up. The step-up flow denies users without an authenticator (not_configured_action: deny), so the gate installs
// one the way `make dev-seed` does for the dev users; the key travels on stdin.
func steppedUpTempUser(t *testing.T, prefix string, groups ...string) *mfaUser {
	t.Helper()
	u := mfaTempUser(t, prefix, groups...)
	u.stepUp(t)
	return u
}

// mfaTempUser is steppedUpTempUser without the step-up.
func mfaTempUser(t *testing.T, prefix string, groups ...string) *mfaUser {
	t.Helper()
	user, password := tempUser(t, prefix, groups...)
	totp := installTOTPs(t, 3*time.Minute, user)[0]
	p, err := loginAs(t, user, password)
	if err != nil {
		t.Fatalf("login %s: %v", user, err)
	}
	return &mfaUser{Portal: p, username: user, password: password, totp: totp}
}

// akShellSlots bounds the `ak shell` processes the gates run at once. Each one boots a full Django process in
// authentik-worker (about 4.5 CPU seconds), and parallel cases starting them together take the CPU that Authentik's
// web workers need on a 4-vCPU runner (PDK-603).
var akShellSlots = make(chan struct{}, 2)

// installTOTPs installs a TOTP authenticator for each user in one `ak shell`, the way `make dev-seed` does for the dev
// users (the keys travel on stdin), and returns the users' generators in the same order. budget is the shell's own
// timeout; the wait for a slot does not count against it.
func installTOTPs(t *testing.T, budget time.Duration, users ...string) []*authflow.TOTP {
	t.Helper()
	script := "from authentik.core.models import User\n" +
		"from authentik.stages.authenticator_totp.models import TOTPDevice\n"
	totps := make([]*authflow.TOTP, len(users))
	for i, user := range users {
		key := make([]byte, 20)
		if _, err := rand.Read(key); err != nil {
			t.Fatal(err)
		}
		script += fmt.Sprintf("TOTPDevice.objects.update_or_create(user=User.objects.get(username=%q), name=\"paddock-acceptance\", "+
			"defaults={\"key\": %q, \"confirmed\": True})\n", user, hex.EncodeToString(key))
		totps[i] = &authflow.TOTP{Secret: base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(key)}
	}
	script += "print(\"paddock-acceptance totp ok\")\n"
	akShellSlots <- struct{}{}
	defer func() { <-akShellSlots }()
	out, err := stack.ComposeInput(testContext(t, budget), strings.NewReader(script), "exec", "-T", "authentik-worker", "ak", "shell")
	if err != nil || !strings.Contains(out, "paddock-acceptance totp ok") {
		t.Fatalf("install TOTP authenticators of %v: %v: %s", users, err, out)
	}
	return totps
}

// adminPool is a pool of temporary administrators with TOTP authenticators of their own, made known to env so the
// helpers for dev users serve them. The A3 cases that need a stepped-up acme administrator take one in turn instead of
// alice: a user's TOTP generator hands out one code per 30 s step, and the 33 step-ups and device logins of alice in
// one A3 run on CI queued for it for 16 minutes, past the 3-minute budget of a device login (PDK-603).
type adminPool struct {
	users []string
	next  atomic.Uint64
}

// newAdminPool creates n users in groups with one `ak shell` for all their authenticators; they are deleted when t
// ends.
func newAdminPool(t *testing.T, prefix string, n int, groups ...string) *adminPool {
	t.Helper()
	users, passwords := make([]string, n), make([]string, n)
	for i := range users {
		users[i], passwords[i] = tempUser(t, prefix, groups...)
	}
	for i, totp := range installTOTPs(t, 3*time.Minute, users...) {
		env.AddUser(users[i], passwords[i], totp)
	}
	return &adminPool{users: users}
}

// take returns the next user of the pool. Parallel cases may get the same one: each signs in on a session of its own,
// and the user's TOTP generator never hands out a code twice.
func (p *adminPool) take() string {
	return p.users[(p.next.Add(1)-1)%uint64(len(p.users))]
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
		operator := steppedUpTempUser(t, "t1-operator", env.RoleGroup("acme", "operators"))
		res := postAPIToken(t, operator.Portal, apiTokenName("operator admin"), "org_admin", 2*time.Hour)
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
		removeCreated(t, alice, "/api/v1/api-tokens", res)
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
