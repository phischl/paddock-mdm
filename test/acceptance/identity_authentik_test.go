package acceptance

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/test/acceptance/internal/authflow"
	"github.com/phischl/paddock-mdm/test/acceptance/internal/env"
	"github.com/phischl/paddock-mdm/test/acceptance/internal/stack"
)

// deviceUser is an Authentik user that signs in like Himmelblau: device code, password, TOTP.
type deviceUser struct {
	name, password string
	pk             int
	totp           *authflow.TOTP
}

// newDeviceUser creates an Authentik user with a password in groups and deletes it when the test ends.
func newDeviceUser(t *testing.T, ak *env.Authentik, prefix, domain string, groups ...string) *deviceUser {
	t.Helper()
	ctx := testContext(t, time.Minute)
	pw := make([]byte, 18)
	_, _ = rand.Read(pw)
	u := &deviceUser{name: prefix + "-" + uniqueSuffix() + "@" + domain, password: hex.EncodeToString(pw), totp: &authflow.TOTP{}}
	pk, err := ak.CreateUser(ctx, u.name, u.password, groups...)
	if pk != 0 {
		t.Cleanup(func() { _ = ak.DeleteUser(context.Background(), pk) })
	}
	if err != nil {
		t.Fatal(err)
	}
	u.pk = pk
	return u
}

// deviceLogin runs the device authorization grant for client as u, as Himmelblau does at the greeter, and returns
// the tokens; the error of a refused approval is authflow.ErrAccessDenied.
// deviceLogin approves a new device authorization through its QR code URL and returns the tokens and the stages the
// approval passed.
func deviceLogin(t *testing.T, client string, u *deviceUser) (authflow.Tokens, []string, error) {
	t.Helper()
	ctx := testContext(t, 3*time.Minute)
	hc, err := env.NewHTTPClient()
	if err != nil {
		t.Fatal(err)
	}
	da, err := authflow.StartDevice(ctx, hc, stack.AuthURL(), client)
	if err != nil {
		t.Fatalf("device authorization: %v", err)
	}
	secrets, err := stack.SecretsDir()
	if err != nil {
		t.Fatal(err)
	}
	stages, err := authflow.ApproveDevice(ctx, filepath.Join(secrets, "caddy-root.crt"), da, u.name, u.password, u.totp)
	if err != nil {
		return authflow.Tokens{}, stages, err
	}
	tokens, err := authflow.PollDeviceToken(ctx, hc, stack.AuthURL(), client, da, time.Minute)
	return tokens, stages, err
}

func authHTTP(t *testing.T) *http.Client {
	t.Helper()
	hc, err := env.NewHTTPClient()
	if err != nil {
		t.Fatal(err)
	}
	return hc
}

// TestIdentityAuthentikProvisioning is gate I1 (plan M3a §6): a fresh organization gets its device login provider,
// application, access policy and groups claim mapping; a user without an authenticator approves through the QR code
// URL, has to set up TOTP before the confirmation, refreshes, and the userinfo groups claim lists only the
// organization's paddock.<slug>… groups (no non-Paddock group, no other organization's group); a user of another
// organization is refused by the application.
func TestIdentityAuthentikProvisioning(t *testing.T) {
	root := login(t, env.PlatformAdmin)
	ak, err := env.NewAuthentik()
	if err != nil {
		t.Fatal(err)
	}
	ctx := testContext(t, 5*time.Minute)
	org := newOrg()
	expectStatus(t, call(t, root, http.MethodPost, "/api/platform/v1/organizations", org), http.StatusCreated, "")
	slug := org["slug"]
	client := "paddock-device-" + slug

	var providers struct {
		Results []struct {
			PK                 int      `json:"pk"`
			ClientType         string   `json:"client_type"`
			GrantTypes         []string `json:"grant_types"`
			PropertyMappings   []string `json:"property_mappings"`
			AuthenticationFlow string   `json:"authentication_flow"`
		} `json:"results"`
	}
	if err := ak.Get(ctx, "/providers/oauth2/?name="+client, &providers); err != nil || len(providers.Results) != 1 {
		t.Fatalf("provider %s: %v %+v", client, err, providers)
	}
	p := providers.Results[0]
	if p.ClientType != "public" || len(p.PropertyMappings) != 4 || !slices.Contains(p.GrantTypes, "urn:ietf:params:oauth:grant-type:device_code") ||
		!slices.Contains(p.GrantTypes, "refresh_token") {
		t.Fatalf("provider %+v", p)
	}
	var app struct {
		PK               string `json:"pk"`
		PolicyEngineMode string `json:"policy_engine_mode"`
	}
	if err := ak.Get(ctx, "/core/applications/"+client+"/", &app); err != nil || app.PolicyEngineMode != "all" {
		t.Fatalf("application: %v %+v", err, app)
	}
	var bindings struct {
		Results []struct {
			PolicyObj struct {
				Name string `json:"name"`
			} `json:"policy_obj"`
		} `json:"results"`
	}
	if err := ak.Get(ctx, "/policies/bindings/?target="+app.PK, &bindings); err != nil || len(bindings.Results) != 1 ||
		bindings.Results[0].PolicyObj.Name != client+"-access" {
		t.Fatalf("policy bindings: %v %+v", err, bindings)
	}

	// A member of the organization, also in a non-Paddock group, signs in with device code, password and TOTP.
	unrelated := "i1-unrelated-" + uniqueSuffix()
	if _, err := ak.EnsureGroup(ctx, unrelated); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if pk, _ := ak.GroupPK(context.Background(), unrelated); pk != "" {
			_ = ak.Delete(context.Background(), "/core/groups/"+pk+"/")
		}
	})
	// A group named like another organization's group: the claim must not carry it either.
	foreign := env.RootGroup("globex") + ".g.i1-" + uniqueSuffix()
	if _, err := ak.EnsureGroup(ctx, foreign); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if pk, _ := ak.GroupPK(context.Background(), foreign); pk != "" {
			_ = ak.Delete(context.Background(), "/core/groups/"+pk+"/")
		}
	})
	member := newDeviceUser(t, ak, "i1", slug+".test", env.RootGroup(slug), unrelated, foreign)
	tokens, stages, err := deviceLogin(t, client, member)
	if err != nil {
		t.Fatalf("device login: %v", err)
	}
	// The QR code path runs the Paddock authorization flow, and a user without an authenticator has to set up TOTP
	// there before the device code is confirmed (ADR 0007 amendment).
	setup := slices.Index(stages, "paddock-device-authorization ak-stage-authenticator-totp")
	finish := slices.IndexFunc(stages, func(s string) bool { return strings.HasSuffix(s, " ak-provider-oauth2-device-code-finish") })
	if member.totp.Secret == "" || setup < 0 || finish < 0 || setup > finish {
		t.Fatalf("approval without TOTP setup in the authorization flow before the confirmation: %v", stages)
	}
	refreshed, err := authflow.Refresh(ctx, authHTTP(t), stack.AuthURL(), client, tokens.RefreshToken)
	if err != nil {
		t.Fatalf("refresh grant: %v", err)
	}
	info, err := authflow.UserInfo(ctx, authHTTP(t), stack.AuthURL(), refreshed.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	groups, _ := info["groups"].([]any)
	if !slices.Contains(groups, any(env.RootGroup(slug))) {
		t.Fatalf("groups claim %v lacks %s", groups, env.RootGroup(slug))
	}
	for _, g := range groups {
		name, _ := g.(string)
		if name != env.RootGroup(slug) && !strings.HasPrefix(name, env.RootGroup(slug)+".") {
			t.Fatalf("groups claim leaks %q: %v", name, groups)
		}
	}
	if slices.Contains(groups, any(unrelated)) || slices.Contains(groups, any(foreign)) {
		t.Fatalf("groups claim carries a non-Paddock or another organization's group: %v", groups)
	}

	// A globex user is refused by this organization's application: the approval is denied and no token is issued.
	outsider := newDeviceUser(t, ak, "i1-globex", "globex.test", env.RootGroup("globex"))
	da, err := authflow.StartDevice(ctx, authHTTP(t), stack.AuthURL(), client)
	if err != nil {
		t.Fatal(err)
	}
	secrets, err := stack.SecretsDir()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := authflow.ApproveDevice(ctx, filepath.Join(secrets, "caddy-root.crt"), da, outsider.name,
		outsider.password, outsider.totp); !errors.Is(err, authflow.ErrAccessDenied) {
		t.Fatalf("approval by a globex user: %v, want access denied", err)
	}
	if tok, err := authflow.PollDeviceToken(ctx, authHTTP(t), stack.AuthURL(), client, da, 10*time.Second); err == nil || tok.AccessToken != "" {
		t.Fatal("a user of another organization got tokens of the device application")
	}
}

// TestIdentityLockAuthentik is gate I2 (plan M3a §6): locking a user adds it to paddock.<slug>.locked and deletes its
// refresh tokens and sessions, so the refresh grant with the old token fails; unlocking removes the membership;
// each produces exactly one audit event.
func TestIdentityLockAuthentik(t *testing.T) {
	alice := login(t, env.Alice)
	ak, err := env.NewAuthentik()
	if err != nil {
		t.Fatal(err)
	}
	ctx := testContext(t, 5*time.Minute)
	user := createLocalUser(t, alice, "i2")
	// The local user has no password yet; the test sets one as the recovery link would.
	pw := make([]byte, 18)
	_, _ = rand.Read(pw)
	u := &deviceUser{name: user.Username, password: hex.EncodeToString(pw), totp: &authflow.TOTP{}}
	if err := setAuthentikPassword(ctx, ak, u); err != nil {
		t.Fatal(err)
	}
	tokens, _, err := deviceLogin(t, "paddock-device-acme", u)
	if err != nil {
		t.Fatalf("device login before the lock: %v", err)
	}

	res := call(t, alice, http.MethodPost, "/api/v1/users/"+user.ID+"/lock", nil)
	expectStatus(t, res, http.StatusOK, "")
	expectOneEvent(t, alice, res.RequestID, "user.locked", "success")
	if members, err := ak.GroupMembers(ctx, env.RootGroup("acme")+".locked"); err != nil || !slices.Contains(members, u.name) {
		t.Fatalf("locked group members %v (%v)", members, err)
	}
	var refresh struct {
		Results []any `json:"results"`
	}
	if err := ak.Get(ctx, fmt.Sprintf("/oauth2/refresh_tokens/?user=%d", u.pk), &refresh); err != nil || len(refresh.Results) != 0 {
		t.Fatalf("refresh tokens after the lock: %v %v", refresh.Results, err)
	}
	var sessions struct {
		Results []any `json:"results"`
	}
	if err := ak.Get(ctx, "/core/authenticated_sessions/?user__username="+u.name, &sessions); err != nil || len(sessions.Results) != 0 {
		t.Fatalf("sessions after the lock: %v %v", sessions.Results, err)
	}
	if _, err := authflow.Refresh(ctx, authHTTP(t), stack.AuthURL(), "paddock-device-acme", tokens.RefreshToken); err == nil {
		t.Fatal("the refresh grant with the old token still works after the lock")
	}

	res = call(t, alice, http.MethodPost, "/api/v1/users/"+user.ID+"/unlock", nil)
	expectStatus(t, res, http.StatusOK, "")
	expectOneEvent(t, alice, res.RequestID, "user.unlocked", "success")
	if members, err := ak.GroupMembers(ctx, env.RootGroup("acme")+".locked"); err != nil || slices.Contains(members, u.name) {
		t.Fatalf("locked group members after the unlock %v (%v)", members, err)
	}
}

// createdUser is a local user created through the admin API.
type createdUser struct {
	ID       string `json:"id"`
	Username string `json:"username"`
}

// createLocalUser creates a local acme user through the admin API and deletes it when the test ends.
func createLocalUser(t *testing.T, p *env.Portal, prefix string) createdUser {
	t.Helper()
	username := prefix + "-" + uniqueSuffix() + "@acme.test"
	res := call(t, p, http.MethodPost, "/api/v1/users", map[string]string{"username": username, "display_name": prefix + " gate user"})
	expectStatus(t, res, http.StatusCreated, "")
	var out struct {
		User         createdUser `json:"user"`
		RecoveryLink string      `json:"recovery_link"`
	}
	if err := res.JSON(&out); err != nil {
		t.Fatal(err)
	}
	deleteOnCleanup(t, p, "/api/v1/users/"+out.User.ID)
	if !strings.Contains(out.RecoveryLink, "/if/flow/paddock-recovery/") {
		t.Fatalf("recovery link %q", out.RecoveryLink)
	}
	return out.User
}

// setAuthentikPassword sets a user's password with the admin API and records its pk.
func setAuthentikPassword(ctx context.Context, ak *env.Authentik, u *deviceUser) error {
	pk, err := ak.UserPK(ctx, u.name)
	if err != nil {
		return err
	}
	u.pk = pk
	return ak.SetPassword(ctx, pk, u.password)
}
