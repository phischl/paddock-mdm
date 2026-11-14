package admin_test

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/domain/organization"
	"github.com/phischl/paddock-mdm/server/internal/ports"
	"github.com/phischl/paddock-mdm/server/internal/transport/http/admin"
)

// passkeyLookup is an identity provider with the authenticators of accounts by username.
type passkeyLookup struct {
	accounts map[string]ports.Authenticators
	fail     error
}

func (p *passkeyLookup) UserMembership(_ context.Context, username, uid string) (ports.IdentityUser, []string, bool, error) {
	if p.fail != nil {
		return ports.IdentityUser{}, nil, false, p.fail
	}
	if _, ok := p.accounts[username]; !ok {
		return ports.IdentityUser{}, nil, false, nil
	}
	return ports.IdentityUser{PK: "pk-" + username, Username: username, UID: uid}, nil, true, nil
}

func (p *passkeyLookup) UserAuthenticators(_ context.Context, pks []string) (map[string]ports.Authenticators, error) {
	out := map[string]ports.Authenticators{}
	for username, a := range p.accounts {
		for _, pk := range pks {
			if pk == "pk-"+username {
				out[pk] = a
			}
		}
	}
	return out, nil
}

// TestLoginWithoutPasskeyNamesTheEnrolment (ADR 0053 amendment c point 3): a sign-in refused for its factors whose
// account has no passkey is refused with mfa_enrolment_required, audited as a denied admin.login with that reason and
// no session, since signing in again cannot help such an account. An account with a passkey, a failed or empty lookup
// and an identity without a portal role keep their factor reason.
func TestLoginWithoutPasskeyNamesTheEnrolment(t *testing.T) {
	lookup := &passkeyLookup{accounts: map[string]ports.Authenticators{}}
	w := newLoginWorld(t, func(d *admin.Deps) { d.Passkeys = lookup })
	ctx := context.Background()
	login := func(t *testing.T, claims map[string]any, want string) string {
		t.Helper()
		username := claims["preferred_username"].(string)
		before := len(w.e.sessions.records)
		res := w.login(ctx, claims)
		if res.Code != http.StatusFound || res.Header().Get("Location") != "/login-denied?reason="+want {
			t.Fatalf("login: %d %s, want reason %s", res.Code, res.Header().Get("Location"), want)
		}
		if cookieOf(res, admin.SessionCookie) != nil || len(w.e.sessions.records) != before {
			t.Fatal("a refused sign-in opened a session")
		}
		return username
	}
	account := func(a *ports.Authenticators) string {
		username := "enrol-" + uuid.NewString() + "@acme.test"
		if a != nil {
			lookup.accounts[username] = *a
		}
		return username
	}
	for role, group := range map[string]string{
		"platform administrator": organization.PlatformAdminsGroup(),
		"organization admin":     organization.RoleGroup(w.slug, organization.GroupAdmins),
		"operator":               organization.RoleGroup(w.slug, organization.GroupOperators),
	} {
		t.Run(role+"/TOTP only", func(t *testing.T) {
			claims := w.adminClaims(account(&ports.Authenticators{TOTP: true}), []string{"pwd", "mfa"})
			claims["groups"], claims["paddock_mfa_classes"] = []string{group}, []string{totpClass}
			username := login(t, claims, "mfa_enrolment_required")
			if n, outcome, errCode, reason, _ := w.loginEvents(username); n != 1 || outcome != "denied" ||
				errCode != "mfa_enrolment_required" || reason != "mfa_enrolment_required" {
				t.Fatalf("audit: %d events, outcome %q, error code %q, reason %q", n, outcome, errCode, reason)
			}
		})
		t.Run(role+"/no second factor", func(t *testing.T) {
			claims := w.adminClaims(account(&ports.Authenticators{}), []string{"pwd"})
			claims["groups"] = []string{group}
			login(t, claims, "mfa_enrolment_required")
		})
		t.Run(role+"/account with a passkey", func(t *testing.T) {
			claims := w.adminClaims(account(&ports.Authenticators{WebAuthn: true, TOTP: true}), []string{"pwd", "mfa"})
			claims["groups"], claims["paddock_mfa_classes"] = []string{group}, []string{totpClass}
			login(t, claims, "passkey_required")
		})
	}
	t.Run("account not found", func(t *testing.T) {
		claims := w.adminClaims(account(nil), []string{"pwd", "mfa"})
		claims["paddock_mfa_classes"] = []string{totpClass}
		login(t, claims, "passkey_required")
	})
	t.Run("lookup failed", func(t *testing.T) {
		lookup.fail = errors.New("authentik down")
		defer func() { lookup.fail = nil }()
		claims := w.adminClaims(account(&ports.Authenticators{}), []string{"pwd", "mfa"})
		claims["paddock_mfa_classes"] = []string{totpClass}
		login(t, claims, "passkey_required")
	})
	t.Run("no portal role", func(t *testing.T) {
		claims := w.adminClaims(account(&ports.Authenticators{}), []string{"pwd"})
		claims["groups"] = []string{"staff"}
		login(t, claims, "mfa_required")
	})
}
