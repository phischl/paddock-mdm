package compiler

import (
	"testing"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/pkg/bundle"
	"github.com/phischl/paddock-mdm/pkg/policy"
	"github.com/phischl/paddock-mdm/server/internal/domain/loginsettings"
	"github.com/phischl/paddock-mdm/server/internal/domain/organization"
	"github.com/phischl/paddock-mdm/server/internal/domain/user"
	"github.com/phischl/paddock-mdm/server/internal/domain/usergroup"
)

// TestLoginSpecContract is the shared table of the login rules (plan M12h decision 14): a login spec the compiler
// renders from values the server accepts passes policy.ValidateLoginSpec, which the agent runs before it writes
// himmelblau.conf, and a value the server refuses also fails it. The two sides must never drift apart.
func TestLoginSpecContract(t *testing.T) {
	device := uuid.MustParse("0f8fad5b-d9cb-469f-a165-70867728950e")
	spec := func(slug, domain, group, username, account string) bundle.LoginSpec {
		client := organization.DeviceLoginApp(slug)
		return bundle.LoginSpec{
			Provider: bundle.ProviderHimmelblau,
			Himmelblau: bundle.HimmelblauSpec{
				OIDCIssuerURL: "https://auth.example.org/application/o/" + client + "/", AppID: client, Domain: domain,
				PamAllowGroups: []string{organization.RootGroup(slug), organization.LocalUserGroup(slug, group),
					organization.SyncedUserGroup(slug, group), organization.DeviceLoginGroup(slug, device)},
			},
			LockedUsers:        []string{username},
			BreakGlassAccounts: []string{account},
			LocalAdmin:         &bundle.LocalAdminSpec{Username: account, RotationDays: 30},
		}
	}
	const slug, domain, group, username, account = "acme", "acme.example.org", "dev-team", "alice@acme.example.org", "rescue"
	cases := []struct {
		name                                   string
		slug, domain, group, username, account string
		serverAccepts                          bool
	}{
		{"valid", slug, domain, group, username, account, true},
		{"shortest slugs", "abc", "a.io", "ab", "a@a.io", "a", true},
		{"longest org slug", "a234567890123456789012345678901b", domain, group, username, account, true},
		{"org slug too long", "a2345678901234567890123456789012b", domain, group, username, account, false},
		{"org slug too short", "ab", domain, group, username, account, false},
		{"org slug uppercase", "Acme", domain, group, username, account, false},
		{"org slug trailing dash", "acme-", domain, group, username, account, false},
		{"org slug with dot", "ac.me", domain, group, username, account, false},
		{"domain uppercase", slug, "Acme.example.org", group, username, account, false},
		{"domain single label", slug, "acme", group, username, account, false},
		{"domain numeric tld", slug, "acme.123", group, username, account, false},
		{"group slug too short", slug, domain, "a", username, account, false},
		{"group slug uppercase", slug, domain, "Dev", username, account, false},
		{"group slug with dot", slug, domain, "dev.team", username, account, false},
		{"longest group slug", slug, domain, "a2345678901234567890123456789012345678901b", username, account, true},
		{"group slug too long", slug, domain, "a23456789012345678901234567890123456789012b", username, account, false},
		{"account uppercase", slug, domain, group, username, "Rescue", false},
		{"account leading dash", slug, domain, group, username, "-rescue", false},
		{"local username with plus", slug, domain, group, "a.b+c@acme.example.org", account, true},
	}
	for _, c := range cases {
		server := organization.ValidateSlug(c.slug) == nil && organization.ValidateDomains([]string{c.domain}) == nil &&
			usergroup.ValidateSlug(c.group) == nil && user.ValidateLocalUsername(c.username, []string{c.domain}) == nil &&
			validAccount(c.account)
		if server != c.serverAccepts {
			t.Fatalf("%s: server accepts %v, table says %v", c.name, server, c.serverAccepts)
		}
		err := policy.ValidateLoginSpec(spec(c.slug, c.domain, c.group, c.username, c.account))
		if (err == nil) != server {
			t.Errorf("%s: server accepts %v, policy.ValidateLoginSpec: %v", c.name, server, err)
		}
	}
}

// validAccount applies the server's rule for break-glass and local administrator accounts.
func validAccount(name string) bool {
	s := loginsettings.Settings{HelloPinMinLength: 6, BootPinMinLength: 8, UserLockSessionAction: bundle.SessionActionLockScreen,
		BreakGlassAccounts: []string{name}, SudoLectureText: "x", LocalAdminUsername: name, LocalAdminRotationDays: 30}
	return loginsettings.Validate(s) == nil
}
