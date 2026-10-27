package organization

import (
	"reflect"
	"testing"

	"github.com/phischl/paddock-mdm/server/internal/principal"
)

var (
	acme          = RootGroup("acme")
	acmeAdmins    = RoleGroup("acme", GroupAdmins)
	acmeOperators = RoleGroup("acme", GroupOperators)
	acmeAuditors  = RoleGroup("acme", GroupAuditors)
	globexAdmins  = RoleGroup("globex", GroupAdmins)
	platformAdmin = PlatformAdminsGroup()
)

func TestResolveRole(t *testing.T) {
	cases := []struct {
		name   string
		groups []string
		want   RoleResolution
	}{
		{"no groups", nil, RoleResolution{Denied: true, Reason: DenialNoRole}},
		{"only root group", []string{acme}, RoleResolution{Denied: true, Reason: DenialNoRole}},
		{"unrelated groups", []string{"authentik Admins", "staff"}, RoleResolution{Denied: true, Reason: DenialNoRole}},
		{"org admin", []string{acme, acmeAdmins}, RoleResolution{Slug: "acme", Role: principal.RoleOrgAdmin, Slugs: []string{"acme"}}},
		{"duplicated group", []string{acmeAdmins, acme, acmeAdmins}, RoleResolution{Slug: "acme", Role: principal.RoleOrgAdmin, Slugs: []string{"acme"}}},
		{"org operator", []string{acmeOperators}, RoleResolution{Slug: "acme", Role: principal.RoleOrgOperator, Slugs: []string{"acme"}}},
		{"org auditor", []string{acmeAuditors}, RoleResolution{Slug: "acme", Role: principal.RoleOrgAuditor, Slugs: []string{"acme"}}},
		{"platform admin", []string{platformAdmin}, RoleResolution{Platform: true, Role: principal.RolePlatform}},
		{"two roles in one organization", []string{acmeAdmins, acmeAuditors}, RoleResolution{Denied: true, Slugs: []string{"acme"}, Reason: DenialMultipleRoles}},
		{"three roles in one organization", []string{acmeAdmins, acmeOperators, acmeAuditors}, RoleResolution{Denied: true, Slugs: []string{"acme"}, Reason: DenialMultipleRoles}},
		{"two roles in one organization plus another organization", []string{acmeAdmins, acmeAuditors, globexAdmins}, RoleResolution{Denied: true, Slugs: []string{"acme", "globex"}, Reason: DenialMultipleOrganizations}},
		{"two organizations", []string{acmeAdmins, globexAdmins}, RoleResolution{Denied: true, Slugs: []string{"acme", "globex"}, Reason: DenialMultipleOrganizations}},
		{"platform plus organization", []string{platformAdmin, acmeAdmins}, RoleResolution{Platform: true, Slug: "acme", Role: principal.RoleOrgAdmin, Slugs: []string{"acme"}, Choices: []RoleChoice{ChoicePlatform, ChoiceOrganization}}},
		{"organization plus platform", []string{acmeOperators, platformAdmin}, RoleResolution{Platform: true, Slug: "acme", Role: principal.RoleOrgOperator, Slugs: []string{"acme"}, Choices: []RoleChoice{ChoicePlatform, ChoiceOrganization}}},
		{"platform plus two organizations", []string{platformAdmin, acmeAdmins, globexAdmins}, RoleResolution{Denied: true, Slugs: []string{"acme", "globex"}, Reason: DenialMultipleOrganizations}},
		{"platform plus two roles in one organization", []string{platformAdmin, acmeAdmins, acmeAuditors}, RoleResolution{Denied: true, Slugs: []string{"acme"}, Reason: DenialMultipleRoles}},
		{"slug too short", []string{"paddock.ab.admins"}, RoleResolution{Denied: true, Reason: DenialNoRole}},
		{"slug with uppercase", []string{"paddock.Acme.admins"}, RoleResolution{Denied: true, Reason: DenialNoRole}},
		{"unknown role suffix", []string{"paddock.acme.owners"}, RoleResolution{Denied: true, Reason: DenialNoRole}},
		{"suffix injection", []string{"paddock.acme.admins.x", "xpaddock.acme.admins"}, RoleResolution{Denied: true, Reason: DenialNoRole}},
		{"platform slug as org", []string{"paddock.platform.auditors"}, RoleResolution{Denied: true, Reason: DenialNoRole}},
		{"colon-separated names are ignored", []string{"paddock:acme:admins", "paddock:platform:admins"}, RoleResolution{Denied: true, Reason: DenialNoRole}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := ResolveRole(c.groups); !reflect.DeepEqual(got, c.want) {
				t.Fatalf("ResolveRole(%v) = %+v, want %+v", c.groups, got, c.want)
			}
		})
	}
}

func TestRoleResolutionActive(t *testing.T) {
	twoRoles := ResolveRole([]string{platformAdmin, acmeAdmins})
	orgOnly := ResolveRole([]string{acmeAdmins})
	platformOnly := ResolveRole([]string{platformAdmin})
	denied := ResolveRole([]string{platformAdmin, acmeAdmins, globexAdmins})
	cases := []struct {
		name   string
		res    RoleResolution
		choice RoleChoice
		want   RoleResolution
		ok     bool
	}{
		{"two roles, platform", twoRoles, ChoicePlatform, RoleResolution{Platform: true, Role: principal.RolePlatform, Slugs: []string{"acme"}}, true},
		{"two roles, organization", twoRoles, ChoiceOrganization, RoleResolution{Slug: "acme", Role: principal.RoleOrgAdmin, Slugs: []string{"acme"}}, true},
		{"two roles, no choice", twoRoles, "", RoleResolution{}, false},
		{"two roles, unknown choice", twoRoles, "both", RoleResolution{}, false},
		{"organization, no choice", orgOnly, "", orgOnly, true},
		{"organization, organization", orgOnly, ChoiceOrganization, orgOnly, true},
		{"organization, platform", orgOnly, ChoicePlatform, RoleResolution{}, false},
		{"platform, no choice", platformOnly, "", platformOnly, true},
		{"platform, platform", platformOnly, ChoicePlatform, platformOnly, true},
		{"platform, organization", platformOnly, ChoiceOrganization, RoleResolution{}, false},
		{"denied, no choice", denied, "", RoleResolution{}, false},
		{"denied, platform", denied, ChoicePlatform, RoleResolution{}, false},
		{"denied, organization", denied, ChoiceOrganization, RoleResolution{}, false},
		{"no role, no choice", ResolveRole(nil), "", RoleResolution{}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, ok := c.res.Active(c.choice)
			if ok != c.ok {
				t.Fatalf("Active(%q) ok = %v, want %v", c.choice, ok, c.ok)
			}
			if ok && !reflect.DeepEqual(got, c.want) {
				t.Fatalf("Active(%q) = %+v, want %+v", c.choice, got, c.want)
			}
		})
	}
}

func TestRoleResolutionAlternate(t *testing.T) {
	twoRoles := ResolveRole([]string{platformAdmin, acmeAdmins})
	cases := []struct {
		name     string
		res      RoleResolution
		active   RoleChoice
		wantRole principal.Role
		wantSlug string
	}{
		{"two roles from organization", twoRoles, ChoiceOrganization, principal.RolePlatform, ""},
		{"two roles from platform", twoRoles, ChoicePlatform, principal.RoleOrgAdmin, "acme"},
		{"organization only", ResolveRole([]string{acmeAdmins}), ChoiceOrganization, "", ""},
		{"organization only, no choice", ResolveRole([]string{acmeAdmins}), "", "", ""},
		{"platform only", ResolveRole([]string{platformAdmin}), ChoicePlatform, "", ""},
		{"denied", ResolveRole([]string{platformAdmin, acmeAdmins, globexAdmins}), ChoiceOrganization, "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			role, slug := c.res.Alternate(c.active)
			if role != c.wantRole || slug != c.wantSlug {
				t.Fatalf("Alternate(%q) = (%q, %q), want (%q, %q)", c.active, role, slug, c.wantRole, c.wantSlug)
			}
		})
	}
}
