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
		{"platform plus organization", []string{platformAdmin, acmeAdmins}, RoleResolution{Denied: true, Slugs: []string{"acme"}, Reason: DenialPlatformAndOrganization}},
		{"platform plus two organizations", []string{platformAdmin, acmeAdmins, globexAdmins}, RoleResolution{Denied: true, Slugs: []string{"acme", "globex"}, Reason: DenialPlatformAndOrganization}},
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
