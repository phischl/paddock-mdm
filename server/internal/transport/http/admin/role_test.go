package admin

import (
	"reflect"
	"testing"

	"github.com/paddock-mdm/paddock/server/internal/domain/organization"
	"github.com/paddock-mdm/paddock/server/internal/principal"
)

var (
	acme          = organization.RootGroup("acme")
	acmeAdmins    = organization.RoleGroup("acme", organization.GroupAdmins)
	acmeOperators = organization.RoleGroup("acme", organization.GroupOperators)
	acmeAuditors  = organization.RoleGroup("acme", organization.GroupAuditors)
	globexAdmins  = organization.RoleGroup("globex", organization.GroupAdmins)
	platformAdmin = organization.PlatformAdminsGroup()
)

func TestResolveRole(t *testing.T) {
	cases := []struct {
		name   string
		groups []string
		want   RoleResolution
	}{
		{"no groups", nil, RoleResolution{Denied: true}},
		{"only root group", []string{acme}, RoleResolution{Denied: true}},
		{"unrelated groups", []string{"authentik Admins", "staff"}, RoleResolution{Denied: true}},
		{"org admin", []string{acme, acmeAdmins}, RoleResolution{Slug: "acme", Role: principal.RoleOrgAdmin, Slugs: []string{"acme"}}},
		{"duplicated group", []string{acmeAdmins, acme, acmeAdmins}, RoleResolution{Slug: "acme", Role: principal.RoleOrgAdmin, Slugs: []string{"acme"}}},
		{"org operator", []string{acmeOperators}, RoleResolution{Slug: "acme", Role: principal.RoleOrgOperator, Slugs: []string{"acme"}}},
		{"org auditor", []string{acmeAuditors}, RoleResolution{Slug: "acme", Role: principal.RoleOrgAuditor, Slugs: []string{"acme"}}},
		{"platform admin", []string{platformAdmin}, RoleResolution{Platform: true, Role: principal.RolePlatform}},
		{"two roles in one org", []string{acmeAdmins, acmeAuditors}, RoleResolution{Denied: true, Slugs: []string{"acme"}}},
		{"two organizations", []string{acmeAdmins, globexAdmins}, RoleResolution{Denied: true, Slugs: []string{"acme", "globex"}}},
		{"platform plus organization", []string{platformAdmin, acmeAdmins}, RoleResolution{Denied: true, Slugs: []string{"acme"}}},
		{"slug too short", []string{"paddock.ab.admins"}, RoleResolution{Denied: true}},
		{"slug with uppercase", []string{"paddock.Acme.admins"}, RoleResolution{Denied: true}},
		{"unknown role suffix", []string{"paddock.acme.owners"}, RoleResolution{Denied: true}},
		{"suffix injection", []string{"paddock.acme.admins.x", "xpaddock.acme.admins"}, RoleResolution{Denied: true}},
		{"platform slug as org", []string{"paddock.platform.auditors"}, RoleResolution{Denied: true}},
		{"colon-separated names are ignored", []string{"paddock:acme:admins", "paddock:platform:admins"}, RoleResolution{Denied: true}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := ResolveRole(c.groups); !reflect.DeepEqual(got, c.want) {
				t.Fatalf("ResolveRole(%v) = %+v, want %+v", c.groups, got, c.want)
			}
		})
	}
}
