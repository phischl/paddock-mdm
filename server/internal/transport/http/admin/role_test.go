package admin

import (
	"reflect"
	"testing"

	"github.com/paddock-mdm/paddock/server/internal/principal"
)

func TestResolveRole(t *testing.T) {
	cases := []struct {
		name   string
		groups []string
		want   RoleResolution
	}{
		{"no groups", nil, RoleResolution{Denied: true}},
		{"only root group", []string{"paddock:acme"}, RoleResolution{Denied: true}},
		{"unrelated groups", []string{"authentik Admins", "staff"}, RoleResolution{Denied: true}},
		{"org admin", []string{"paddock:acme", "paddock:acme:admins"}, RoleResolution{Slug: "acme", Role: principal.RoleOrgAdmin, Slugs: []string{"acme"}}},
		{"duplicated group", []string{"paddock:acme:admins", "paddock:acme", "paddock:acme:admins"}, RoleResolution{Slug: "acme", Role: principal.RoleOrgAdmin, Slugs: []string{"acme"}}},
		{"org operator", []string{"paddock:acme:operators"}, RoleResolution{Slug: "acme", Role: principal.RoleOrgOperator, Slugs: []string{"acme"}}},
		{"org auditor", []string{"paddock:acme:auditors"}, RoleResolution{Slug: "acme", Role: principal.RoleOrgAuditor, Slugs: []string{"acme"}}},
		{"platform admin", []string{"paddock:platform:admins"}, RoleResolution{Platform: true, Role: principal.RolePlatform}},
		{"two roles in one org", []string{"paddock:acme:admins", "paddock:acme:auditors"}, RoleResolution{Denied: true, Slugs: []string{"acme"}}},
		{"two organizations", []string{"paddock:acme:admins", "paddock:globex:admins"}, RoleResolution{Denied: true, Slugs: []string{"acme", "globex"}}},
		{"platform plus organization", []string{"paddock:platform:admins", "paddock:acme:admins"}, RoleResolution{Denied: true, Slugs: []string{"acme"}}},
		{"slug too short", []string{"paddock:ab:admins"}, RoleResolution{Denied: true}},
		{"slug with uppercase", []string{"paddock:Acme:admins"}, RoleResolution{Denied: true}},
		{"unknown role suffix", []string{"paddock:acme:owners"}, RoleResolution{Denied: true}},
		{"suffix injection", []string{"paddock:acme:admins:x", "xpaddock:acme:admins"}, RoleResolution{Denied: true}},
		{"platform slug as org", []string{"paddock:platform:auditors"}, RoleResolution{Denied: true}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := ResolveRole(c.groups); !reflect.DeepEqual(got, c.want) {
				t.Fatalf("ResolveRole(%v) = %+v, want %+v", c.groups, got, c.want)
			}
		})
	}
}
