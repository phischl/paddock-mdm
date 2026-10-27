package app

import (
	"testing"

	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/domain/organization"
	"github.com/phischl/paddock-mdm/server/internal/principal"
)

// TestChangeIgnoresThePlatformGroup pins that the organization round judges an organization account by its
// organization's groups only: the platform group neither keeps nor changes its role (ADR 0045 decision 8).
func TestChangeIgnoresThePlatformGroup(t *testing.T) {
	acmeAdmins := organization.RoleGroup("acme", organization.GroupAdmins)
	acmeOperators := organization.RoleGroup("acme", organization.GroupOperators)
	platformAdmins := organization.PlatformAdminsGroup()
	cases := []struct {
		name       string
		user       *directoryUser
		wantReason string
		wantRole   principal.Role
	}{
		{"same role plus platform", &directoryUser{groups: []string{acmeAdmins, platformAdmins}, active: true}, "", ""},
		{"other role plus platform", &directoryUser{groups: []string{acmeOperators, platformAdmins}, active: true}, RevokeReasonRoleChanged, principal.RoleOrgOperator},
		{"platform only", &directoryUser{groups: []string{platformAdmins}, active: true}, RevokeReasonRemoved, ""},
		{"same role", &directoryUser{groups: []string{acmeAdmins}, active: true}, "", ""},
		{"deactivated with both roles", &directoryUser{groups: []string{acmeAdmins, platformAdmins}}, RevokeReasonDeactivated, ""},
		{"not in the directory", nil, RevokeReasonRemoved, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			reason, role := change(pgstore.AdminAccount{Role: string(principal.RoleOrgAdmin)}, c.user)
			if reason != c.wantReason || role != c.wantRole {
				t.Fatalf("change = (%q, %q), want (%q, %q)", reason, role, c.wantReason, c.wantRole)
			}
		})
	}
}
