package organization

import (
	"slices"

	"github.com/phischl/paddock-mdm/server/internal/principal"
)

// DenialReason says why ResolveRole denied the portal (plan M8x decision 31); the portal names it on /login-denied.
type DenialReason string

// Denial reasons of ResolveRole.
const (
	DenialNoRole                  DenialReason = "no_role"                   // no Paddock role group
	DenialMultipleOrganizations   DenialReason = "multiple_organizations"    // role groups of several organizations
	DenialMultipleRoles           DenialReason = "multiple_roles"            // several role groups of one organization
	DenialPlatformAndOrganization DenialReason = "platform_and_organization" // platform admins plus an organization role
)

// RoleResolution is the result of mapping the groups claim to a portal role (plan M0 §6.7).
type RoleResolution struct {
	Platform bool
	Slug     string // organization of a granted organization role
	Role     principal.Role
	Denied   bool
	// Slugs are the distinct organizations named by role groups; a denial is recorded in the organization when
	// exactly one of them resolves to an active organization.
	Slugs []string
	// Reason is set when Denied.
	Reason DenialReason
}

// ResolveRole maps Authentik groups to the portal role:
//   - membership of paddock.platform.admins (and no organization role group) → platform admin;
//   - otherwise exactly one group paddock.<slug>.(admins|operators|auditors) → that role in that organization;
//   - zero or several matches, or platform plus organization membership → denied.
func ResolveRole(groups []string) RoleResolution {
	platform := false
	var res RoleResolution
	matches := 0
	var role principal.Role
	seen := map[string]bool{}
	platformAdmins := PlatformAdminsGroup()
	for _, g := range groups {
		// Identity providers may repeat a group (Authentik merges the groups claim of several scopes).
		if seen[g] {
			continue
		}
		seen[g] = true
		if g == platformAdmins {
			platform = true
			continue
		}
		slug, groupRole, ok := ParseRoleGroup(g)
		if !ok {
			continue
		}
		matches++
		switch groupRole {
		case GroupAdmins:
			role = principal.RoleOrgAdmin
		case GroupOperators:
			role = principal.RoleOrgOperator
		default:
			role = principal.RoleOrgAuditor
		}
		if !slices.Contains(res.Slugs, slug) {
			res.Slugs = append(res.Slugs, slug)
		}
	}
	switch {
	case platform && matches == 0:
		res.Platform, res.Role = true, principal.RolePlatform
	case !platform && matches == 1:
		res.Slug, res.Role = res.Slugs[0], role
	default:
		res.Denied = true
		switch {
		case platform && matches > 0:
			res.Reason = DenialPlatformAndOrganization
		case len(res.Slugs) > 1:
			res.Reason = DenialMultipleOrganizations
		case matches > 1:
			res.Reason = DenialMultipleRoles
		default:
			res.Reason = DenialNoRole
		}
	}
	return res
}
