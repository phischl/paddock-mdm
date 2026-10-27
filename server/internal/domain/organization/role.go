package organization

import (
	"slices"

	"github.com/phischl/paddock-mdm/server/internal/principal"
)

// DenialReason says why ResolveRole denied the portal (plan M8x decision 31); the portal names it on /login-denied.
type DenialReason string

// RoleChoice names the role an identity with the platform role and an organization role acts in (ADR 0045).
type RoleChoice string

// Role choices of a two-role identity (ADR 0045).
const (
	ChoicePlatform     RoleChoice = "platform"
	ChoiceOrganization RoleChoice = "organization"
)

// Denial reasons of ResolveRole.
const (
	DenialNoRole                DenialReason = "no_role"                // no Paddock role group
	DenialMultipleOrganizations DenialReason = "multiple_organizations" // role groups of several organizations
	DenialMultipleRoles         DenialReason = "multiple_roles"         // several role groups of one organization
	// DenialRoleNotGranted: the caller asked for a RoleChoice the groups do not grant (switch, MCP login).
	DenialRoleNotGranted DenialReason = "role_not_granted"
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
	// Choices is set for an identity in paddock.platform.admins and exactly one organization role group:
	// [ChoicePlatform, ChoiceOrganization]. Platform is then true and Slug and Role name the organization role.
	// A resolution with Choices MUST be narrowed with Active before it is used.
	Choices []RoleChoice
}

// Active narrows the resolution to one role. A denied resolution is never active. A single-role resolution is
// active for c == "" and for the choice that names its role (ChoicePlatform for a platform resolution,
// ChoiceOrganization for an organization resolution). A two-role resolution is active for either of its Choices
// and never for c == "". The result has no Choices; Slugs is kept.
func (r RoleResolution) Active(c RoleChoice) (RoleResolution, bool) {
	if r.Denied {
		return RoleResolution{}, false
	}
	if len(r.Choices) > 0 {
		switch c {
		case ChoicePlatform:
			return RoleResolution{Platform: true, Role: principal.RolePlatform, Slugs: r.Slugs}, true
		case ChoiceOrganization:
			return RoleResolution{Slug: r.Slug, Role: r.Role, Slugs: r.Slugs}, true
		default:
			return RoleResolution{}, false
		}
	}
	switch c {
	case "":
		return r, true
	case ChoicePlatform:
		return r, r.Platform
	case ChoiceOrganization:
		return r, !r.Platform && r.Slug != ""
	default:
		return RoleResolution{}, false
	}
}

// Alternate returns the role and organization slug an identity may switch to from active (a resolution narrowed
// with Active): ("platform_admin", "") from an organization session, (<organization role>, <slug>) from a platform
// session, ("", "") for a single-role identity.
func (r RoleResolution) Alternate(active RoleChoice) (role principal.Role, slug string) {
	if r.Denied || len(r.Choices) == 0 {
		return "", ""
	}
	switch active {
	case ChoiceOrganization:
		return principal.RolePlatform, ""
	case ChoicePlatform:
		return r.Role, r.Slug
	default:
		return "", ""
	}
}

// ResolveRole maps Authentik groups to the portal role:
//   - membership of paddock.platform.admins (and no organization role group) → platform admin;
//   - exactly one group paddock.<slug>.(admins|operators|auditors) → that role in that organization, and with
//     paddock.platform.admins in addition both roles (Choices, ADR 0045);
//   - zero or several organization role groups → denied, also for a platform administrator.
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
	case matches == 1:
		res.Slug, res.Role = res.Slugs[0], role
		if platform {
			res.Platform = true
			res.Choices = []RoleChoice{ChoicePlatform, ChoiceOrganization}
		}
	default:
		res.Denied = true
		switch {
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
