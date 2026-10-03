package app

import (
	"context"
	"slices"

	"github.com/google/uuid"

	"github.com/paddock-mdm/paddock/server/internal/principal"
	"github.com/paddock-mdm/paddock/server/internal/problem"
)

// Roles allowed on organization endpoints (architecture §9.6).
var (
	RolesRead     = []principal.Role{principal.RoleOrgAdmin, principal.RoleOrgOperator, principal.RoleOrgAuditor}
	RolesWrite    = []principal.Role{principal.RoleOrgAdmin, principal.RoleOrgOperator}
	RolesAdmin    = []principal.Role{principal.RoleOrgAdmin}
	RolesAudit    = []principal.Role{principal.RoleOrgAdmin, principal.RoleOrgAuditor}
	RolesPlatform = []principal.Role{principal.RolePlatform}
)

// RequireOrg checks a read on organization data: authenticated, member of an organization, role allowed.
func RequireOrg(ctx context.Context, roles []principal.Role) (principal.Principal, error) {
	p, ok := principal.From(ctx)
	switch {
	case !ok:
		return p, problem.Unauthenticated
	case p.OrganizationID == uuid.Nil:
		return p, problem.NoOrganization
	case !slices.Contains(roles, p.Role):
		return p, problem.Forbidden
	}
	return p, nil
}

// RequirePlatform checks a read on platform data.
func RequirePlatform(ctx context.Context) (principal.Principal, error) {
	p, ok := principal.From(ctx)
	switch {
	case !ok:
		return p, problem.Unauthenticated
	case p.Kind != principal.KindPlatformAdmin:
		return p, problem.Forbidden
	}
	return p, nil
}

// ListMaxRows bounds every list (ADR 0018): page × page_size may not exceed it and totals are counted up to it.
const ListMaxRows = 10000

// countLimit makes the capped count see one row more than ListMaxRows, so "more than 10 000" is detectable.
const countLimit = ListMaxRows + 1

// ListPage selects one page of a collection. The transport validates it against the endpoint's allow list
// (package listing); the use cases pass it to the static list queries unchanged.
type ListPage struct {
	Sort     string  // allow-listed sort value; "-" prefix = descending
	QPattern *string // escaped ILIKE pattern "%…%"; nil without search
	Offset   int32
	Limit    int32
}

// Listed is one page of rows and the number of matching rows, counted up to ListMaxRows+1.
type Listed[T any] struct {
	Items []T
	Count int
}
