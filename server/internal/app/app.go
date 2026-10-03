package app

import (
	"context"
	"encoding/base64"
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

// Page bounds (plan M0 §6.6).
const (
	DefaultLimit = 50
	MaxLimit     = 200
)

// PageLimit validates limit (nil = default).
func PageLimit(limit *int) (int32, error) {
	if limit == nil {
		return DefaultLimit, nil
	}
	if *limit < 1 || *limit > MaxLimit {
		return 0, problem.InvalidRequest.WithDetail("limit must be between 1 and 200")
	}
	return int32(*limit), nil //nolint:gosec // bounded above
}

// EncodeCursor turns the last ID of a page into an opaque cursor (base64url of the UUIDv7).
func EncodeCursor(id uuid.UUID) string { return base64.RawURLEncoding.EncodeToString(id[:]) }

// DecodeCursor parses a cursor; nil means "first page".
func DecodeCursor(cursor *string) (uuid.NullUUID, error) {
	if cursor == nil || *cursor == "" {
		return uuid.NullUUID{}, nil
	}
	b, err := base64.RawURLEncoding.DecodeString(*cursor)
	if err != nil || len(b) != 16 {
		return uuid.NullUUID{}, problem.InvalidRequest.WithDetail("invalid cursor")
	}
	id, err := uuid.FromBytes(b)
	if err != nil {
		return uuid.NullUUID{}, problem.InvalidRequest.WithDetail("invalid cursor")
	}
	return uuid.NullUUID{UUID: id, Valid: true}, nil
}
