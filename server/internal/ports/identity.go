// Package ports declares the interfaces the application needs from external systems.
package ports

import "context"

// OrgIdentityRefs are the Authentik primary keys of an organization's groups.
type OrgIdentityRefs struct{ RootGroupPK, AdminsGroupPK, OperatorsGroupPK, AuditorsGroupPK string }

// IdentityProvider manages the identity objects of organizations (Authentik, ADR 0007).
type IdentityProvider interface {
	// EnsureOrganization creates the four groups if missing; idempotent; returns their Authentik pks.
	EnsureOrganization(ctx context.Context, slug string) (OrgIdentityRefs, error)
}
