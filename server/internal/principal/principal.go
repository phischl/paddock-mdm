// Package principal describes the authenticated caller of a request or background job.
package principal

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// Kind is the kind of principal.
type Kind string

const (
	KindAdmin         Kind = "admin"          // organization administrator (portal)
	KindPlatformAdmin Kind = "platform_admin" // platform administrator (portal)
	KindSystem        Kind = "system"         // background roles
)

// Role is the portal role of an administrator.
type Role string

const (
	RoleOrgAdmin    Role = "org_admin"
	RoleOrgOperator Role = "org_operator"
	RoleOrgAuditor  Role = "org_auditor"
	RolePlatform    Role = "platform_admin"
)

// Principal is the authenticated caller. The organization is only ever taken from here, never from a request.
type Principal struct {
	Kind           Kind
	ID             uuid.UUID // admin_account.id or platform_admin.id; uuid.Nil for system
	Subject        string    // Authentik sub; "" for system
	Display        string
	Role           Role      // "" for system
	OrganizationID uuid.UUID // uuid.Nil for platform admins and system
	IP             string
	// StepUpAt is the time of the last step-up authentication of the session (zero: none, plan M4a decision 6) and
	// StepUpJTI the jti of its ID token, under which the api keeps the token for the escrow-reader (plan M4b.1).
	StepUpAt  time.Time
	StepUpJTI string
	// APITokenID and APITokenName are set when the request authenticated with an API token (plan M6c decision 7).
	// The token acts in its organization with Role; ID is the creating administrator's account ID.
	APITokenID   uuid.UUID
	APITokenName string
}

type ctxKey struct{}

// With returns a copy of ctx carrying p.
func With(ctx context.Context, p Principal) context.Context {
	return context.WithValue(ctx, ctxKey{}, p)
}

// From returns the principal stored in ctx.
func From(ctx context.Context) (Principal, bool) {
	p, ok := ctx.Value(ctxKey{}).(Principal)
	return p, ok
}
