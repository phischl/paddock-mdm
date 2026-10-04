package app

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/paddock-mdm/paddock/pkg/protocol"
	"github.com/paddock-mdm/paddock/server/internal/adapters/postgres/pgstore"
	"github.com/paddock-mdm/paddock/server/internal/domain/audit"
	"github.com/paddock-mdm/paddock/server/internal/domain/enrollment"
	"github.com/paddock-mdm/paddock/server/internal/platform/db"
	"github.com/paddock-mdm/paddock/server/internal/principal"
	"github.com/paddock-mdm/paddock/server/internal/problem"
)

// BundleKeySource returns the public bundle-signing keys devices must trust (bundlesign.PublicKeys).
type BundleKeySource func(ctx context.Context) ([]protocol.BundleKey, error)

// EnrollmentTokens are the enrollment token use cases (plan M2a decision 9).
type EnrollmentTokens struct {
	runner    *ActionRunner
	org       *db.OrgPool
	keys      BundleKeySource
	deviceURL string
	now       func() time.Time
}

// NewEnrollmentTokens creates the use cases. deviceURL is the public device API URL put into enrollment
// configurations, e.g. https://device.example.org.
func NewEnrollmentTokens(runner *ActionRunner, org *db.OrgPool, keys BundleKeySource, deviceURL string) *EnrollmentTokens {
	return &EnrollmentTokens{runner: runner, org: org, keys: keys, deviceURL: deviceURL, now: time.Now}
}

// Specs of the privileged enrollment token actions.
var (
	SpecEnrollmentTokenCreate = ActionSpec{Code: audit.CodeEnrollmentTokenCreated, AllowedRoles: RolesAdmin}
	SpecEnrollmentTokenRevoke = ActionSpec{Code: audit.CodeEnrollmentTokenRevoked, AllowedRoles: RolesAdmin}
)

// List returns one page of enrollment tokens.
func (e *EnrollmentTokens) List(ctx context.Context, page ListPage) (Listed[pgstore.EnrollmentToken], error) {
	var out Listed[pgstore.EnrollmentToken]
	if _, err := RequireOrg(ctx, RolesWrite); err != nil {
		return out, err
	}
	err := e.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		n, err := q.CountEnrollmentTokens(ctx, pgstore.CountEnrollmentTokensParams{QPattern: page.QPattern, CountLimit: countLimit})
		if err != nil {
			return fmt.Errorf("count enrollment tokens: %w", err)
		}
		out.Count = int(n)
		out.Items, err = q.ListEnrollmentTokens(ctx, pgstore.ListEnrollmentTokensParams{
			QPattern: page.QPattern, Sort: page.Sort, SkipRows: page.Offset, MaxRows: page.Limit,
		})
		if err != nil {
			return fmt.Errorf("list enrollment tokens: %w", err)
		}
		return nil
	})
	return out, err
}

// Get returns one enrollment token; missing and foreign tokens are both not_found.
func (e *EnrollmentTokens) Get(ctx context.Context, id uuid.UUID) (pgstore.EnrollmentToken, error) {
	if _, err := RequireOrg(ctx, RolesWrite); err != nil {
		return pgstore.EnrollmentToken{}, err
	}
	var tok pgstore.EnrollmentToken
	err := e.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		var err error
		tok, err = q.GetEnrollmentToken(ctx, id)
		return notFound(err)
	})
	return tok, err
}

// TokenInput are the fields of a new enrollment token.
type TokenInput struct {
	Name          string
	ExpiresAt     time.Time
	MaxUses       int
	DeviceGroupID *uuid.UUID
	AutoApprove   bool
}

// CreatedToken is the result of Create. Secret and Config are shown once and never stored.
type CreatedToken struct {
	Token  pgstore.EnrollmentToken
	Secret string
	Config protocol.EnrollmentConfig
}

// Create creates an enrollment token (audited: enrollment_token.created; the secret is never recorded).
func (e *EnrollmentTokens) Create(ctx context.Context, in TokenInput) (CreatedToken, error) {
	var out CreatedToken
	name := enrollment.NormalizeName(in.Name)
	spec := SpecEnrollmentTokenCreate
	spec.Params = map[string]any{"name": name, "max_uses": in.MaxUses, "auto_approve": in.AutoApprove,
		"expires_at": in.ExpiresAt.UTC().Format(time.RFC3339)}
	if in.DeviceGroupID != nil {
		spec.Params["device_group_id"] = in.DeviceGroupID.String()
	}
	err := e.runner.RunTx(ctx, ScopeOrg, spec, func(ctx context.Context, q *pgstore.Queries, rec Recorder) error {
		if err := enrollment.Validate(name, in.ExpiresAt, in.MaxUses, e.now()); err != nil {
			return problem.InvalidRequest.WithDetail(err.Error())
		}
		if err := requireGroups(ctx, q, optionalID(in.DeviceGroupID)); err != nil {
			return err
		}
		keys, err := e.keys(ctx)
		if err != nil {
			return problem.UpstreamUnavailable.WithDetail("bundle-signing keys are not available")
		}
		secret, hash, err := enrollment.NewSecret()
		if err != nil {
			return err
		}
		p, _ := principal.From(ctx)
		out.Token, err = q.InsertEnrollmentToken(ctx, pgstore.InsertEnrollmentTokenParams{
			ID: uuid.Must(uuid.NewV7()), OrganizationID: p.OrganizationID, Name: name, SecretSha256: hash,
			DeviceGroupID: nullID(in.DeviceGroupID), AutoApprove: in.AutoApprove, MaxUses: int32(in.MaxUses), //nolint:gosec // validated ≤ 1000
			ExpiresAt: in.ExpiresAt, CreatedBy: p.ID,
		})
		if err != nil {
			return err
		}
		rec.SetTarget(audit.Target{Type: "enrollment_token", ID: out.Token.ID.String(), Display: name})
		out.Secret = secret
		out.Config = protocol.EnrollmentConfig{
			ServerURL: e.deviceURL, OrganizationID: p.OrganizationID.String(), Token: secret, BundleKeys: keys,
		}
		return nil
	})
	return out, err
}

// Revoke revokes an enrollment token; revoking a revoked token keeps the first revocation (audited:
// enrollment_token.revoked).
func (e *EnrollmentTokens) Revoke(ctx context.Context, id uuid.UUID) (pgstore.EnrollmentToken, error) {
	var tok pgstore.EnrollmentToken
	spec := SpecEnrollmentTokenRevoke
	spec.Target = &audit.Target{Type: "enrollment_token", ID: id.String()}
	err := e.runner.RunTx(ctx, ScopeOrg, spec, func(ctx context.Context, q *pgstore.Queries, rec Recorder) error {
		var err error
		if tok, err = q.RevokeEnrollmentToken(ctx, id); err != nil {
			return notFound(err)
		}
		rec.SetTarget(audit.Target{Type: "enrollment_token", ID: id.String(), Display: tok.Name})
		rec.SetParam("name", tok.Name)
		return nil
	})
	return tok, err
}

// requireGroups checks that every ID names a device group of the caller's organization (RLS hides the others).
func requireGroups(ctx context.Context, q *pgstore.Queries, ids []uuid.UUID) error {
	for _, id := range ids {
		if _, err := q.GetDeviceGroup(ctx, id); err != nil {
			if db.IsNoRows(err) {
				return problem.InvalidRequest.WithDetail("device group " + id.String() + " does not exist")
			}
			return err
		}
	}
	return nil
}

func optionalID(id *uuid.UUID) []uuid.UUID {
	if id == nil {
		return nil
	}
	return []uuid.UUID{*id}
}

func nullID(id *uuid.UUID) uuid.NullUUID {
	if id == nil {
		return uuid.NullUUID{}
	}
	return uuid.NullUUID{UUID: *id, Valid: true}
}
