package app

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
	"github.com/phischl/paddock-mdm/server/internal/domain/statechange"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/principal"
)

// Admin are the restore commands of paddock-server admin (plan M6c decisions 20–22). They run on the host with the
// worker's database roles, never through the admin API.
type Admin struct {
	runner *ActionRunner
	org    *db.OrgPool
}

// NewAdmin creates the use cases.
func NewAdmin(runner *ActionRunner, org *db.OrgPool) *Admin {
	return &Admin{runner: runner, org: org}
}

// Runner is the action runner the restore commands record with, shared by the break-glass commands of the IP
// allow list (plan M7a decision 21).
func (a *Admin) Runner() *ActionRunner { return a.runner }

// adminActor is the actor of every restore command.
var adminActor = audit.Actor{Type: audit.ActorSystem, Display: "paddock-server admin"}

// Specs of the restore commands.
var (
	SpecBundleSeqBump      = ActionSpec{Code: audit.CodePlatformBundleSeqBumped, Actor: &adminActor}
	SpecRecompileRequested = ActionSpec{Code: audit.CodeOrganizationRecompileRequested, Actor: &adminActor}
	SpecCacheRebuilt       = ActionSpec{Code: audit.CodePlatformCacheRebuilt, Actor: &adminActor}
	// SpecSecurityReviewRequired records the start of the review of existing data (ADR 0034 decision 7).
	SpecSecurityReviewRequired = ActionSpec{Code: audit.CodeOrganizationSecurityReviewRequired, Actor: &adminActor}
)

// Bounds of BumpBundleSeq.
const (
	MinBundleSeqBump = 1
	MaxBundleSeqBump = 1_000_000_000
)

// ErrBumpOutOfRange is returned for a bump outside [MinBundleSeqBump, MaxBundleSeqBump].
var ErrBumpOutOfRange = errors.New("--by must be between 1 and 1000000000")

func system(ctx context.Context, org uuid.UUID) context.Context {
	return principal.With(ctx, principal.Principal{Kind: principal.KindSystem, Display: adminActor.Display, OrganizationID: org})
}

// BumpBundleSeq raises the bundle sequence of every device by by (audited: platform.bundle_seq_bumped) and returns
// the number of devices.
func (a *Admin) BumpBundleSeq(ctx context.Context, by int64) (int64, error) {
	if by < MinBundleSeqBump || by > MaxBundleSeqBump {
		return 0, ErrBumpOutOfRange
	}
	var devices int64
	spec := SpecBundleSeqBump
	spec.Params = map[string]any{"by": by}
	err := a.runner.RunTx(system(ctx, uuid.Nil), ScopePlatform, spec, func(ctx context.Context, q *pgstore.Queries, rec Recorder) error {
		var err error
		if devices, err = q.BumpBundleSeq(ctx, by); err != nil {
			return err
		}
		rec.SetParam("devices", devices)
		return nil
	})
	return devices, err
}

// RecompileAll requests a forced recompile of every organization (audited once per organization:
// organization.recompile_requested) and returns the number of organizations.
func (a *Admin) RecompileAll(ctx context.Context) (int, error) {
	orgs, err := a.org.OrganizationIDs(system(ctx, uuid.Nil))
	if err != nil {
		return 0, fmt.Errorf("list organizations: %w", err)
	}
	var errs []error
	for _, org := range orgs {
		spec := SpecRecompileRequested
		spec.Target = &audit.Target{Type: "organization", ID: org.String()}
		spec.Params = map[string]any{"organizations_total": len(orgs)}
		err := a.runner.RunTx(system(ctx, org), ScopeOrg, spec, func(_ context.Context, _ *pgstore.Queries, rec Recorder) error {
			rec.ForcedStateChanged(statechange.ScopeOrg, org)
			return nil
		})
		if err != nil {
			errs = append(errs, fmt.Errorf("organization %s: %w", org, err))
		}
	}
	return len(orgs), errors.Join(errs...)
}

// OrganizationReview is the outcome of the security review of one organization.
type OrganizationReview struct {
	Slug   string
	Counts SecurityReviewCounts
}

// SecurityReviewAll computes the security review of every organization and records
// organization.security_review_required in every organization where a count is above zero (plan M8s decision 28).
// A second run records again.
func (a *Admin) SecurityReviewAll(ctx context.Context) ([]OrganizationReview, error) {
	orgs, err := a.org.OrganizationIDs(system(ctx, uuid.Nil))
	if err != nil {
		return nil, fmt.Errorf("list organizations: %w", err)
	}
	var out []OrganizationReview
	var errs []error
	for _, org := range orgs {
		var r OrganizationReview
		err := a.org.InOrg(system(ctx, org), func(ctx context.Context, q *pgstore.Queries) error {
			o, err := q.GetOrganization(ctx, org)
			if err != nil {
				return fmt.Errorf("organization: %w", err)
			}
			review, err := securityReviewIn(ctx, q, time.Now())
			r = OrganizationReview{Slug: o.Slug, Counts: review.Counts()}
			return err
		})
		if err == nil && r.Counts != (SecurityReviewCounts{}) {
			spec := SpecSecurityReviewRequired
			spec.Target = &audit.Target{Type: "organization", ID: org.String(), Display: r.Slug}
			spec.Params = map[string]any{
				"root_grant_profiles": r.Counts.RootGrants, "sensitive_files": r.Counts.SensitiveFiles, "denied_files": r.Counts.DeniedFiles,
			}
			err = a.runner.RunTx(system(ctx, org), ScopeOrg, spec, func(context.Context, *pgstore.Queries, Recorder) error { return nil })
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("organization %s: %w", org, err))
			continue
		}
		out = append(out, r)
	}
	return out, errors.Join(errs...)
}

// RebuildCache runs rebuild, which rewrites the gateway's cache from PostgreSQL (worker.CacheSync.ReconcileAll), and
// records it (audited: platform.cache_rebuilt). It returns the number of organizations.
func (a *Admin) RebuildCache(ctx context.Context, rebuild func(ctx context.Context) error) (int, error) {
	orgs, err := a.org.OrganizationIDs(system(ctx, uuid.Nil))
	if err != nil {
		return 0, fmt.Errorf("list organizations: %w", err)
	}
	spec := SpecCacheRebuilt
	spec.Params = map[string]any{"organizations": len(orgs)}
	err = a.runner.RunTx(system(ctx, uuid.Nil), ScopePlatform, spec, func(ctx context.Context, _ *pgstore.Queries, _ Recorder) error {
		return rebuild(ctx)
	})
	return len(orgs), err
}
