package app

import (
	"cmp"
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/pkg/policy"
	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/domain/privilege"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/principal"
)

// SecurityReviewCap bounds every list of the review; the totals count every item.
const SecurityReviewCap = 100

// SecurityReview lists what existed before the step-up rules covered it (ADR 0034 decision 7, plan M8s decision 25):
// effectively Full profiles and files on sensitive paths without a confirmation, and files on denied paths.
type SecurityReview struct {
	org *db.OrgPool
	now func() time.Time
}

// NewSecurityReview creates the use case.
func NewSecurityReview(org *db.OrgPool) *SecurityReview {
	return &SecurityReview{org: org, now: time.Now}
}

// SecurityReviewResult is what GET /api/v1/security-review answers; every list holds at most SecurityReviewCap items.
type SecurityReviewResult struct {
	GeneratedAt    time.Time
	RootGrants     []ReviewedProfile
	RootGrantTotal int
	Sensitive      []pgstore.ManagedFile
	SensitiveTotal int
	Denied         []pgstore.ManagedFile
	DeniedTotal    int
}

// ReviewedProfile is an unconfirmed effectively Full profile and the number of its assignments.
type ReviewedProfile struct {
	Profile     pgstore.PermissionProfile
	Assignments int
}

// SecurityReviewCounts are the totals of the review (overview banner, CLI).
type SecurityReviewCounts struct {
	RootGrants, SensitiveFiles, DeniedFiles int
}

// Counts returns the totals of r.
func (r SecurityReviewResult) Counts() SecurityReviewCounts {
	return SecurityReviewCounts{RootGrants: r.RootGrantTotal, SensitiveFiles: r.SensitiveTotal, DeniedFiles: r.DeniedTotal}
}

// Get returns the review of the caller's organization (roles org_admin, org_operator, org_auditor).
func (r *SecurityReview) Get(ctx context.Context) (SecurityReviewResult, error) {
	out := SecurityReviewResult{GeneratedAt: r.now().UTC()}
	if _, err := RequireOrg(ctx, RolesRead); err != nil {
		return out, err
	}
	err := r.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		var err error
		out, err = securityReviewIn(ctx, q, out.GeneratedAt)
		return err
	})
	return out, err
}

// securityReviewIn computes the review inside an organization transaction; the tiers come from the policy, not SQL.
func securityReviewIn(ctx context.Context, q *pgstore.Queries, at time.Time) (SecurityReviewResult, error) {
	out := SecurityReviewResult{GeneratedAt: at, RootGrants: []ReviewedProfile{}, Sensitive: []pgstore.ManagedFile{},
		Denied: []pgstore.ManagedFile{}}
	profiles, err := q.ListAllPermissionProfiles(ctx)
	if err != nil {
		return out, fmt.Errorf("security review profiles: %w", err)
	}
	counts, err := q.CountProfileAssignmentsByProfile(ctx)
	if err != nil {
		return out, fmt.Errorf("security review assignments: %w", err)
	}
	assigned := make(map[uuid.UUID]int, len(counts))
	for _, c := range counts {
		assigned[c.ProfileID] = int(c.Assignments)
	}
	for _, p := range profiles {
		if p.RootGrantConfirmedAt == nil && privilege.RequiresStepUp(profileOf(p)) {
			out.RootGrants = append(out.RootGrants, ReviewedProfile{Profile: p, Assignments: assigned[p.ID]})
		}
	}
	slices.SortFunc(out.RootGrants, func(a, b ReviewedProfile) int {
		return cmp.Or(cmp.Compare(a.Profile.Name, b.Profile.Name), slices.Compare(a.Profile.ID[:], b.Profile.ID[:]))
	})
	files, err := q.ListAllManagedFiles(ctx)
	if err != nil {
		return out, fmt.Errorf("security review files: %w", err)
	}
	roots, err := operatorRoots(ctx, q)
	if err != nil {
		return out, fmt.Errorf("security review operator roots: %w", err)
	}
	for _, f := range files {
		tier, err := policy.Classify(f.Path, f.Mode, roots)
		switch {
		case err != nil || tier == policy.TierDenied:
			out.Denied = append(out.Denied, f)
		case tier == policy.TierSensitive && f.SensitiveConfirmedAt == nil:
			out.Sensitive = append(out.Sensitive, f)
		}
	}
	byPath := func(a, b pgstore.ManagedFile) int {
		return cmp.Or(cmp.Compare(a.Path, b.Path), slices.Compare(a.ID[:], b.ID[:]))
	}
	slices.SortFunc(out.Sensitive, byPath)
	slices.SortFunc(out.Denied, byPath)
	out.RootGrantTotal, out.SensitiveTotal, out.DeniedTotal = len(out.RootGrants), len(out.Sensitive), len(out.Denied)
	out.RootGrants = out.RootGrants[:min(len(out.RootGrants), SecurityReviewCap)]
	out.Sensitive = out.Sensitive[:min(len(out.Sensitive), SecurityReviewCap)]
	out.Denied = out.Denied[:min(len(out.Denied), SecurityReviewCap)]
	return out, nil
}

// confirmation is the value of a confirmation column pair (ADR 0034 decision 7): now and the acting administrator
// when the action confirmed the grant with a step-up, NULL otherwise. A system principal has no account.
func confirmation(ctx context.Context, confirmed bool) (*time.Time, uuid.NullUUID) {
	if !confirmed {
		return nil, uuid.NullUUID{}
	}
	now := time.Now().UTC()
	p, _ := principal.From(ctx)
	return &now, uuid.NullUUID{UUID: p.ID, Valid: p.Kind == principal.KindAdmin && p.ID != uuid.Nil}
}
