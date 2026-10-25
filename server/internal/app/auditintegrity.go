package app

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/phischl/paddock-mdm/server/internal/adapters/auditpg/auditstore"
	"github.com/phischl/paddock-mdm/server/internal/auditwriter"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
)

// VerificationWindowDays is how many of the latest sealed days the nightly run verifies (plan M8b decision 27).
const VerificationWindowDays = auditwriter.VerifyWindowDays

// AuditIntegrity reads the integrity of the caller's organization's audit evidence: its sealed days and the chain
// verification runs (plan M8b decisions 30 and 31). It uses the read-only audit role, so RLS bounds every query to
// the organization; it never writes.
type AuditIntegrity struct {
	reader *db.AuditReader
}

// NewAuditIntegrity creates the use case.
func NewAuditIntegrity(reader *db.AuditReader) *AuditIntegrity {
	return &AuditIntegrity{reader: reader}
}

// IntegritySummary is the state of the evidence: the last sealed day (nil before the first seal), the number of
// sealed days, the newest verification run and the end of the newest successful and failed run.
type IntegritySummary struct {
	SealedThrough *time.Time
	Manifests     int
	LastRun       *auditstore.AuditVerificationRun
	LastSuccessAt *time.Time
	LastFailureAt *time.Time
}

// RunQuery filters the verification runs; nil OK and nil Triggers match every run.
type RunQuery struct {
	OK       *bool
	Triggers []string
	Page     ListPage
}

// ManifestQuery filters the sealed days: From and To are inclusive days, Verified selects days with (or without)
// a successful run covering them.
type ManifestQuery struct {
	From, To *time.Time
	Verified *bool
	Page     ListPage
}

// Summary returns the integrity summary of the caller's organization.
func (a *AuditIntegrity) Summary(ctx context.Context) (IntegritySummary, error) {
	var out IntegritySummary
	if _, err := RequireOrg(ctx, RolesAudit); err != nil {
		return out, err
	}
	err := a.reader.InOrg(ctx, func(ctx context.Context, q *auditstore.Queries) error {
		n, err := q.CountAuditManifests(ctx)
		if err != nil {
			return fmt.Errorf("count audit manifests: %w", err)
		}
		out.Manifests = int(n)
		day, err := q.LatestAuditManifestDay(ctx)
		switch {
		case err == nil:
			out.SealedThrough = &day
		case !db.IsNoRows(err):
			return fmt.Errorf("latest audit manifest: %w", err)
		}
		last, err := q.GetLatestAuditVerificationRun(ctx)
		switch {
		case err == nil:
			out.LastRun = &last
		case !db.IsNoRows(err):
			return fmt.Errorf("latest verification run: %w", err)
		}
		if out.LastSuccessAt, err = latestRunEnd(ctx, q, true); err != nil {
			return err
		}
		out.LastFailureAt, err = latestRunEnd(ctx, q, false)
		return err
	})
	return out, err
}

// latestRunEnd is the end of the newest run with the result ok, nil without one.
func latestRunEnd(ctx context.Context, q *auditstore.Queries, ok bool) (*time.Time, error) {
	run, err := q.GetLatestAuditVerificationRunByOK(ctx, ok)
	if db.IsNoRows(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("latest verification run (ok=%t): %w", ok, err)
	}
	return &run.FinishedAt, nil
}

// ListRuns returns one page of verification runs and the capped number of matches (ADR 0018).
func (a *AuditIntegrity) ListRuns(ctx context.Context, f RunQuery) (Listed[auditstore.AuditVerificationRun], error) {
	var out Listed[auditstore.AuditVerificationRun]
	if _, err := RequireOrg(ctx, RolesAudit); err != nil {
		return out, err
	}
	err := a.reader.InOrg(ctx, func(ctx context.Context, q *auditstore.Queries) error {
		n, err := q.CountAuditVerificationRunsFiltered(ctx, auditstore.CountAuditVerificationRunsFilteredParams{
			OkFilter: f.OK, Triggers: f.Triggers, QPattern: f.Page.QPattern, CountLimit: countLimit,
		})
		if err != nil {
			return fmt.Errorf("count verification runs: %w", err)
		}
		out.Count = int(n)
		out.Items, err = q.ListAuditVerificationRuns(ctx, auditstore.ListAuditVerificationRunsParams{
			OkFilter: f.OK, Triggers: f.Triggers, QPattern: f.Page.QPattern,
			Sort: f.Page.Sort, SkipRows: f.Page.Offset, MaxRows: f.Page.Limit,
		})
		if err != nil {
			return fmt.Errorf("list verification runs: %w", err)
		}
		return nil
	})
	return out, err
}

// ListManifests returns one page of sealed days, each with the newest verification run covering it, and the capped
// number of matches (ADR 0018).
func (a *AuditIntegrity) ListManifests(ctx context.Context, f ManifestQuery) (Listed[auditstore.ListAuditManifestsWithVerificationRow], error) {
	var out Listed[auditstore.ListAuditManifestsWithVerificationRow]
	if _, err := RequireOrg(ctx, RolesAudit); err != nil {
		return out, err
	}
	from, to := sqlDate(f.From), sqlDate(f.To)
	err := a.reader.InOrg(ctx, func(ctx context.Context, q *auditstore.Queries) error {
		n, err := q.CountAuditManifestsFiltered(ctx, auditstore.CountAuditManifestsFilteredParams{
			FromDay: from, ToDay: to, Verified: f.Verified, QPattern: f.Page.QPattern, CountLimit: countLimit,
		})
		if err != nil {
			return fmt.Errorf("count audit manifests: %w", err)
		}
		out.Count = int(n)
		out.Items, err = q.ListAuditManifestsWithVerification(ctx, auditstore.ListAuditManifestsWithVerificationParams{
			FromDay: from, ToDay: to, Verified: f.Verified, QPattern: f.Page.QPattern,
			Sort: f.Page.Sort, SkipRows: f.Page.Offset, MaxRows: f.Page.Limit,
		})
		if err != nil {
			return fmt.Errorf("list audit manifests: %w", err)
		}
		return nil
	})
	return out, err
}

// sqlDate is the calendar day of t (as given, not converted to UTC), or SQL NULL for nil.
func sqlDate(t *time.Time) pgtype.Date {
	if t == nil {
		return pgtype.Date{}
	}
	return pgtype.Date{Time: time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC), Valid: true}
}
