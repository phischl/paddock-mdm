package app

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
)

// Overview computes the numbers of the overview page (plan M7c decision 26) in one transaction; never cached.
type Overview struct {
	org *db.OrgPool
	now func() time.Time
}

// NewOverview creates the use case.
func NewOverview(org *db.OrgPool) *Overview { return &Overview{org: org, now: time.Now} }

// SecurityOverdueWindow: an active device without a successful security run within it counts as overdue.
const SecurityOverdueWindow = 48 * time.Hour

// securityOverdueInterval is SecurityOverdueWindow as the device list's security_updates=overdue filter takes it.
func securityOverdueInterval() pgtype.Interval {
	return pgtype.Interval{Microseconds: SecurityOverdueWindow.Microseconds(), Valid: true}
}

// OverviewResult is what GET /api/v1/overview answers.
type OverviewResult struct {
	GeneratedAt     time.Time
	Devices         pgstore.OverviewDevicesRow
	Encryption      pgstore.OverviewEncryptionRow
	Vulnerabilities OverviewVulnerabilities
	Updates         OverviewUpdates
	Attention       pgstore.OverviewAttentionRow
	SecurityReview  SecurityReviewCounts
}

// OverviewVulnerabilities: devices by their worst finding, the critical and high CVEs, and the top CVEs.
type OverviewVulnerabilities struct {
	ByHighestSeverity pgstore.OverviewVulnerabilityBucketsRow
	// CriticalHighCVEs is counted like the vulnerability list filtered by severity critical and high.
	CriticalHighCVEs int
	Top              []OverviewCVE
}

// OverviewCVE is one of the top findings.
type OverviewCVE struct {
	CVE      string
	Severity string
	Devices  int
	Packages []string
}

// OverviewUpdates: update and agent rollout counters.
type OverviewUpdates struct {
	SecurityOverdue int
	RebootRequired  int
	// CurrentVersion is nil while no agent rollout has completed.
	CurrentVersion *string
	OnCurrent      int
	Outdated       int
	Ahead          int
	Unknown        int
	// LatestPublished is nil while no agent release is published.
	LatestPublished *string
	// Rollout is nil while no rollout runs.
	Rollout    *OverviewRollout
	OSReleases []pgstore.OverviewOSReleasesRow
}

// OverviewRollout is the running agent rollout: its release, the 1-based wave of the waves and that wave's percentage.
type OverviewRollout struct {
	Version string
	Wave    int
	Waves   int
	Percent int
}

// severityRanks maps the rank of the overview queries back to the severity name (unknown = not rated by Ubuntu).
var severityRanks = []string{"critical", "high", "medium", "low", "unknown"}

// SeverityOfRank returns the severity name of a rank 0–4; anything else is unknown.
func SeverityOfRank(rank int32) string {
	if rank < 0 || int(rank) >= len(severityRanks) {
		return "unknown"
	}
	return severityRanks[rank]
}

// Get computes the overview for the caller's organization (roles org_admin, org_operator, org_auditor).
func (o *Overview) Get(ctx context.Context) (OverviewResult, error) {
	out := OverviewResult{GeneratedAt: o.now().UTC()}
	if _, err := RequireOrg(ctx, RolesRead); err != nil {
		return out, err
	}
	err := o.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		var err error
		if out.Devices, err = q.OverviewDevices(ctx); err != nil {
			return fmt.Errorf("overview devices: %w", err)
		}
		if out.Encryption, err = q.OverviewEncryption(ctx); err != nil {
			return fmt.Errorf("overview encryption: %w", err)
		}
		if out.Vulnerabilities.ByHighestSeverity, err = q.OverviewVulnerabilityBuckets(ctx); err != nil {
			return fmt.Errorf("overview vulnerability buckets: %w", err)
		}
		// The KPI numbers that link to a list are counted with that list's own query (plan M7c amendment 2026-10-10),
		// so the number and the list's total cannot drift apart.
		critical, err := q.CountVulnerabilities(ctx, pgstore.CountVulnerabilitiesParams{Severities: []string{"critical", "high"}, CountLimit: countLimit})
		if err != nil {
			return fmt.Errorf("overview critical and high CVEs: %w", err)
		}
		out.Vulnerabilities.CriticalHighCVEs = int(critical)
		top, err := q.OverviewTopCVEs(ctx)
		if err != nil {
			return fmt.Errorf("overview top CVEs: %w", err)
		}
		out.Vulnerabilities.Top = make([]OverviewCVE, len(top))
		for i, c := range top {
			out.Vulnerabilities.Top[i] = OverviewCVE{CVE: c.Cve, Severity: SeverityOfRank(c.Rank), Devices: int(c.Devices), Packages: c.Packages}
			if out.Vulnerabilities.Top[i].Packages == nil {
				out.Vulnerabilities.Top[i].Packages = []string{}
			}
		}
		updates, err := q.OverviewUpdates(ctx)
		if err != nil {
			return fmt.Errorf("overview updates: %w", err)
		}
		overdue, err := q.CountDevices(ctx, pgstore.CountDevicesParams{
			States: []string{"active"}, SecurityOverdueWindow: securityOverdueInterval(), CountLimit: countLimit,
		})
		if err != nil {
			return fmt.Errorf("overview security updates overdue: %w", err)
		}
		out.Updates = OverviewUpdates{
			SecurityOverdue: int(overdue), RebootRequired: int(updates.RebootRequired),
			OnCurrent: int(updates.AgentOnCurrent), Outdated: int(updates.AgentOutdated), Ahead: int(updates.AgentAhead),
			Unknown: int(updates.AgentUnknown),
		}
		version, err := q.CurrentAgentVersion(ctx)
		if err != nil {
			return fmt.Errorf("current agent version: %w", err)
		}
		if version != "" {
			out.Updates.CurrentVersion = &version
		}
		latest, err := q.LatestPublishedAgentVersion(ctx)
		if err != nil {
			return fmt.Errorf("latest published agent version: %w", err)
		}
		if latest != "" {
			out.Updates.LatestPublished = &latest
		}
		rollouts, err := q.RunningAgentRollout(ctx)
		if err != nil {
			return fmt.Errorf("running agent rollout: %w", err)
		}
		if len(rollouts) > 0 {
			r := rollouts[0]
			out.Updates.Rollout = &OverviewRollout{Version: r.Version, Wave: int(r.Wave), Waves: int(r.Waves), Percent: int(r.Percent)}
		}
		if out.Updates.OSReleases, err = q.OverviewOSReleases(ctx); err != nil {
			return fmt.Errorf("overview OS releases: %w", err)
		}
		if out.Attention, err = q.OverviewAttention(ctx); err != nil {
			return fmt.Errorf("overview attention: %w", err)
		}
		review, err := securityReviewIn(ctx, q, out.GeneratedAt)
		if err != nil {
			return err
		}
		out.SecurityReview = review.Counts()
		return nil
	})
	return out, err
}
