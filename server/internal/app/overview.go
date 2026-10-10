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

// OverviewResult is what GET /api/v1/overview answers.
type OverviewResult struct {
	GeneratedAt     time.Time
	Devices         pgstore.OverviewDevicesRow
	Encryption      pgstore.OverviewEncryptionRow
	Vulnerabilities OverviewVulnerabilities
	Updates         OverviewUpdates
	Attention       pgstore.OverviewAttentionRow
}

// OverviewVulnerabilities: devices by their worst finding and the top CVEs.
type OverviewVulnerabilities struct {
	ByHighestSeverity pgstore.OverviewVulnerabilityBucketsRow
	Top               []OverviewCVE
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
	// CurrentVersion is nil while no agent release is published.
	CurrentVersion *string
	OnCurrent      int
	Outdated       int
	Unknown        int
	OSReleases     []pgstore.OverviewOSReleasesRow
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
		updates, err := q.OverviewUpdates(ctx, pgtype.Interval{Microseconds: SecurityOverdueWindow.Microseconds(), Valid: true})
		if err != nil {
			return fmt.Errorf("overview updates: %w", err)
		}
		out.Updates = OverviewUpdates{
			SecurityOverdue: int(updates.SecurityOverdue), RebootRequired: int(updates.RebootRequired),
			OnCurrent: int(updates.AgentOnCurrent), Outdated: int(updates.AgentOutdated), Unknown: int(updates.AgentUnknown),
		}
		version, err := q.CurrentAgentVersion(ctx)
		if err != nil {
			return fmt.Errorf("current agent version: %w", err)
		}
		if version != "" {
			out.Updates.CurrentVersion = &version
		}
		if out.Updates.OSReleases, err = q.OverviewOSReleases(ctx); err != nil {
			return fmt.Errorf("overview OS releases: %w", err)
		}
		if out.Attention, err = q.OverviewAttention(ctx); err != nil {
			return fmt.Errorf("overview attention: %w", err)
		}
		return nil
	})
	return out, err
}
