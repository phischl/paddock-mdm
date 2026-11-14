package app

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
	"github.com/phischl/paddock-mdm/server/internal/domain/patchsla"
)

// VulnerabilitySLASummary records the daily summary of findings open longer than the organization's patch SLA (plan
// M13c decision 18), on the notification path of the critical summary (plan M9 decision 37).
type VulnerabilitySLASummary struct {
	runner *ActionRunner
	// load reads the SLA, the devices and their findings (patchFindingsInput; replaced in tests).
	load func(ctx context.Context, q *pgstore.Queries, group uuid.NullUUID, now time.Time) (patchsla.Input, error)
}

// NewVulnerabilitySLASummary creates the use case.
func NewVulnerabilitySLASummary(runner *ActionRunner) *VulnerabilitySLASummary {
	return &VulnerabilitySLASummary{runner: runner, load: patchFindingsInput}
}

// Record records vulnerability.sla_breached for the organization of ctx when at least one finding breaches the SLA at
// now and the UTC day of now has no summary yet. A claimed day reads no findings; a round without a breach records and
// claims nothing.
func (s *VulnerabilitySLASummary) Record(ctx context.Context, now time.Time) error {
	day := audit.Timestamp(now).Truncate(24 * time.Hour)
	org, err := orgOf(ctx)
	if err != nil {
		return err
	}
	spec := ActionSpec{Code: audit.CodeVulnerabilitySLABreached, Target: &audit.Target{Type: "organization", ID: org.String()}}
	_, err = s.runner.RecordOnceWith(ctx, spec, func(ctx context.Context, q *pgstore.Queries, rec Recorder) (bool, error) {
		// Every inventory round calls this; a claimed day must not read the organization's findings again.
		if claimed, err := q.VulnerabilitySLASummaryClaimed(ctx, day); err != nil || claimed {
			return false, err
		}
		in, err := s.load(ctx, q, uuid.NullUUID{}, now)
		if err != nil {
			return false, err
		}
		report := patchsla.Compute(in)
		if report.Summary.Breached == 0 {
			return false, nil
		}
		n, err := q.ClaimVulnerabilitySLASummary(ctx, pgstore.ClaimVulnerabilitySLASummaryParams{OrganizationID: org, Day: day})
		if err != nil || n != 1 {
			return false, err
		}
		for severity, count := range report.BreachedBySeverity() {
			rec.SetParam(severity, count)
		}
		rec.SetParam("devices", report.Summary.Breached)
		return true, nil
	})
	return err
}
