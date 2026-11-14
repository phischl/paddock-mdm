package app

import (
	"bytes"
	"context"
	"encoding/csv"
	"fmt"
	"strconv"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
	"github.com/phischl/paddock-mdm/server/internal/domain/patchsla"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/problem"
)

// Privileged actions of the patch compliance report (plan M13c decision 18): RolesAudit and org_operator read it. The
// view is a read recorded through RecordReadOnce under inventory_view_recorded; every export is recorded.
var (
	SpecPatchComplianceViewed   = ActionSpec{Code: audit.CodePatchComplianceViewed, AllowedRoles: RolesRead}
	SpecPatchComplianceExported = ActionSpec{Code: audit.CodePatchComplianceExported, AllowedRoles: RolesRead}
)

// PatchComplianceQuery selects the report: all devices in scope or the members of one device group. The report is
// the state at its generation, it has no period (plan M13c amendment 2026-11-14).
type PatchComplianceQuery struct {
	DeviceGroupID uuid.NullUUID
}

// PatchComplianceReport is the report of decision 18 at GeneratedAt: the computed sections, the SLA they were computed
// against and the device group filter.
type PatchComplianceReport struct {
	patchsla.Report
	GeneratedAt   time.Time
	SLA           patchsla.SLA
	DeviceGroupID uuid.NullUUID
}

// PatchComplianceExport is an export of the report; Report is complete (no device cap).
type PatchComplianceExport struct {
	Format   string
	Filename string
	CSV      []byte
	Report   PatchComplianceReport
}

// PatchCompliance computes the patch compliance report of the caller's organization (plan M13c decision 18).
type PatchCompliance struct {
	runner *ActionRunner
	org    *db.OrgPool
	now    func() time.Time
}

// NewPatchCompliance creates the use cases.
func NewPatchCompliance(runner *ActionRunner, org *db.OrgPool) *PatchCompliance {
	return &PatchCompliance{runner: runner, org: org, now: time.Now}
}

// Report returns the report, its device list capped at patchsla.DeviceCap. The view is recorded as
// patch_compliance.viewed once per actor and UTC day, only while inventory_view_recorded is on; a role that may not
// read it is recorded as denied, and a refused device group as failure while recording is on.
func (p *PatchCompliance) Report(ctx context.Context, in PatchComplianceQuery) (PatchComplianceReport, error) {
	now := p.now()
	enabled := func(ctx context.Context, qs *pgstore.Queries) (bool, error) {
		s, err := LoadPrivacySettings(ctx, qs)
		return s.InventoryViewRecorded, err
	}
	spec := SpecPatchComplianceViewed
	if org, err := orgOf(ctx); err == nil {
		spec.Target = &audit.Target{Type: "organization", ID: org.String()}
	}
	_, err := p.runner.RecordReadOnce(ctx, spec, enabled, func(ctx context.Context, qs *pgstore.Queries, rec Recorder) (bool, error) {
		if err := checkPatchGroup(ctx, qs, in.DeviceGroupID); err != nil {
			return false, err
		}
		window := now.UTC().Truncate(24 * time.Hour)
		if fresh, err := claimReadWindow(ctx, qs, audit.CodePatchComplianceViewed, "", window); err != nil || !fresh {
			return false, err
		}
		setPatchComplianceParams(rec, in.DeviceGroupID)
		rec.SetParam("window_start", window.Format(time.RFC3339))
		return true, nil
	})
	if err != nil {
		return PatchComplianceReport{}, err
	}
	var out PatchComplianceReport
	err = p.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		if err := checkPatchGroup(ctx, q, in.DeviceGroupID); err != nil {
			return err
		}
		var err error
		out, err = buildPatchCompliance(ctx, q, in.DeviceGroupID, now)
		return err
	})
	out.Report = out.Capped(patchsla.DeviceCap)
	return out, err
}

// Export returns the complete report as format (AccessReviewJSON or AccessReviewCSV). Every export is recorded as
// patch_compliance.exported, whatever the privacy settings.
func (p *PatchCompliance) Export(ctx context.Context, in PatchComplianceQuery, format string) (PatchComplianceExport, error) {
	now := p.now()
	spec := SpecPatchComplianceExported
	if org, err := orgOf(ctx); err == nil {
		spec.Target = &audit.Target{Type: "organization", ID: org.String()}
	}
	var out PatchComplianceExport
	err := p.runner.RunTx(ctx, ScopeOrg, spec, func(ctx context.Context, q *pgstore.Queries, rec Recorder) error {
		if format != AccessReviewJSON && format != AccessReviewCSV {
			return problem.InvalidRequest.WithDetail("format must be json or csv")
		}
		if err := checkPatchGroup(ctx, q, in.DeviceGroupID); err != nil {
			return err
		}
		setPatchComplianceParams(rec, in.DeviceGroupID)
		rec.SetParam("format", format)
		report, err := buildPatchCompliance(ctx, q, in.DeviceGroupID, now)
		if err != nil {
			return err
		}
		org, err := q.GetOrganization(ctx, mustOrg(ctx))
		if err != nil {
			return fmt.Errorf("organization of the patch compliance export: %w", err)
		}
		out = PatchComplianceExport{Format: format, Report: report, Filename: fmt.Sprintf("paddock-patch-compliance-%s-%s.%s",
			org.Slug, report.GeneratedAt.Format(time.DateOnly), format)}
		if format == AccessReviewCSV {
			out.CSV, err = report.csv()
		}
		return err
	})
	return out, err
}

func setPatchComplianceParams(rec Recorder, group uuid.NullUUID) {
	if group.Valid {
		rec.SetParam("device_group_id", group.UUID.String())
	}
}

// checkPatchGroup refuses a device group the organization does not have (404, as for any foreign object).
func checkPatchGroup(ctx context.Context, q *pgstore.Queries, group uuid.NullUUID) error {
	if !group.Valid {
		return nil
	}
	if _, err := q.GetDeviceGroup(ctx, group.UUID); db.IsNoRows(err) {
		return problem.NotFound
	} else if err != nil {
		return fmt.Errorf("device group of the patch compliance report: %w", err)
	}
	return nil
}

// buildPatchCompliance reads the inventory in scope and computes the complete report as the state at now: every open
// finding with a severity and a fixed version of a device in scope counts, its days open measured to now (plan M13c
// amendment 2026-11-14).
func buildPatchCompliance(ctx context.Context, q *pgstore.Queries, group uuid.NullUUID, now time.Time) (PatchComplianceReport, error) {
	out := PatchComplianceReport{GeneratedAt: now.UTC(), DeviceGroupID: group}
	in, err := patchComplianceInput(ctx, q, group, now)
	if err != nil {
		return out, err
	}
	out.SLA = in.SLA
	out.Report = patchsla.Compute(in)
	return out, nil
}

// patchComplianceInput reads everything patchsla.Compute needs inside an organization transaction.
func patchComplianceInput(ctx context.Context, q *pgstore.Queries, group uuid.NullUUID, now time.Time) (patchsla.Input, error) {
	in, err := patchFindingsInput(ctx, q, group, now)
	if err != nil {
		return in, err
	}
	groups, err := q.ListPatchComplianceGroups(ctx, group)
	if err != nil {
		return in, fmt.Errorf("patch compliance groups: %w", err)
	}
	for _, g := range groups {
		in.Memberships = append(in.Memberships, patchsla.Membership{GroupID: g.DeviceGroupID, Name: g.Name, DeviceID: g.DeviceID})
	}
	pins, err := q.ListPinnedRequiredAssignments(ctx)
	if err != nil {
		return in, fmt.Errorf("patch compliance pins: %w", err)
	}
	for _, p := range pins {
		in.Pins = append(in.Pins, patchsla.Pin{AssignmentID: p.ID, Entry: p.Entry, RequiredVersion: p.RequiredVersion})
	}
	installs, err := q.ListPinnedRequiredInstalls(ctx, group)
	if err != nil {
		return in, fmt.Errorf("patch compliance installs: %w", err)
	}
	for _, i := range installs {
		in.Installs = append(in.Installs, patchsla.Install{AssignmentID: i.AssignmentID, DeviceID: i.DeviceID, Version: i.InstalledVersion})
	}
	return in, nil
}

// patchFindingsInput reads the SLA, the devices in scope and their findings: what the breach counts need (the
// worker's daily summary reads no more).
func patchFindingsInput(ctx context.Context, q *pgstore.Queries, group uuid.NullUUID, now time.Time) (patchsla.Input, error) {
	in := patchsla.Input{Now: now}
	sla, err := LoadPatchSLA(ctx, q)
	if err != nil {
		return in, fmt.Errorf("patch sla: %w", err)
	}
	in.SLA = sla.SLA
	devices, err := q.ListPatchComplianceDevices(ctx, group)
	if err != nil {
		return in, fmt.Errorf("patch compliance devices: %w", err)
	}
	for _, d := range devices {
		in.Devices = append(in.Devices, patchsla.Device{ID: d.ID, Hostname: d.Hostname})
	}
	findings, err := q.ListPatchComplianceFindings(ctx, group)
	if err != nil {
		return in, fmt.Errorf("patch compliance findings: %w", err)
	}
	for _, f := range findings {
		in.Findings = append(in.Findings, patchsla.Finding{DeviceID: f.DeviceID, CVE: f.Cve, Package: f.SoftwareName,
			Severity: f.Severity, FixedVersion: f.FixedVersion, FirstSeenAt: f.FirstSeenAt})
	}
	return in, nil
}

// patchComplianceColumns are the columns of the CSV export: one file for every section, told apart by section. A row
// fills the columns that apply to its section and leaves the others empty.
var patchComplianceColumns = []string{
	"section", "severity", "device_group", "device_id", "hostname", "cve", "package", "days_open", "fixed_version",
	"sla_days", "findings_open", "findings_breached", "median_days_open", "p90_days_open", "devices", "compliant",
	"breached", "entry", "required_version", "devices_behind",
}

// csv renders every row of r: the summary, the severities, the groups, one row per breached finding and the pinned
// required assignments.
func (r PatchComplianceReport) csv() ([]byte, error) {
	itoa := strconv.Itoa
	rows := []csvRow{{"section": "summary", "devices": itoa(r.Summary.Devices), "compliant": itoa(r.Summary.Compliant),
		"breached": itoa(r.Summary.Breached)}}
	for _, s := range r.BySeverity {
		rows = append(rows, csvRow{"section": "severity", "severity": s.Severity, "sla_days": itoa(r.SLA.Days(s.Severity)),
			"findings_open": itoa(s.FindingsOpen), "findings_breached": itoa(s.FindingsBreached),
			"median_days_open": itoa(s.MedianDaysOpen), "p90_days_open": itoa(s.P90DaysOpen)})
	}
	for _, g := range r.ByGroup {
		rows = append(rows, csvRow{"section": "group", "device_group": g.Name, "devices": itoa(g.Devices), "breached": itoa(g.Breached)})
	}
	for _, d := range r.Devices {
		for _, b := range d.Breached {
			rows = append(rows, csvRow{"section": "breach", "device_id": d.DeviceID.String(), "hostname": d.Hostname, "cve": b.CVE,
				"package": b.Package, "severity": b.Severity, "days_open": itoa(b.DaysOpen), "fixed_version": b.FixedVersion,
				"sla_days": itoa(b.SLADays)})
		}
	}
	for _, c := range r.Catalog {
		rows = append(rows, csvRow{"section": "catalog", "entry": c.Entry, "required_version": c.RequiredVersion,
			"devices_behind": itoa(c.DevicesBehind)})
	}
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	if err := w.Write(patchComplianceColumns); err != nil {
		return nil, fmt.Errorf("write patch compliance csv: %w", err)
	}
	for _, row := range rows {
		cells := make([]string, len(patchComplianceColumns))
		for i, c := range patchComplianceColumns {
			cells[i] = csvSafe(row[c])
		}
		if err := w.Write(cells); err != nil {
			return nil, fmt.Errorf("write patch compliance csv: %w", err)
		}
	}
	w.Flush()
	if err := w.Error(); err != nil {
		return nil, fmt.Errorf("write patch compliance csv: %w", err)
	}
	return buf.Bytes(), nil
}
