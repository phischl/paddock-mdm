package admin

import (
	"bytes"
	"context"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/domain/patchsla"
	"github.com/phischl/paddock-mdm/server/internal/transport/http/admin/adminapi"
)

func (h *handlers) GetPatchSlaSettings(ctx context.Context, _ adminapi.GetPatchSlaSettingsRequestObject) (adminapi.GetPatchSlaSettingsResponseObject, error) {
	s, err := h.patchSLA.Get(ctx)
	if err != nil {
		return nil, err
	}
	return adminapi.GetPatchSlaSettings200JSONResponse(toPatchSLASettings(s)), nil
}

func (h *handlers) UpdatePatchSlaSettings(ctx context.Context, req adminapi.UpdatePatchSlaSettingsRequestObject) (adminapi.UpdatePatchSlaSettingsResponseObject, error) {
	b := req.Body
	s, err := h.patchSLA.Update(ctx, patchsla.SLA{CriticalDays: b.CriticalDays, HighDays: b.HighDays, MediumDays: b.MediumDays,
		LowDays: b.LowDays})
	if err != nil {
		return nil, err
	}
	return adminapi.UpdatePatchSlaSettings200JSONResponse(toPatchSLASettings(s)), nil
}

func toPatchSLASettings(s app.PatchSLASettings) adminapi.PatchSlaSettings {
	return adminapi.PatchSlaSettings{CriticalDays: s.CriticalDays, HighDays: s.HighDays, MediumDays: s.MediumDays,
		LowDays: s.LowDays, UpdatedAt: s.UpdatedAt.UTC()}
}

func patchComplianceQuery(group *uuid.UUID) app.PatchComplianceQuery {
	var q app.PatchComplianceQuery
	if group != nil {
		q.DeviceGroupID = uuid.NullUUID{UUID: *group, Valid: true}
	}
	return q
}

func (h *handlers) GetPatchCompliance(ctx context.Context, req adminapi.GetPatchComplianceRequestObject) (adminapi.GetPatchComplianceResponseObject, error) {
	r, err := h.patchCompliance.Report(ctx, patchComplianceQuery(req.Params.DeviceGroupId))
	if err != nil {
		return nil, err
	}
	return adminapi.GetPatchCompliance200JSONResponse(toPatchComplianceReport(r)), nil
}

func (h *handlers) ExportPatchCompliance(ctx context.Context, req adminapi.ExportPatchComplianceRequestObject) (adminapi.ExportPatchComplianceResponseObject, error) {
	e, err := h.patchCompliance.Export(ctx, patchComplianceQuery(req.Params.DeviceGroupId),
		string(req.Params.Format))
	if err != nil {
		return nil, err
	}
	headers := adminapi.ExportPatchCompliance200ResponseHeaders{ContentDisposition: attachment(e.Filename)}
	if e.Format == app.AccessReviewCSV {
		return adminapi.ExportPatchCompliance200TextcsvResponse{Body: bytes.NewReader(e.CSV), ContentLength: int64(len(e.CSV)), Headers: headers}, nil
	}
	return adminapi.ExportPatchCompliance200JSONResponse{Body: toPatchComplianceReport(e.Report), Headers: headers}, nil
}

func toPatchComplianceReport(r app.PatchComplianceReport) adminapi.PatchComplianceReport {
	out := adminapi.PatchComplianceReport{
		GeneratedAt: r.GeneratedAt,
		Sla: adminapi.PatchSla{CriticalDays: r.SLA.CriticalDays, HighDays: r.SLA.HighDays, MediumDays: r.SLA.MediumDays,
			LowDays: r.SLA.LowDays},
		DevicesTotal: r.DevicesTotal, RowCap: patchsla.DeviceCap,
		BySeverity: mapItems(r.BySeverity, func(s patchsla.SeverityStats) adminapi.PatchComplianceSeverity {
			return adminapi.PatchComplianceSeverity{Severity: adminapi.PatchComplianceSeveritySeverity(s.Severity),
				FindingsOpen: s.FindingsOpen, FindingsBreached: s.FindingsBreached, MedianDaysOpen: s.MedianDaysOpen,
				P90DaysOpen: s.P90DaysOpen}
		}),
		ByGroup: mapItems(r.ByGroup, func(g patchsla.GroupStats) adminapi.PatchComplianceGroup {
			return adminapi.PatchComplianceGroup{DeviceGroupId: g.GroupID, DeviceGroup: g.Name, Devices: g.Devices, Breached: g.Breached}
		}),
		Devices: mapItems(r.Devices, func(d patchsla.DeviceBreaches) adminapi.PatchComplianceDevice {
			return adminapi.PatchComplianceDevice{DeviceId: d.DeviceID, Hostname: d.Hostname,
				Breached: mapItems(d.Breached, func(b patchsla.Breach) adminapi.PatchComplianceBreach {
					return adminapi.PatchComplianceBreach{Cve: b.CVE, Package: b.Package,
						Severity: adminapi.PatchComplianceBreachSeverity(b.Severity), DaysOpen: b.DaysOpen,
						FixedVersion: b.FixedVersion, SlaDays: b.SLADays}
				})}
		}),
		Catalog: mapItems(r.Catalog, func(c patchsla.CatalogRow) adminapi.PatchComplianceCatalogRow {
			return adminapi.PatchComplianceCatalogRow{AssignmentId: c.AssignmentID, Entry: c.Entry,
				RequiredVersion: c.RequiredVersion, DevicesBehind: c.DevicesBehind}
		}),
	}
	if r.DeviceGroupID.Valid {
		out.DeviceGroupId = &r.DeviceGroupID.UUID
	}
	out.Summary.Devices, out.Summary.Compliant, out.Summary.Breached = r.Summary.Devices, r.Summary.Compliant, r.Summary.Breached
	return out
}
