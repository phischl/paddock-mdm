package admin

import (
	"context"

	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/transport/http/admin/adminapi"
	"github.com/phischl/paddock-mdm/server/internal/transport/http/admin/listing"
)

// List definitions of the inventory endpoints (plan M5a decision 9); they match x-paddock-list.
var (
	deviceSoftwareList   = listing.Spec{Sort: []string{"name", "version"}, DefaultSort: "name"}
	findingList          = listing.Spec{Sort: []string{"cvss_score", "severity", "cve"}, DefaultSort: "-cve"}
	softwareList         = listing.Spec{Sort: []string{"name", "version", "device_count"}, DefaultSort: "name"}
	vulnerabilityList    = listing.Spec{Sort: []string{"cvss_score", "severity", "cve", "device_count"}, DefaultSort: "-cve"}
	vulnerableDeviceList = listing.Spec{Sort: []string{"hostname"}, DefaultSort: "hostname"}
)

func (h *handlers) ListDeviceSoftware(ctx context.Context, req adminapi.ListDeviceSoftwareRequestObject) (adminapi.ListDeviceSoftwareResponseObject, error) {
	params, err := listing.Parse(deviceSoftwareList, listing.Query{
		Page: req.Params.Page, PageSize: (*int)(req.Params.PageSize), Sort: (*string)(req.Params.Sort), Q: req.Params.Q,
	})
	if err != nil {
		return nil, err
	}
	res, err := h.inventory.DeviceSoftware(ctx, req.Id, params.ListPage())
	if err != nil {
		return nil, err
	}
	items := make([]adminapi.InstalledSoftware, len(res.Items))
	for i, r := range res.Items {
		items[i] = adminapi.InstalledSoftware{Name: r.Name, Version: r.Version, Source: r.Source}
	}
	return adminapi.ListDeviceSoftware200JSONResponse(listing.NewPage(items, params, res.Count)), nil
}

func (h *handlers) ListDeviceVulnerabilities(ctx context.Context, req adminapi.ListDeviceVulnerabilitiesRequestObject) (adminapi.ListDeviceVulnerabilitiesResponseObject, error) {
	params, err := listing.Parse(findingList, listing.Query{
		Page: req.Params.Page, PageSize: (*int)(req.Params.PageSize), Sort: (*string)(req.Params.Sort), Q: req.Params.Q,
	})
	if err != nil {
		return nil, err
	}
	severities, err := listing.Enum("severity", req.Params.Severity)
	if err != nil {
		return nil, err
	}
	res, err := h.inventory.DeviceVulnerabilities(ctx, req.Id, app.VulnerabilityQuery{Page: params.ListPage(), Severities: severities})
	if err != nil {
		return nil, err
	}
	items := make([]adminapi.VulnerabilityFinding, len(res.Items))
	for i, r := range res.Items {
		items[i] = toFinding(r)
	}
	return adminapi.ListDeviceVulnerabilities200JSONResponse(listing.NewPage(items, params, res.Count)), nil
}

func toFinding(r pgstore.ListDeviceVulnerabilitiesRow) adminapi.VulnerabilityFinding {
	return adminapi.VulnerabilityFinding{
		Cve: r.Cve, SoftwareName: r.SoftwareName, SoftwareVersion: r.SoftwareVersion, CvssScore: r.CvssScore,
		Severity: adminapi.Severity(r.Severity), FixedVersion: r.FixedVersion, CvssVector: r.CvssVector,
		FirstSeenAt: r.FirstSeenAt.UTC(),
	}
}

func (h *handlers) ListSoftware(ctx context.Context, req adminapi.ListSoftwareRequestObject) (adminapi.ListSoftwareResponseObject, error) {
	params, err := listing.Parse(softwareList, listing.Query{
		Page: req.Params.Page, PageSize: (*int)(req.Params.PageSize), Sort: (*string)(req.Params.Sort), Q: req.Params.Q,
	})
	if err != nil {
		return nil, err
	}
	res, err := h.inventory.Software(ctx, app.SoftwareQuery{Page: params.ListPage(), HasVulnerabilities: req.Params.HasVulnerabilities})
	if err != nil {
		return nil, err
	}
	items := make([]adminapi.SoftwareSummary, len(res.Items))
	for i, r := range res.Items {
		items[i] = adminapi.SoftwareSummary{Name: r.Name, Version: r.Version, DeviceCount: int(r.DeviceCount), HasVulnerabilities: r.HasVulnerabilities}
	}
	return adminapi.ListSoftware200JSONResponse(listing.NewPage(items, params, res.Count)), nil
}

func (h *handlers) ListVulnerabilities(ctx context.Context, req adminapi.ListVulnerabilitiesRequestObject) (adminapi.ListVulnerabilitiesResponseObject, error) {
	params, err := listing.Parse(vulnerabilityList, listing.Query{
		Page: req.Params.Page, PageSize: (*int)(req.Params.PageSize), Sort: (*string)(req.Params.Sort), Q: req.Params.Q,
	})
	if err != nil {
		return nil, err
	}
	severities, err := listing.Enum("severity", req.Params.Severity)
	if err != nil {
		return nil, err
	}
	res, err := h.inventory.Vulnerabilities(ctx, app.VulnerabilityQuery{Page: params.ListPage(), Severities: severities})
	if err != nil {
		return nil, err
	}
	items := make([]adminapi.Vulnerability, len(res.Items))
	for i, r := range res.Items {
		items[i] = adminapi.Vulnerability{Cve: r.Cve, CvssScore: r.CvssScore, Severity: adminapi.Severity(r.Severity),
			DeviceCount: int(r.DeviceCount), FixedVersion: r.FixedVersion, CvssVector: r.CvssVector}
	}
	return adminapi.ListVulnerabilities200JSONResponse(listing.NewPage(items, params, res.Count)), nil
}

func (h *handlers) GetVulnerabilitySummary(ctx context.Context, _ adminapi.GetVulnerabilitySummaryRequestObject) (adminapi.GetVulnerabilitySummaryResponseObject, error) {
	s, err := h.inventory.Summary(ctx)
	if err != nil {
		return nil, err
	}
	return adminapi.GetVulnerabilitySummary200JSONResponse{CriticalHighDevices: int(s.CriticalHighDevices),
		UnknownSeverityDevices: int(s.UnknownSeverityDevices), AffectedDevices: int(s.AffectedDevices)}, nil
}

func (h *handlers) ListVulnerabilityDevices(ctx context.Context, req adminapi.ListVulnerabilityDevicesRequestObject) (adminapi.ListVulnerabilityDevicesResponseObject, error) {
	params, err := listing.Parse(vulnerableDeviceList, listing.Query{
		Page: req.Params.Page, PageSize: (*int)(req.Params.PageSize), Sort: (*string)(req.Params.Sort), Q: req.Params.Q,
	})
	if err != nil {
		return nil, err
	}
	res, err := h.inventory.VulnerabilityDevices(ctx, req.Cve, params.ListPage())
	if err != nil {
		return nil, err
	}
	items := make([]adminapi.VulnerableDevice, len(res.Items))
	for i, r := range res.Items {
		items[i] = adminapi.VulnerableDevice{DeviceId: r.DeviceID, Hostname: r.Hostname, SoftwareName: r.SoftwareName, SoftwareVersion: r.SoftwareVersion}
	}
	return adminapi.ListVulnerabilityDevices200JSONResponse(listing.NewPage(items, params, res.Count)), nil
}
