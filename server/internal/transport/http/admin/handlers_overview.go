package admin

import (
	"context"

	"github.com/phischl/paddock-mdm/server/internal/transport/http/admin/adminapi"
)

// GetOverview answers the numbers of the overview page (plan M7c decision 26); not a list endpoint.
func (h *handlers) GetOverview(ctx context.Context, _ adminapi.GetOverviewRequestObject) (adminapi.GetOverviewResponseObject, error) {
	o, err := h.overview.Get(ctx)
	if err != nil {
		return nil, err
	}
	out := adminapi.Overview{
		GeneratedAt: o.GeneratedAt,
		Devices: adminapi.OverviewDevices{
			Total: int(o.Devices.Total), Active: int(o.Devices.Active), Pending: int(o.Devices.Pending), Quarantined: int(o.Devices.Quarantined),
			Retired: int(o.Devices.Retired), Rejected: int(o.Devices.Rejected), Online: int(o.Devices.Online), Silent: int(o.Devices.Silent),
			SilentCritical: int(o.Devices.SilentCritical), PresumedLost: int(o.Devices.PresumedLost), NeverContacted: int(o.Devices.NeverContacted),
		},
		Encryption: adminapi.OverviewEncryption{
			Encrypted: int(o.Encryption.Encrypted), NotEncrypted: int(o.Encryption.NotEncrypted), Partial: int(o.Encryption.Partial),
			NotReported: int(o.Encryption.NotReported),
		},
		Vulnerabilities: adminapi.OverviewVulnerabilities{
			ByHighestSeverity: adminapi.OverviewSeverityBuckets{
				Critical: int(o.Vulnerabilities.ByHighestSeverity.Critical), High: int(o.Vulnerabilities.ByHighestSeverity.High),
				Medium: int(o.Vulnerabilities.ByHighestSeverity.Medium), Low: int(o.Vulnerabilities.ByHighestSeverity.Low),
				Unknown: int(o.Vulnerabilities.ByHighestSeverity.Unknown), None: int(o.Vulnerabilities.ByHighestSeverity.None),
			},
			CriticalHighCves: o.Vulnerabilities.CriticalHighCVEs,
			Top:              make([]adminapi.OverviewTopCVE, len(o.Vulnerabilities.Top)),
		},
		Updates: adminapi.OverviewUpdates{
			SecurityOverdue: o.Updates.SecurityOverdue, RebootRequired: o.Updates.RebootRequired,
			Agent: adminapi.OverviewAgent{
				CurrentVersion: o.Updates.CurrentVersion, OnCurrent: o.Updates.OnCurrent, Outdated: o.Updates.Outdated, Ahead: o.Updates.Ahead,
				Unknown: o.Updates.Unknown, LatestPublished: o.Updates.LatestPublished,
			},
			OsReleases: make([]adminapi.OverviewOSRelease, len(o.Updates.OSReleases)),
		},
		Attention: adminapi.OverviewAttention{Conditions: int(o.Attention.Conditions), Devices: int(o.Attention.Devices)},
	}
	for i, c := range o.Vulnerabilities.Top {
		out.Vulnerabilities.Top[i] = adminapi.OverviewTopCVE{Cve: c.CVE, Severity: adminapi.Severity(c.Severity), Devices: c.Devices, Packages: c.Packages}
	}
	if r := o.Updates.Rollout; r != nil {
		out.Updates.Agent.Rollout = &struct {
			Percent int    `json:"percent"`
			Version string `json:"version"`
			Wave    int    `json:"wave"`
			Waves   int    `json:"waves"`
		}{Percent: r.Percent, Version: r.Version, Wave: r.Wave, Waves: r.Waves}
	}
	for i, r := range o.Updates.OSReleases {
		out.Updates.OsReleases[i] = adminapi.OverviewOSRelease{Release: r.Release, Devices: int(r.Devices)}
	}
	return adminapi.GetOverview200JSONResponse(out), nil
}
