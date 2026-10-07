package app

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/problem"
)

// Inventory are the read use cases of the organization's inventory and vulnerabilities (plan M5a decision 9); reads
// are not audited.
type Inventory struct {
	org *db.OrgPool
}

// NewInventory creates the use cases.
func NewInventory(org *db.OrgPool) *Inventory { return &Inventory{org: org} }

// SoftwareQuery selects a page of the organization's software; HasVulnerabilities filters by matched CVEs.
type SoftwareQuery struct {
	Page               ListPage
	HasVulnerabilities *bool
}

// VulnerabilityQuery selects a page of vulnerabilities; Severities are critical, high, medium, low or unknown.
type VulnerabilityQuery struct {
	Page       ListPage
	Severities []string
}

// cvePattern is a CVE ID as the API accepts it.
var cvePattern = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,19}$`)

// DeviceSoftware returns a page of the packages installed on a device; a missing or foreign device is not_found.
func (i *Inventory) DeviceSoftware(ctx context.Context, device uuid.UUID, page ListPage) (Listed[pgstore.ListDeviceSoftwareRow], error) {
	var out Listed[pgstore.ListDeviceSoftwareRow]
	err := i.inOrgDevice(ctx, device, func(ctx context.Context, q *pgstore.Queries) error {
		n, err := q.CountDeviceSoftware(ctx, pgstore.CountDeviceSoftwareParams{DeviceID: device, QPattern: page.QPattern, CountLimit: countLimit})
		if err != nil {
			return fmt.Errorf("count device software: %w", err)
		}
		out.Count = int(n)
		out.Items, err = q.ListDeviceSoftware(ctx, pgstore.ListDeviceSoftwareParams{
			DeviceID: device, QPattern: page.QPattern, Sort: page.Sort, SkipRows: page.Offset, MaxRows: page.Limit,
		})
		return err
	})
	return out, err
}

// DeviceVulnerabilities returns a page of the vulnerability findings of a device; a missing or foreign device is
// not_found.
func (i *Inventory) DeviceVulnerabilities(ctx context.Context, device uuid.UUID, query VulnerabilityQuery) (Listed[pgstore.ListDeviceVulnerabilitiesRow], error) {
	var out Listed[pgstore.ListDeviceVulnerabilitiesRow]
	page := query.Page
	err := i.inOrgDevice(ctx, device, func(ctx context.Context, q *pgstore.Queries) error {
		n, err := q.CountDeviceVulnerabilities(ctx, pgstore.CountDeviceVulnerabilitiesParams{
			DeviceID: device, QPattern: page.QPattern, Severities: query.Severities, CountLimit: countLimit,
		})
		if err != nil {
			return fmt.Errorf("count device vulnerabilities: %w", err)
		}
		out.Count = int(n)
		out.Items, err = q.ListDeviceVulnerabilities(ctx, pgstore.ListDeviceVulnerabilitiesParams{
			DeviceID: device, QPattern: page.QPattern, Severities: query.Severities, Sort: page.Sort,
			SkipRows: page.Offset, MaxRows: page.Limit,
		})
		return err
	})
	return out, err
}

// Software returns a page of the organization's software per name and version with the number of devices.
func (i *Inventory) Software(ctx context.Context, query SoftwareQuery) (Listed[pgstore.ListSoftwareRow], error) {
	var out Listed[pgstore.ListSoftwareRow]
	page := query.Page
	err := i.inOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		n, err := q.CountSoftware(ctx, pgstore.CountSoftwareParams{
			QPattern: page.QPattern, HasVulnerabilities: query.HasVulnerabilities, CountLimit: countLimit,
		})
		if err != nil {
			return fmt.Errorf("count software: %w", err)
		}
		out.Count = int(n)
		out.Items, err = q.ListSoftware(ctx, pgstore.ListSoftwareParams{
			QPattern: page.QPattern, HasVulnerabilities: query.HasVulnerabilities, Sort: page.Sort,
			SkipRows: page.Offset, MaxRows: page.Limit,
		})
		return err
	})
	return out, err
}

// Vulnerabilities returns a page of the organization's vulnerabilities per CVE.
func (i *Inventory) Vulnerabilities(ctx context.Context, query VulnerabilityQuery) (Listed[pgstore.ListVulnerabilitiesRow], error) {
	var out Listed[pgstore.ListVulnerabilitiesRow]
	page := query.Page
	err := i.inOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		n, err := q.CountVulnerabilities(ctx, pgstore.CountVulnerabilitiesParams{
			QPattern: page.QPattern, Severities: query.Severities, CountLimit: countLimit,
		})
		if err != nil {
			return fmt.Errorf("count vulnerabilities: %w", err)
		}
		out.Count = int(n)
		out.Items, err = q.ListVulnerabilities(ctx, pgstore.ListVulnerabilitiesParams{
			QPattern: page.QPattern, Severities: query.Severities, Sort: page.Sort, SkipRows: page.Offset, MaxRows: page.Limit,
		})
		return err
	})
	return out, err
}

// VulnerabilityDevices returns a page of the organization's devices with a finding of cve; a CVE without finding in
// the organization is not_found.
func (i *Inventory) VulnerabilityDevices(ctx context.Context, cve string, page ListPage) (Listed[pgstore.ListVulnerabilityDevicesRow], error) {
	var out Listed[pgstore.ListVulnerabilityDevicesRow]
	cve = strings.ToUpper(cve)
	if !cvePattern.MatchString(cve) {
		return out, problem.InvalidRequest.WithDetail("cve must be a CVE ID such as CVE-2024-3094")
	}
	err := i.inOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		all, err := q.CountVulnerabilityDevices(ctx, pgstore.CountVulnerabilityDevicesParams{Cve: cve, CountLimit: 1})
		if err != nil {
			return fmt.Errorf("count vulnerability devices: %w", err)
		}
		if all == 0 {
			return problem.NotFound
		}
		n, err := q.CountVulnerabilityDevices(ctx, pgstore.CountVulnerabilityDevicesParams{Cve: cve, QPattern: page.QPattern, CountLimit: countLimit})
		if err != nil {
			return fmt.Errorf("count vulnerability devices: %w", err)
		}
		out.Count = int(n)
		out.Items, err = q.ListVulnerabilityDevices(ctx, pgstore.ListVulnerabilityDevicesParams{
			Cve: cve, QPattern: page.QPattern, Sort: page.Sort, SkipRows: page.Offset, MaxRows: page.Limit,
		})
		return err
	})
	return out, err
}

// Summary returns the numbers of the dashboard tile (plan M5a decision 10).
func (i *Inventory) Summary(ctx context.Context) (pgstore.VulnerabilitySummaryRow, error) {
	var out pgstore.VulnerabilitySummaryRow
	err := i.inOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		var err error
		out, err = q.VulnerabilitySummary(ctx)
		return err
	})
	return out, err
}

func (i *Inventory) inOrg(ctx context.Context, fn func(ctx context.Context, q *pgstore.Queries) error) error {
	if _, err := RequireOrg(ctx, RolesRead); err != nil {
		return err
	}
	return i.org.InOrg(ctx, fn)
}

// inOrgDevice is inOrg for a device of the organization; RLS hides other organizations' devices (not_found).
func (i *Inventory) inOrgDevice(ctx context.Context, device uuid.UUID, fn func(ctx context.Context, q *pgstore.Queries) error) error {
	return i.inOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		ok, err := q.DeviceExists(ctx, device)
		if err != nil {
			return err
		}
		if !ok {
			return problem.NotFound
		}
		return fn(ctx, q)
	})
}
