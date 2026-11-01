package app

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/problem"
)

// ConfigStatus are the read use cases of the apply status of devices (plan M11 decision 14); reads are not audited.
type ConfigStatus struct {
	org *db.OrgPool
}

// NewConfigStatus creates the use cases.
func NewConfigStatus(org *db.OrgPool) *ConfigStatus { return &ConfigStatus{org: org} }

// ConfigStatusQuery selects a page of resources; Statuses keep rows (or resources) in one of the statuses.
type ConfigStatusQuery struct {
	Page     ListPage
	Statuses []string
}

// BundleQuery selects a page of a device's bundle versions; Outcomes are applied, rejected or none.
type BundleQuery struct {
	Page     ListPage
	Outcomes []string
}

// ResourceType is the type of a resource ID: the prefix before ":" (file, unit) or the whole ID (time, login, sudo,
// updates, inventory, pam-deny-list, watch).
func ResourceType(id string) string {
	t, _, _ := strings.Cut(id, ":")
	return t
}

// DeviceResources returns a page of the apply status of a device's resources; a missing or foreign device is not_found.
func (c *ConfigStatus) DeviceResources(ctx context.Context, device uuid.UUID, query ConfigStatusQuery) (Listed[pgstore.ListDeviceResourceStatusRow], error) {
	var out Listed[pgstore.ListDeviceResourceStatusRow]
	page := query.Page
	err := c.inOrgDevice(ctx, device, func(ctx context.Context, q *pgstore.Queries) error {
		n, err := q.CountDeviceResourceStatusList(ctx, pgstore.CountDeviceResourceStatusListParams{
			DeviceID: device, QPattern: page.QPattern, Statuses: query.Statuses, CountLimit: countLimit,
		})
		if err != nil {
			return fmt.Errorf("count device resource status: %w", err)
		}
		out.Count = int(n)
		out.Items, err = q.ListDeviceResourceStatus(ctx, pgstore.ListDeviceResourceStatusParams{
			DeviceID: device, QPattern: page.QPattern, Statuses: query.Statuses, Sort: page.Sort, SkipRows: page.Offset, MaxRows: page.Limit,
		})
		return err
	})
	return out, err
}

// DeviceBundles returns a page of a device's bundle versions with its report of each; a missing or foreign device is
// not_found.
func (c *ConfigStatus) DeviceBundles(ctx context.Context, device uuid.UUID, query BundleQuery) (Listed[pgstore.ListDeviceBundlesRow], error) {
	var out Listed[pgstore.ListDeviceBundlesRow]
	page := query.Page
	err := c.inOrgDevice(ctx, device, func(ctx context.Context, q *pgstore.Queries) error {
		n, err := q.CountDeviceBundles(ctx, pgstore.CountDeviceBundlesParams{DeviceID: device, QPattern: page.QPattern, Outcomes: query.Outcomes, CountLimit: countLimit})
		if err != nil {
			return fmt.Errorf("count device bundles: %w", err)
		}
		out.Count = int(n)
		out.Items, err = q.ListDeviceBundles(ctx, pgstore.ListDeviceBundlesParams{
			DeviceID: device, QPattern: page.QPattern, Outcomes: query.Outcomes, Sort: page.Sort, SkipRows: page.Offset, MaxRows: page.Limit,
		})
		return err
	})
	return out, err
}

// Fleet returns a page of the organization's resources with the number of active devices per status.
func (c *ConfigStatus) Fleet(ctx context.Context, query ConfigStatusQuery) (Listed[pgstore.ListConfigStatusRow], error) {
	var out Listed[pgstore.ListConfigStatusRow]
	page := query.Page
	if _, err := RequireOrg(ctx, RolesRead); err != nil {
		return out, err
	}
	err := c.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		n, err := q.CountConfigStatus(ctx, pgstore.CountConfigStatusParams{QPattern: page.QPattern, Statuses: query.Statuses, CountLimit: countLimit})
		if err != nil {
			return fmt.Errorf("count config status: %w", err)
		}
		out.Count = int(n)
		out.Items, err = q.ListConfigStatus(ctx, pgstore.ListConfigStatusParams{
			QPattern: page.QPattern, Statuses: query.Statuses, Sort: page.Sort, SkipRows: page.Offset, MaxRows: page.Limit,
		})
		return err
	})
	return out, err
}

// inOrgDevice runs fn for a device of the organization; RLS hides other organizations' devices (not_found).
func (c *ConfigStatus) inOrgDevice(ctx context.Context, device uuid.UUID, fn func(ctx context.Context, q *pgstore.Queries) error) error {
	if _, err := RequireOrg(ctx, RolesRead); err != nil {
		return err
	}
	return c.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
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
