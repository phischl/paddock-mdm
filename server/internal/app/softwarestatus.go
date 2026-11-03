package app

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/domain/software"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/problem"
)

// The states the server derives for a targeted entry that has no reported row (ADR 0028): the device has no package
// for it, or its report has not arrived yet. They are computed per request and never stored.
const (
	SoftwareStateNotApplicable = "not_applicable"
	SoftwareStateUnknown       = "unknown"
)

// SoftwareStatus are the read use cases of what devices report about the catalog's applications (plan M13a §3.4);
// reads are not audited.
type SoftwareStatus struct {
	org *db.OrgPool
}

// NewSoftwareStatus creates the use cases.
func NewSoftwareStatus(org *db.OrgPool) *SoftwareStatus { return &SoftwareStatus{org: org} }

// DeviceManagedSoftwareQuery selects a page of a device's managed software; State is a reported or derived state.
type DeviceManagedSoftwareQuery struct {
	Page   ListPage
	State  *string
	Intent *string
}

// DeviceManagedSoftware is one entry as a device sees it. ReportedAt is nil for a derived state.
type DeviceManagedSoftware struct {
	CatalogEntryID uuid.UUID
	Name           string
	Package        string
	Intent         string
	State          string
	Version        string
	Reason         string
	Error          string
	ReportedAt     *time.Time
}

// ManagedSoftwarePage is a page of a device's managed software. Truncated says that the device's last report left items
// out to keep the check-in small, so an entry without a row may be managed all the same.
type ManagedSoftwarePage struct {
	Listed[DeviceManagedSoftware]
	Truncated bool
}

// DeviceManagedSoftware returns one page of the software a device manages: the entries assigned to it and the rows it
// reported. A missing or foreign device is not_found.
func (s *SoftwareStatus) DeviceManagedSoftware(ctx context.Context, deviceID uuid.UUID, query DeviceManagedSoftwareQuery) (ManagedSoftwarePage, error) {
	var out ManagedSoftwarePage
	if _, err := RequireOrg(ctx, RolesRead); err != nil {
		return out, err
	}
	var all []DeviceManagedSoftware
	err := s.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		ok, err := q.DeviceExists(ctx, deviceID)
		if err != nil {
			return err
		}
		if !ok {
			return problem.NotFound
		}
		target, err := q.GetDeviceSoftwareTarget(ctx, deviceID)
		if err != nil {
			return fmt.Errorf("read the platform of the device: %w", err)
		}
		out.Truncated = target.Truncated
		rows, err := q.ListDeviceManagedSoftware(ctx, pgstore.ListDeviceManagedSoftwareParams{DeviceID: deviceID, QPattern: query.Page.QPattern})
		if err != nil {
			return fmt.Errorf("list the software of the device: %w", err)
		}
		for _, r := range rows {
			item := DeviceManagedSoftware{CatalogEntryID: r.CatalogEntryID, Name: r.Name, Package: r.Package, Intent: r.Intent,
				State: r.State, Version: r.Version, Reason: r.Reason, Error: r.Error, ReportedAt: r.ReportedAt}
			if r.State == "" {
				item.State, item.Package = derivedSoftwareState(r.Packages, target.OsID, target.OsVersionID, target.Arch)
				item.Intent = strongestIntent(r.Intents)
			}
			if (query.State == nil || *query.State == item.State) && (query.Intent == nil || *query.Intent == item.Intent) {
				all = append(all, item)
			}
		}
		return nil
	})
	if err != nil {
		return out, err
	}
	sortManaged(all, query.Page.Sort)
	out.Count = min(len(all), countLimit)
	from := min(int(query.Page.Offset), len(all))
	out.Items = all[from:min(from+int(query.Page.Limit), len(all))]
	return out, nil
}

// SoftwareCatalogDeviceQuery selects a page of the devices an entry is assigned to; q matches the hostname.
type SoftwareCatalogDeviceQuery struct {
	Page          ListPage
	State         *string
	DeviceGroupID *uuid.UUID
}

// SoftwareCatalogDevice is one device an entry is assigned to, with what it reported or the derived state.
type SoftwareCatalogDevice struct {
	DeviceID       uuid.UUID
	Hostname       string
	Name           string
	DeviceGroupIDs []uuid.UUID
	Package        string
	Intent         string
	State          string
	Version        string
	Reason         string
	Error          string
	ReportedAt     *time.Time
}

// CatalogDevices returns one page of the active devices the catalog entry is assigned to. A missing or foreign entry is
// not_found.
func (s *SoftwareStatus) CatalogDevices(ctx context.Context, entryID uuid.UUID, query SoftwareCatalogDeviceQuery) (Listed[SoftwareCatalogDevice], error) {
	var out Listed[SoftwareCatalogDevice]
	if _, err := RequireOrg(ctx, RolesRead); err != nil {
		return out, err
	}
	var all []SoftwareCatalogDevice
	err := s.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		entry, err := q.GetSoftwareCatalogEntry(ctx, entryID)
		if err != nil {
			return notFound(err)
		}
		rows, err := q.ListSoftwareCatalogDevices(ctx, pgstore.ListSoftwareCatalogDevicesParams{
			CatalogEntryID: entryID, DeviceGroupID: nullID(query.DeviceGroupID), QPattern: query.Page.QPattern,
		})
		if err != nil {
			return fmt.Errorf("list the devices of software catalog entry %s: %w", entryID, err)
		}
		refs, decodeErr := software.DecodePackages(entry.Packages)
		for _, r := range rows {
			item := SoftwareCatalogDevice{DeviceID: r.DeviceID, Hostname: r.Hostname, Name: r.Name,
				DeviceGroupIDs: groupIDsOrEmpty(r.DeviceGroupIds), Package: r.Package, Intent: r.Intent,
				State: r.State, Version: r.Version, Reason: r.Reason, Error: r.Error, ReportedAt: r.ReportedAt}
			if r.State == "" {
				item.State, item.Package = derivedFromRefs(refs, decodeErr, r.OsID, r.OsVersionID, r.Arch)
				item.Intent = strongestIntent(r.Intents)
			}
			if query.State == nil || *query.State == item.State {
				all = append(all, item)
			}
		}
		return nil
	})
	if err != nil {
		return out, err
	}
	sortCatalogDevices(all, query.Page.Sort)
	out.Count = min(len(all), countLimit)
	from := min(int(query.Page.Offset), len(all))
	out.Items = all[from:min(from+int(query.Page.Limit), len(all))]
	return out, nil
}

// groupIDsOrEmpty keeps the JSON of a device without groups an empty array instead of null.
func groupIDsOrEmpty(ids []uuid.UUID) []uuid.UUID {
	if ids == nil {
		return []uuid.UUID{}
	}
	return ids
}

// derivedSoftwareState is the state of a targeted entry without a reported row: not_applicable when it names no package
// for the platform, otherwise unknown with the package the device is to get. An entry whose packages cannot be read
// is unknown: the compiler refuses it, the status cannot tell more.
func derivedSoftwareState(packages json.RawMessage, osID, versionID, arch string) (state, pkg string) {
	refs, err := software.DecodePackages(packages)
	return derivedFromRefs(refs, err, osID, versionID, arch)
}

// derivedFromRefs is derivedSoftwareState for packages decoded once (err: the decoding failed).
func derivedFromRefs(refs []software.PackageRef, err error, osID, versionID, arch string) (state, pkg string) {
	if err != nil {
		return SoftwareStateUnknown, ""
	}
	pkg, ok := software.Resolve(refs, osID, versionID, arch)
	if !ok {
		return SoftwareStateNotApplicable, ""
	}
	return SoftwareStateUnknown, pkg
}

// strongestIntent is the intent that wins among the assignments of one entry on a device, in the order of
// software.MergeIntents: forbid, uninstall, required, hold.
func strongestIntent(intents []string) string {
	for _, intent := range []string{software.IntentForbid, software.IntentUninstall, software.IntentRequired, software.IntentHold} {
		if slices.Contains(intents, intent) {
			return intent
		}
	}
	return ""
}

// sortManaged orders items, which arrive in the database's name order, by sort; equal keys keep that order, so the name
// is the tie-breaker as the collation of the other lists orders it. A derived state has no report time: it sorts after
// the reported ones ascending and before them descending, as NULLs do in the database.
func sortManaged(items []DeviceManagedSoftware, sort string) {
	field, desc := strings.TrimPrefix(sort, "-"), strings.HasPrefix(sort, "-")
	switch field {
	case "name":
		if desc {
			slices.Reverse(items)
		}
	case "state":
		slices.SortStableFunc(items, func(a, b DeviceManagedSoftware) int { return compareOrdered(a.State, b.State, desc) })
	default:
		slices.SortStableFunc(items, func(a, b DeviceManagedSoftware) int { return compareTimes(a.ReportedAt, b.ReportedAt, desc) })
	}
}

// sortCatalogDevices is sortManaged for the devices of an entry, which arrive in hostname order.
func sortCatalogDevices(items []SoftwareCatalogDevice, sort string) {
	field, desc := strings.TrimPrefix(sort, "-"), strings.HasPrefix(sort, "-")
	switch field {
	case "hostname":
		if desc {
			slices.Reverse(items)
		}
	case "state":
		slices.SortStableFunc(items, func(a, b SoftwareCatalogDevice) int { return compareOrdered(a.State, b.State, desc) })
	default:
		slices.SortStableFunc(items, func(a, b SoftwareCatalogDevice) int { return compareTimes(a.ReportedAt, b.ReportedAt, desc) })
	}
}

func compareOrdered(a, b string, desc bool) int {
	if desc {
		return strings.Compare(b, a)
	}
	return strings.Compare(a, b)
}

func compareTimes(a, b *time.Time, desc bool) int {
	var c int
	switch {
	case a == nil && b == nil:
		return 0
	case a == nil:
		c = 1
	case b == nil:
		c = -1
	default:
		c = a.Compare(*b)
	}
	if desc {
		return -c
	}
	return c
}
