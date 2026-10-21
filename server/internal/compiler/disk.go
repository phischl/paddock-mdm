package compiler

import (
	"context"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/pkg/bundle"
	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/domain/disk"
)

// orgDisk is the organization's disk unlock mode, the overrides of its device groups (nil = inherit) and its boot
// PIN length.
type orgDisk struct {
	mode         string
	groups       map[uuid.UUID]*string
	pinMinLength int
}

// loadDisk reads the disk unlock mode and the boot PIN length of the context's organization and its device groups.
func loadDisk(ctx context.Context, q *pgstore.Queries) (*orgDisk, error) {
	s, err := q.GetLoginSettings(ctx)
	if err != nil {
		return nil, err
	}
	groups, err := q.ListAllDeviceGroups(ctx)
	if err != nil {
		return nil, err
	}
	d := &orgDisk{mode: s.DiskUnlockMode, groups: make(map[uuid.UUID]*string, len(groups)), pinMinLength: int(s.BootPinMinLength)}
	for _, g := range groups {
		d.groups[g.ID] = g.DiskUnlockMode
	}
	return d, nil
}

// section is the disk section of a device in groups (plan M8d decision 46): disk.EffectiveUnlockMode over the
// overrides of its groups, and the organization's boot PIN length (plan M8e decision 11).
func (d *orgDisk) section(groups []uuid.UUID) *bundle.DiskSpec {
	var overrides []string
	for _, g := range groups {
		if m := d.groups[g]; m != nil {
			overrides = append(overrides, *m)
		}
	}
	return &bundle.DiskSpec{UnlockMode: disk.EffectiveUnlockMode(d.mode, overrides), BootPINMinLength: d.pinMinLength}
}
