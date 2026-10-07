package compiler

import (
	"context"

	"github.com/phischl/paddock-mdm/pkg/bundle"
	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
)

// fleetdArch is the only architecture fleetd is packaged for (plan M5a decision 3).
const fleetdArch = "amd64"

// inventory returns the inventory section of v2 bundles (plan M5a decision 4): Fleet's public URL, the global enroll
// secret and the fleetd package of the newest published release that has one. Without Fleet configuration or without
// a package there is none, and devices leave fleetd as it is.
func (c *Compiler) inventory(ctx context.Context, q *pgstore.Queries) (*bundle.Inventory, error) {
	if c.cfg.FleetURL == "" || c.cfg.FleetEnrollSecret == "" {
		return nil, nil
	}
	rows, err := q.FleetdPackage(ctx, fleetdArch)
	if err != nil || len(rows) == 0 {
		return nil, err
	}
	return &bundle.Inventory{
		FleetURL: c.cfg.FleetURL, EnrollSecret: c.cfg.FleetEnrollSecret,
		Package: bundle.InventoryPackage{Version: rows[0].PackageVersion, URLPath: rows[0].ObjectKey, SHA256: rows[0].Sha256},
	}, nil
}
