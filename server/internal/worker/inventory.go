package worker

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/inventory"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/ports"
	"github.com/phischl/paddock-mdm/server/internal/principal"
)

// DefaultInventorySyncInterval is the period of the inventory rounds (plan M5a decision 6).
const DefaultInventorySyncInterval = 5 * time.Minute

// inventoryRetryInterval is how soon a failed settings round is repeated: Fleet may still be starting.
const inventoryRetryInterval = 15 * time.Second

// inventoryFullEvery is how often a sync round reads every host instead of the changed ones even though the
// vulnerability state did not change (a safety net).
const inventoryFullEvery = 12

// inventorySyncLockKey is the advisory lock of the sync round ("padd inv").
const inventorySyncLockKey = 0x7061646420696e76

var metricUnmappedHosts = promauto.NewGauge(prometheus.GaugeOpts{
	Name: "paddock_inventory_unmapped_hosts",
	Help: "Hosts of the inventory system of the last sync round that map to no device or to more than one; never stored.",
})

// InventorySettings keeps the data minimization settings of the inventory system (fleet.Client).
type InventorySettings interface {
	// EnsureSettings resets drift and returns what it corrected.
	EnsureSettings(ctx context.Context) ([]string, error)
}

// Inventory runs the inventory rounds (plan M5a decisions 2, 6 and 8).
type Inventory struct {
	settings InventorySettings
	source   ports.Inventory
	sync     *app.InventorySync
	org      *db.OrgPool
	platform *db.PlatformPool
	every    time.Duration
	retry    time.Duration
	now      func() time.Time

	// since is the start of the last complete sync round, vulnState the vulnerability state it stored; rounds counts
	// them (owned by RunSync).
	since     time.Time
	vulnState string
	rounds    int
}

// NewInventory creates the inventory rounds.
func NewInventory(settings InventorySettings, source ports.Inventory, sync *app.InventorySync, org *db.OrgPool,
	platform *db.PlatformPool, every time.Duration) *Inventory {
	return &Inventory{settings: settings, source: source, sync: sync, org: org, platform: platform, every: every,
		retry: inventoryRetryInterval, now: time.Now}
}

// RunSettings checks the inventory system's settings at start and then every round until ctx ends; every replica
// does (idempotent). A failure is retried after inventoryRetryInterval.
func (i *Inventory) RunSettings(ctx context.Context) error {
	for {
		wait := i.every
		corrected, err := i.settings.EnsureSettings(ctx)
		switch {
		case err != nil && ctx.Err() == nil:
			slog.WarnContext(ctx, "checking the inventory settings failed", "retry_in", i.retry, "error", err)
			wait = i.retry
		case len(corrected) > 0:
			slog.WarnContext(ctx, "inventory settings drifted; reset", "corrected", corrected)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(wait):
		}
	}
}

// RunSync runs the sync round at start and then every round until ctx ends; only the replica holding the lock acts.
func (i *Inventory) RunSync(ctx context.Context) error {
	tick := time.NewTicker(i.every)
	defer tick.Stop()
	for {
		sys := principal.With(ctx, principal.Principal{Kind: principal.KindSystem, Display: "worker"})
		_, err := i.platform.WithLeaderLock(sys, inventorySyncLockKey, i.Round)
		if err != nil && ctx.Err() == nil {
			slog.WarnContext(ctx, "inventory sync round failed; retrying next round", "error", err)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
		}
	}
}

// Round pushes Paddock's policies, stores the inventory of every changed host that maps to a device — every host
// after a start, when the inventory system's vulnerability matches changed and each inventoryFullEvery rounds — and
// reports devices whose agent fleetd finds not running.
func (i *Inventory) Round(ctx context.Context) error {
	start := i.now()
	policies, err := inventory.Policies()
	if err != nil {
		return err
	}
	if err := i.source.ApplyPolicies(ctx, policies); err != nil {
		return err
	}
	vulnState, err := i.source.VulnerabilityState(ctx)
	if err != nil {
		return err
	}
	since := i.since
	if i.rounds%inventoryFullEvery == 0 || vulnState != i.vulnState {
		since = time.Time{}
	}
	hosts, err := i.changedHosts(ctx, since)
	if err != nil {
		return err
	}
	uuids := make([]string, len(hosts))
	for n, h := range hosts {
		uuids[n] = strings.ToLower(h.HardwareUUID)
	}
	mapped, err := i.sync.MapHosts(ctx, uuids)
	if err != nil {
		return err
	}
	unmapped := 0
	for _, h := range hosts {
		dev, ok := mapped[strings.ToLower(h.HardwareUUID)]
		if !ok {
			unmapped++
			continue
		}
		inv, err := i.source.HostInventory(ctx, h.Ref)
		if err != nil {
			return err
		}
		if err := i.sync.StoreHost(systemContext(ctx, dev.OrganizationID, "inventory-sync"), dev.DeviceID, h.Ref, inv); err != nil {
			return fmt.Errorf("store the inventory of device %s: %w", dev.DeviceID, err)
		}
	}
	if since.IsZero() {
		metricUnmappedHosts.Set(float64(unmapped))
	}
	if err := i.reportAgents(ctx, start); err != nil {
		return err
	}
	i.since, i.vulnState, i.rounds = start.Add(-time.Minute), vulnState, i.rounds+1 // a margin for clocks and in-flight updates
	slog.InfoContext(ctx, "inventory synced", "hosts", len(hosts), "unmapped", unmapped, "full", since.IsZero())
	return nil
}

// changedHosts pages through the hosts changed since.
func (i *Inventory) changedHosts(ctx context.Context, since time.Time) ([]ports.InventoryHost, error) {
	var hosts []ports.InventoryHost
	cursor := ""
	for {
		page, err := i.source.ListHostsChangedSince(ctx, since, cursor)
		if err != nil {
			return nil, err
		}
		hosts = append(hosts, page.Hosts...)
		if page.Next == "" {
			return hosts, nil
		}
		cursor = page.Next
	}
}

// reportAgents runs the mutual watch of every organization.
func (i *Inventory) reportAgents(ctx context.Context, now time.Time) error {
	orgs, err := i.org.OrganizationIDs(ctx)
	if err != nil {
		return err
	}
	for _, org := range orgs {
		devices, err := i.sync.ReportAgentNotRunning(systemContext(ctx, org, "inventory-sync"), now)
		if err != nil {
			return fmt.Errorf("organization %s: %w", org, err)
		}
		for _, d := range devices {
			slog.WarnContext(ctx, "fleetd reports the agent not running", "organization_id", org, "device_id", d)
		}
	}
	return nil
}
