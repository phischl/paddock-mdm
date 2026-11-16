package worker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"

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

// binaryEvaluationLag is how long after the worker applied a new agent binary policy a host's evaluation counts (plan
// M5a amendment 2026-11-16, A3): an earlier evaluation may still use the previous definition.
const binaryEvaluationLag = 2 * time.Minute

// inventorySyncLockKey is the advisory lock of the sync round ("padd inv").
const inventorySyncLockKey = 0x7061646420696e76

var metricUnmappedHosts = prometheus.NewGauge(prometheus.GaugeOpts{
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
	summary  *app.VulnerabilitySummary
	// slaSummary records the daily patch SLA summary (plan M13c decision 18); nil records none.
	slaSummary slaSummarizer
	org        *db.OrgPool
	platform   *db.PlatformPool
	every      time.Duration
	retry      time.Duration
	now        func() time.Time

	// hashes reads the hash set of the agent binary policy.
	hashes agentHashes

	// since is the start of the last complete sync round, vulnState the vulnerability state it stored; rounds counts
	// them (owned by RunSync).
	since     time.Time
	vulnState string
	rounds    int
	// binaryPrint is the fingerprint of the hash set this process last applied, binaryAppliedAt when it applied it
	// (owned by RunSync). A new process starts without one, which only delays reports.
	binaryPrint     string
	binaryAppliedAt time.Time
}

// agentHashes reads the SHA-256 of every published agent artifact (app.InventorySync).
type agentHashes interface {
	PublishedAgentHashes(ctx context.Context) ([]string, error)
}

// NewInventory creates the inventory rounds.
func NewInventory(settings InventorySettings, source ports.Inventory, sync *app.InventorySync, summary *app.VulnerabilitySummary,
	org *db.OrgPool, platform *db.PlatformPool, every time.Duration) *Inventory {
	return &Inventory{settings: settings, source: source, sync: sync, summary: summary, org: org, platform: platform, every: every,
		retry: inventoryRetryInterval, now: time.Now, hashes: sync}
}

// slaSummarizer records the daily patch SLA summary of the organization of ctx (app.VulnerabilitySLASummary).
type slaSummarizer interface {
	Record(ctx context.Context, now time.Time) error
}

// WithSLASummary makes the inventory round also record the daily patch SLA summary of every organization.
func (i *Inventory) WithSLASummary(s slaSummarizer) *Inventory {
	i.slaSummary = s
	return i
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
// reports devices whose agent fleetd finds not running or running from a binary of no published release.
func (i *Inventory) Round(ctx context.Context) error {
	start := i.now()
	policies, err := inventory.Policies()
	if err != nil {
		return err
	}
	raw, err := i.hashes.PublishedAgentHashes(ctx)
	if err != nil {
		return err
	}
	known := inventory.KnownAgentHashes(raw)
	if err := i.source.ApplyPolicies(ctx, append(policies, inventory.AgentBinaryPolicy(known))); err != nil {
		return err
	}
	if fp := hashSetPrint(known); fp != i.binaryPrint {
		i.binaryPrint, i.binaryAppliedAt = fp, i.now()
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
	if err := i.reportBinaries(ctx, known); err != nil {
		return err
	}
	if err := i.summarize(ctx, start); err != nil {
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

// reportBinaries reports, in every organization, the devices whose agent binary policy fails in an evaluation made at
// least binaryEvaluationLag after this process applied the current hash set (plan M5a amendment 2026-11-16, A3). It
// reports nothing for an empty hash set, and nothing when a release was published during the round: the hosts have
// not seen that definition yet, and the next round applies it.
func (i *Inventory) reportBinaries(ctx context.Context, known []string) error {
	if len(known) == 0 {
		return nil
	}
	raw, err := i.hashes.PublishedAgentHashes(ctx)
	if err != nil {
		return err
	}
	if hashSetPrint(inventory.KnownAgentHashes(raw)) != i.binaryPrint {
		slog.InfoContext(ctx, "the published agent releases changed during the inventory round; agent binary reports wait for the next round")
		return nil
	}
	orgs, err := i.org.OrganizationIDs(ctx)
	if err != nil {
		return err
	}
	after := i.binaryAppliedAt.Add(binaryEvaluationLag)
	for _, org := range orgs {
		devices, err := i.sync.ReportAgentBinaryUnknown(systemContext(ctx, org, "inventory-sync"), after, len(known))
		if err != nil {
			return fmt.Errorf("organization %s: %w", org, err)
		}
		for _, d := range devices {
			slog.WarnContext(ctx, "fleetd reports an agent binary of no published release", "organization_id", org, "device_id", d)
		}
	}
	return nil
}

// hashSetPrint is the fingerprint of a sorted hash set: the SHA-256 of its newline-joined hashes.
func hashSetPrint(sorted []string) string {
	sum := sha256.Sum256([]byte(strings.Join(sorted, "\n")))
	return hex.EncodeToString(sum[:])
}

// summarize records the critical CVE summary (plan M9 decision 37) and the patch SLA summary (plan M13c decision 18) of
// every organization.
func (i *Inventory) summarize(ctx context.Context, now time.Time) error {
	orgs, err := i.org.OrganizationIDs(ctx)
	if err != nil {
		return err
	}
	for _, org := range orgs {
		if err := i.summary.Record(systemContext(ctx, org, "inventory-sync"), now); err != nil {
			return fmt.Errorf("vulnerability summary of organization %s: %w", org, err)
		}
		if i.slaSummary == nil {
			continue
		}
		// The patch SLA summary is a notification of its own: one organization's failure must not keep the other
		// organizations' summaries or the round from completing; the next round tries it again.
		if err := i.slaSummary.Record(systemContext(ctx, org, "inventory-sync"), now); err != nil && ctx.Err() == nil {
			slog.WarnContext(ctx, "recording the patch sla summary failed", "organization_id", org, "error", err)
		}
	}
	return nil
}
