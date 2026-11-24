package worker

import (
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/inventory"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/ports"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/problem"
)

// DefaultInventorySyncInterval is the period of the inventory rounds (plan M5a decision 6).
const DefaultInventorySyncInterval = 5 * time.Minute

// inventoryRetryInterval is how soon a failed settings round is repeated: Fleet may still be starting.
const inventoryRetryInterval = 15 * time.Second

// inventoryFullEvery is how often a sync round reads every host instead of the changed ones even though the
// vulnerability state did not change (a safety net).
const inventoryFullEvery = 12

// binaryEvaluationLag is how long after the worker applied a new agent binary policy a host's evaluation counts (plan
// M5a amendment 2026-11-16, A3): an earlier evaluation may still use the previous definition. Fleet's
// policy_updated_at is when Fleet stored the result, not when the host evaluated: a host that read the previous
// definition before the apply and posts its result more than binaryEvaluationLag later passes the gate with a result of
// the previous definition. That needs a device that already runs a release the previous definition did not list, so it
// is accepted (plan M5a amendment 2026-11-16, review round 1, A10).
const binaryEvaluationLag = 2 * time.Minute

// binaryHashesWarn is the size of the hash set above which the worker warns: Fleet must accept the whole policy query
// (plan M5a amendment 2026-11-16, review round 1, A10).
const binaryHashesWarn = 1000

// inventorySyncLockKey is the advisory lock of the sync round ("padd inv").
const inventorySyncLockKey = 0x7061646420696e76

var metricUnmappedHosts = prometheus.NewGauge(prometheus.GaugeOpts{
	Name: "paddock_inventory_unmapped_hosts",
	Help: "Hosts of the inventory system of the last sync round that map to no device or to more than one; never stored.",
})

var metricHostBindings = prometheus.NewCounterVec(prometheus.CounterOpts{
	Name: "paddock_inventory_host_bindings_total",
	Help: "Decisions on the device tokens that devices reported to name their inventory host, by result (ADR 0057).",
}, []string{"result"})

var metricClaimWatchSuppressed = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Name: "paddock_inventory_claim_watch_suppressed",
	Help: "Re-enrollment claims due but not reported in the last sync round because most watched devices of the binding mode re-enrolled (ADR 0057).",
}, []string{"binding"})

var metricPreviousHosts = prometheus.NewCounterVec(prometheus.CounterOpts{
	Name: "paddock_inventory_previous_hosts_total",
	Help: "Left inventory hosts the sync round handled, by result: removed from Fleet, released because another device uses them, failed or unavailable (ADR 0057).",
}, []string{"result"})

var metricBindingsSuspended = prometheus.NewGauge(prometheus.GaugeOpts{
	Name: "paddock_inventory_bindings_suspended",
	Help: "Inventory host bindings whose bound host the last sync round did not list with the device's hardware UUID (ADR 0057).",
})

var metricFleetSilentSuppressed = prometheus.NewGauge(prometheus.GaugeOpts{
	Name: "paddock_inventory_fleet_silent_suppressed",
	Help: "Devices whose silent fleetd the last sync round held back because no or too few live devices reached the inventory system (plan M5a amendment 2026-11-16 c).",
})

var metricPolicyUnanswered = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Name: "paddock_inventory_policy_unanswered_hosts",
	Help: "Mapped hosts of the last full sync round that evaluated a Paddock policy's current definition without an answer: the query failed there.",
}, []string{"policy"})

// InventorySettings keeps the data minimization settings of the inventory system (fleet.Client).
type InventorySettings interface {
	// EnsureSettings resets drift and returns what it corrected.
	EnsureSettings(ctx context.Context) ([]string, error)
}

// Inventory runs the inventory rounds (plan M5a decisions 2, 6 and 8).
type Inventory struct {
	settings InventorySettings
	source   ports.Inventory
	// binder resolves the device tokens the devices report (ADR 0057); nil resolves none. resolvePerRound bounds its
	// calls per round (inventory.ResolvePerRound; tests lower it).
	binder          ports.InventoryBinder
	resolvePerRound int
	// admin removes the hosts devices left (review round 2); nil removes none. leftPerRound bounds the removals per
	// round (inventory.LeftHostDeletesPerRound; tests lower it).
	admin        ports.InventoryAdmin
	leftPerRound int
	sync         *app.InventorySync
	summary      *app.VulnerabilitySummary
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
	// defined holds, per Paddock policy key, the query text this process last applied and when it first applied that
	// text (owned by RunSync; plan M5a addendum 2026-11-16, review round 2, A13).
	defined map[string]definedPolicy
}

// definedPolicy is a policy's applied query text and when this process first applied it.
type definedPolicy struct {
	query string
	at    time.Time
}

// agentHashes reads the SHA-256 of every published agent artifact (app.InventorySync).
type agentHashes interface {
	PublishedAgentHashes(ctx context.Context) ([]string, error)
}

// NewInventory creates the inventory rounds.
func NewInventory(settings InventorySettings, source ports.Inventory, sync *app.InventorySync, summary *app.VulnerabilitySummary,
	org *db.OrgPool, platform *db.PlatformPool, every time.Duration) *Inventory {
	return &Inventory{settings: settings, source: source, sync: sync, summary: summary, org: org, platform: platform, every: every,
		retry: inventoryRetryInterval, now: time.Now, hashes: sync, resolvePerRound: inventory.ResolvePerRound,
		leftPerRound: inventory.LeftHostDeletesPerRound}
}

// WithBinder makes the sync round resolve the device tokens the devices report through b (ADR 0057).
func (i *Inventory) WithBinder(b ports.InventoryBinder) *Inventory {
	i.binder = b
	return i
}

// WithAdmin makes the sync round remove left inventory hosts through a (plan M5a amendment e, review round 2); nil
// removes none.
func (i *Inventory) WithAdmin(a ports.InventoryAdmin) *Inventory {
	i.admin = a
	return i
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
		ran, err := i.platform.WithLeaderLock(sys, inventorySyncLockKey, i.Round)
		if !ran {
			metricClaimWatchSuppressed.WithLabelValues(inventory.BindingDevice).Set(0)
			metricClaimWatchSuppressed.WithLabelValues(inventory.BindingFirst).Set(0)
			metricBindingsSuspended.Set(0)
			metricFleetSilentSuppressed.Set(0)
		}
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
// reports devices whose agent fleetd finds not running or running from a binary of no published release. A device's
// host is the one the device named over its device connection, else the one the inventory system enrolled first for
// its hardware UUID; other hosts claiming it are reported (ADR 0057).
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
	policies = append(policies, inventory.AgentBinaryPolicy(known))
	if err := i.source.ApplyPolicies(ctx, policies); err != nil {
		return err
	}
	i.noteDefinitions(policies)
	if fp := hashSetPrint(known); fp != i.binaryPrint {
		i.binaryPrint, i.binaryAppliedAt = fp, i.now()
		slog.InfoContext(ctx, "applied the agent binary policy", "hashes", len(known))
		if len(known) > binaryHashesWarn {
			slog.WarnContext(ctx, "the agent binary policy accepts many published hashes; Fleet must accept the whole query",
				"hashes", len(known), "warn_above", binaryHashesWarn)
		}
	}
	vulnState, err := i.source.VulnerabilityState(ctx)
	if err != nil {
		return err
	}
	since := i.since
	if i.rounds%inventoryFullEvery == 0 || vulnState != i.vulnState {
		since = time.Time{}
	}
	hosts, seen, err := i.listHosts(ctx, since)
	if err != nil {
		return err
	}
	// Loaded before the store, so that the claim watch compares with the host stored before this round.
	devices, err := i.sync.InventoryClaimDevices(ctx)
	if err != nil {
		return err
	}
	left, err := i.sync.InventoryLeftHosts(ctx)
	if err != nil {
		return err
	}
	bindings, bound, err := i.bindHosts(ctx, seen, devices, left, start)
	if err != nil {
		return err
	}
	targets := inventory.HostTargets(seen, bindings, devices, left)
	if err := i.recordLeftHosts(ctx, targets.Left, start); err != nil {
		return err
	}
	for host, devs := range targets.Excluded {
		slog.WarnContext(ctx, "inventory host bound to several devices", "host", host, "devices", devs)
	}
	isBound, stored := map[uuid.UUID]bool{}, map[uuid.UUID]ports.HostRef{}
	for _, b := range bindings {
		isBound[b.DeviceID] = b.Host != ""
	}
	for _, d := range devices {
		stored[d.DeviceID] = d.ExternalID
	}
	uuids := make([]string, len(hosts))
	for n, h := range hosts {
		uuids[n] = strings.ToLower(h.HardwareUUID)
	}
	mapped, err := i.sync.MapHosts(ctx, uuids)
	if err != nil {
		return err
	}
	unmapped, ignored, unanswered := 0, 0, map[string]int{}
	for _, h := range hosts {
		dev, outcome := speaksFor(h, targets, mapped, isBound, stored)
		switch outcome {
		case hostUnmapped:
			unmapped++
			continue
		case hostIgnored:
			ignored++
			continue
		}
		inv, err := i.source.HostInventory(ctx, h.Ref)
		if err != nil {
			return err
		}
		stored := inventory.UnansweredAgentRunningAsFailing(inv, i.evaluatedCurrent(inv, inventory.PolicyAgentRunning))
		if err := i.sync.StoreHost(systemContext(ctx, dev.OrganizationID, "inventory-sync"), dev.DeviceID, h.Ref, stored); err != nil {
			return fmt.Errorf("store the inventory of device %s: %w", dev.DeviceID, err)
		}
		i.countUnanswered(inv, unanswered)
	}
	if since.IsZero() {
		metricUnmappedHosts.Set(float64(unmapped))
		i.reportUnanswered(ctx, unanswered)
	}
	claims, err := i.watchClaims(ctx, withBindings(devices, bindings), seen, targets, start)
	if err != nil {
		return err
	}
	if err := i.watchFleet(ctx, seen, targets, start); err != nil {
		return err
	}
	if err := i.removeLeftHosts(ctx, start); err != nil {
		return err
	}
	if err := i.reportAgents(ctx, start); err != nil {
		return err
	}
	if err := i.reportBinaries(ctx, start, known); err != nil {
		return err
	}
	if err := i.summarize(ctx, start); err != nil {
		return err
	}
	i.since, i.vulnState, i.rounds = start.Add(-time.Minute), vulnState, i.rounds+1 // a margin for clocks and in-flight updates
	slog.InfoContext(ctx, "inventory synced", "hosts", len(hosts), "unmapped", unmapped, "ignored", ignored,
		"bound", bound, "claims", claims, "full", since.IsZero())
	return nil
}

// listHosts pages through the host list: the hosts changed since, and every listed host with a hardware UUID.
func (i *Inventory) listHosts(ctx context.Context, since time.Time) ([]ports.InventoryHost, []ports.HostSeen, error) {
	var hosts []ports.InventoryHost
	var seen []ports.HostSeen
	cursor := ""
	for {
		page, err := i.source.ListHostsChangedSince(ctx, since, cursor)
		if err != nil {
			return nil, nil, err
		}
		hosts, seen = append(hosts, page.Hosts...), append(seen, page.Seen...)
		if page.Next == "" {
			return hosts, seen, nil
		}
		cursor = page.Next
	}
}

// Outcomes of speaksFor.
const (
	hostStored = iota
	hostUnmapped
	hostIgnored
)

// speaksFor applies the store rule (ADR 0057, H6; review round 1, F1 and F2): a host is stored for the one device it
// is validly bound to, else for the unbound device its hardware UUID maps to if it is that device's FirstSpeaker. Any
// other host that claims a device's UUID is ignored.
func speaksFor(h ports.InventoryHost, t inventory.Targets, mapped map[string]app.MappedDevice, isBound map[uuid.UUID]bool,
	stored map[uuid.UUID]ports.HostRef) (app.MappedDevice, int) {
	if b, ok := t.Bound[h.Ref]; ok {
		return app.MappedDevice{DeviceID: b.DeviceID, OrganizationID: b.OrganizationID}, hostStored
	}
	if len(t.Excluded[h.Ref]) > 0 {
		return app.MappedDevice{}, hostUnmapped
	}
	u := strings.ToLower(h.HardwareUUID)
	dev, ok := mapped[u]
	_, inUse := t.InUse[h.Ref]
	switch {
	case ok && !isBound[dev.DeviceID] && inventory.FirstSpeaker(dev.DeviceID, u, stored[dev.DeviceID], t) == h.Ref:
		return dev, hostStored
	case ok || t.BindingUUIDs[u] || inUse:
		return app.MappedDevice{}, hostIgnored
	}
	return app.MappedDevice{}, hostUnmapped
}

// withBindings returns the devices with this round's binding decisions and suspensions.
func withBindings(devices []inventory.ClaimDevice, bindings []inventory.Binding) []inventory.ClaimDevice {
	byDevice := map[uuid.UUID]inventory.Binding{}
	for _, b := range bindings {
		byDevice[b.DeviceID] = b
	}
	out := slices.Clone(devices)
	for n, d := range out {
		if b, ok := byDevice[d.DeviceID]; ok {
			out[n].BoundHost, out[n].BoundAt, out[n].SuspendedAt = b.Host, b.BoundAt, b.SuspendedAt
		}
	}
	return out
}

// bindHosts expires old device tokens and decides every pending one (ADR 0057, H5). It returns the bindings as decided
// and the number of devices bound or rebound. A failure of the inventory system keeps the remaining tokens for the next
// round and does not fail it.
func (i *Inventory) bindHosts(ctx context.Context, seen []ports.HostSeen, devices []inventory.ClaimDevice,
	left []inventory.LeftHost, now time.Time) ([]inventory.Binding, int, error) {
	if _, err := i.sync.ExpireFleetDeviceTokens(ctx, now.Add(-inventory.TokenMaxAge)); err != nil {
		return nil, 0, err
	}
	bindings, err := i.sync.InventoryBindings(ctx)
	if err != nil {
		return nil, 0, err
	}
	index := make(map[ports.HostRef]ports.HostSeen, len(seen))
	for _, h := range seen {
		index[h.Ref] = h
	}
	r := inventory.NewestSeen(seen)
	inUse := inventory.HostTargets(seen, bindings, devices, left).InUse
	slices.SortStableFunc(bindings, func(a, b inventory.Binding) int {
		return cmp.Compare(btoi(!a.Urgent(now)), btoi(!b.Urgent(now)))
	})
	calls, unavailable, changed := 0, false, 0
	for n, b := range bindings {
		if b.PendingToken == "" {
			continue
		}
		decision := inventory.DecideBinding(b, index, r, now, nil, uuid.Nil)
		var host ports.HostRef
		if decision == inventory.DecideResolve {
			if i.binder == nil || unavailable || calls >= i.resolvePerRound {
				continue
			}
			calls++
			ref, hw, err := i.binder.ResolveDeviceToken(ctx, b.PendingToken)
			switch {
			case errors.Is(err, problem.NotFound):
				metricHostBindings.WithLabelValues("unknown_token").Inc()
				if err := i.clearToken(ctx, b); err != nil {
					return nil, 0, err
				}
				continue
			case err != nil && ctx.Err() != nil:
				return nil, 0, err
			case err != nil:
				unavailable = true
				metricHostBindings.WithLabelValues("unavailable").Inc()
				slog.WarnContext(ctx, "resolving the device tokens failed; retrying next round", "error", err)
				continue
			}
			host = ref
			decision = inventory.DecideBinding(b, index, r, now, &ports.HostSeen{Ref: ref, HardwareUUID: hw}, inUse[ref])
		}
		attrs := []any{"organization_id", b.OrganizationID, "device_id", b.DeviceID, "host", host}
		switch decision {
		case inventory.DecideBind, inventory.DecideRebind:
			ok, err := i.sync.BindInventoryHost(systemContext(ctx, b.OrganizationID, "inventory-sync"), b.DeviceID,
				*b.TokenReportedAt, host, now)
			if err != nil {
				return nil, 0, err
			}
			if !ok {
				continue
			}
			if decision == inventory.DecideBind {
				metricHostBindings.WithLabelValues("bound").Inc()
				slog.InfoContext(ctx, "inventory host bound", attrs...)
			} else {
				metricHostBindings.WithLabelValues("rebound").Inc()
				slog.InfoContext(ctx, "inventory host rebound", append(attrs, "previous", b.Host)...)
			}
			bindings[n].Host, bindings[n].BoundAt, bindings[n].SuspendedAt = host, &now, nil
			inUse[host] = b.DeviceID
			changed++
			continue
		case inventory.DecideExpired:
			metricHostBindings.WithLabelValues("expired").Inc()
		case inventory.DecideCurrent:
			metricHostBindings.WithLabelValues("current").Inc()
		case inventory.DecideUUIDMismatch:
			metricHostBindings.WithLabelValues("uuid_mismatch").Inc()
			slog.WarnContext(ctx, "inventory host binding refused", attrs...)
		case inventory.DecideHostInUse:
			// Only the requesting device is named: the device that uses the host belongs to its own organization.
			metricHostBindings.WithLabelValues("host_in_use").Inc()
			slog.WarnContext(ctx, "inventory host binding refused", append(attrs, "reason", "host_in_use")...)
		}
		if err := i.clearToken(ctx, b); err != nil {
			return nil, 0, err
		}
	}
	return bindings, changed, i.suspendBindings(ctx, bindings, index, now)
}

// recordLeftHosts persists this round's relisted stored hosts before the store step, so that a restart cannot release
// them to another device (review round 2).
func (i *Inventory) recordLeftHosts(ctx context.Context, left []inventory.LeftHost, now time.Time) error {
	byOrg := map[uuid.UUID][]inventory.LeftHost{}
	for _, l := range left {
		byOrg[l.OrganizationID] = append(byOrg[l.OrganizationID], l)
	}
	for org, hosts := range byOrg {
		if err := i.sync.RecordLeftInventoryHosts(systemContext(ctx, org, "inventory-sync"), hosts, now); err != nil {
			return fmt.Errorf("organization %s: %w", org, err)
		}
	}
	return nil
}

// removeLeftHosts removes up to LeftHostDeletesPerRound reserved left hosts from the inventory system (review round 2).
// A failing inventory system ends the step without failing the round.
func (i *Inventory) removeLeftHosts(ctx context.Context, now time.Time) error {
	if i.admin == nil {
		return nil
	}
	left, err := i.sync.InventoryLeftHosts(ctx)
	if err != nil {
		return err
	}
	handled := 0
	for _, h := range left {
		if handled == i.leftPerRound {
			return nil
		}
		if !h.OrgActive || h.AttemptedAt != nil && now.Sub(*h.AttemptedAt) < inventory.LeftHostRetryAfter {
			continue
		}
		handled++
		attrs := []any{"organization_id", h.OrganizationID, "device_id", h.DeviceID, "host", h.Host}
		outcome, err := i.sync.RemoveLeftInventoryHost(systemContext(ctx, h.OrganizationID, "inventory-sync"), h, i.admin)
		switch {
		case err == nil && outcome == app.LeftHostInUse:
			metricPreviousHosts.WithLabelValues("in_use").Inc()
			slog.InfoContext(ctx, "inventory left host released", attrs...)
		case err == nil:
			metricPreviousHosts.WithLabelValues("removed").Inc()
			slog.InfoContext(ctx, "inventory left host removed", append(attrs, "reason", h.Reason)...)
		case errors.Is(err, problem.InvalidState):
			metricPreviousHosts.WithLabelValues("failed").Inc()
			slog.WarnContext(ctx, "inventory left host not removed", append(attrs, "error", err)...)
		case errors.Is(err, problem.UpstreamUnavailable):
			metricPreviousHosts.WithLabelValues("unavailable").Inc()
			slog.WarnContext(ctx, "removing left inventory hosts failed; retrying next round", "error", err)
			return nil
		case errors.Is(err, problem.NotFound):
		default:
			return err
		}
	}
	return nil
}

// suspendBindings suspends every binding whose bound host is not listed with the device's hardware UUID and resumes
// the others (review round 1, F1); it updates bindings in place and sets the gauge.
func (i *Inventory) suspendBindings(ctx context.Context, bindings []inventory.Binding, index map[ports.HostRef]ports.HostSeen,
	now time.Time) error {
	type change struct{ suspend, resume []uuid.UUID }
	byOrg, suspended := map[uuid.UUID]*change{}, 0
	for n, b := range bindings {
		if b.Host == "" {
			continue
		}
		c := byOrg[b.OrganizationID]
		if c == nil {
			c = &change{}
			byOrg[b.OrganizationID] = c
		}
		switch valid := b.Valid(index); {
		case !valid && b.SuspendedAt == nil:
			c.suspend, bindings[n].SuspendedAt = append(c.suspend, b.DeviceID), &now
		case valid && b.SuspendedAt != nil:
			c.resume, bindings[n].SuspendedAt = append(c.resume, b.DeviceID), nil
		}
		if !b.Valid(index) {
			suspended++
		}
	}
	metricBindingsSuspended.Set(float64(suspended))
	for org, c := range byOrg {
		if len(c.suspend)+len(c.resume) == 0 {
			continue
		}
		if err := i.sync.SuspendInventoryBindings(systemContext(ctx, org, "inventory-sync"), c.suspend, c.resume, now); err != nil {
			return fmt.Errorf("organization %s: %w", org, err)
		}
	}
	return nil
}

func btoi(b bool) int {
	if b {
		return 1
	}
	return 0
}

// clearToken clears a decided token unless a newer one was reported meanwhile.
func (i *Inventory) clearToken(ctx context.Context, b inventory.Binding) error {
	if b.TokenReportedAt == nil {
		return nil
	}
	return i.sync.ClearFleetDeviceToken(systemContext(ctx, b.OrganizationID, "inventory-sync"), b.DeviceID, *b.TokenReportedAt)
}

// watchClaims runs the claim watch (ADR 0057, H7 to H9) and returns the number of claims it reported.
func (i *Inventory) watchClaims(ctx context.Context, devices []inventory.ClaimDevice, seen []ports.HostSeen, t inventory.Targets,
	now time.Time) (int, error) {
	w := inventory.WatchClaims(devices, seen, t, now)
	for _, d := range w.Suspended {
		slog.WarnContext(ctx, "inventory binding suspended", "organization_id", d.OrganizationID, "device_id", d.DeviceID,
			"since", d.SuspendedAt)
	}
	for _, d := range w.Resetting {
		slog.InfoContext(ctx, "inventory claim held: enrollment reset announced", "organization_id", d.OrganizationID,
			"device_id", d.DeviceID)
	}
	var orgs []uuid.UUID
	for _, d := range devices {
		if !slices.Contains(orgs, d.OrganizationID) {
			orgs = append(orgs, d.OrganizationID)
		}
	}
	reported := 0
	for _, org := range orgs {
		part := w.ForOrganization(org, devices)
		if len(part.Enrolled)+len(part.Reenrolled)+len(part.ClaimStart)+len(part.ClaimClear)+len(part.Claims) == 0 {
			continue
		}
		ids, err := i.sync.ApplyClaimWatch(systemContext(ctx, org, "inventory-sync"), part, now)
		if err != nil {
			return reported, fmt.Errorf("organization %s: %w", org, err)
		}
		for _, id := range ids {
			slog.WarnContext(ctx, "another inventory host claims a device", "organization_id", org, "device_id", id)
		}
		reported += len(ids)
	}
	for mode, g := range w.Guard {
		if g.Suppressed {
			slog.WarnContext(ctx, "inventory claim watch suppressed", "reason", "claim_majority", "binding", mode, "due", g.Held,
				"claimed", g.Claimed, "watched", g.Watched)
		}
		metricClaimWatchSuppressed.WithLabelValues(mode).Set(float64(g.Held))
	}
	return reported, nil
}

// watchFleet runs the fleetd silence watch over the round's complete host list (plan M5a amendments 2026-11-16 c and
// d) and sets the gauge to the due devices it held back.
func (i *Inventory) watchFleet(ctx context.Context, seen []ports.HostSeen, t inventory.Targets, now time.Time) error {
	devices, err := i.sync.FleetWatchDevices(ctx)
	if err != nil {
		return err
	}
	w := inventory.WatchFleet(devices, seen, t, now, app.AgentSilence)
	held := 0
	if w.Suppressed != "" {
		held = w.Due
		slog.WarnContext(ctx, "fleet silence watch suppressed", "reason", w.Suppressed, "due", w.Due, "live", w.Live,
			"fresh", w.Fresh)
	}
	metricFleetSilentSuppressed.Set(float64(held))
	var orgs []uuid.UUID
	for _, d := range devices {
		if !slices.Contains(orgs, d.OrganizationID) {
			orgs = append(orgs, d.OrganizationID)
		}
	}
	for _, org := range orgs {
		part := w.ForOrganization(org, devices)
		if len(part.Start)+len(part.Note)+len(part.Reset)+len(part.Clear)+len(part.Report) == 0 {
			continue
		}
		ids, err := i.sync.ApplyFleetWatch(systemContext(ctx, org, "inventory-sync"), part, now)
		if err != nil {
			return fmt.Errorf("organization %s: %w", org, err)
		}
		for _, id := range ids {
			slog.WarnContext(ctx, "fleetd is silent while the device checks in", "organization_id", org, "device_id", id)
		}
	}
	return nil
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
func (i *Inventory) reportBinaries(ctx context.Context, now time.Time, known []string) error {
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
		devices, err := i.sync.ReportAgentBinaryUnknown(systemContext(ctx, org, "inventory-sync"), now, after, len(known))
		if err != nil {
			return fmt.Errorf("organization %s: %w", org, err)
		}
		for _, d := range devices {
			slog.WarnContext(ctx, "fleetd reports an agent binary of no published release", "organization_id", org, "device_id", d)
		}
	}
	return nil
}

// noteDefinitions records when this process first applied each policy's current query text.
func (i *Inventory) noteDefinitions(policies []ports.PolicyDefinition) {
	if i.defined == nil {
		i.defined = map[string]definedPolicy{}
	}
	for _, p := range policies {
		if d, ok := i.defined[p.Key]; !ok || d.query != p.Query {
			i.defined[p.Key] = definedPolicy{query: p.Query, at: i.now()}
		}
	}
}

// countUnanswered counts, per Paddock policy, a host that lists it without an answer although it evaluated its
// policies binaryEvaluationLag or more after the current definition was applied: the query did not run there.
func (i *Inventory) countUnanswered(inv ports.HostInventory, counts map[string]int) {
	if inv.PolicyUpdatedAt == nil {
		return
	}
	for _, key := range inv.UnansweredPolicies {
		if i.evaluatedCurrent(inv, key) {
			counts[key]++
		}
	}
}

// evaluatedCurrent reports whether the host evaluated its policies binaryEvaluationLag or more after this process
// first applied the current definition of the policy key.
func (i *Inventory) evaluatedCurrent(inv ports.HostInventory, key string) bool {
	d, ok := i.defined[key]
	return ok && inv.PolicyUpdatedAt != nil && !inv.PolicyUpdatedAt.Before(d.at.Add(binaryEvaluationLag))
}

// reportUnanswered sets the gauge of every Paddock policy and logs one warning per policy that did not run on some
// host (plan M5a addendum 2026-11-16, review round 2, A13): detection by that policy stops there.
func (i *Inventory) reportUnanswered(ctx context.Context, counts map[string]int) {
	for key := range i.defined {
		metricPolicyUnanswered.WithLabelValues(key).Set(float64(counts[key]))
		if counts[key] > 0 {
			slog.WarnContext(ctx, "a Paddock policy did not run on hosts that evaluated it", "policy", key, "hosts", counts[key])
		}
	}
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
