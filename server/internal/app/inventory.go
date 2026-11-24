package app

import (
	"context"
	"errors"
	"math"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
	"github.com/phischl/paddock-mdm/server/internal/inventory"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/ports"
	"github.com/phischl/paddock-mdm/server/internal/problem"
)

// AgentSilence is how long a device must have been without check-in before a failing agent-running policy is reported
// (plan M5a decision 8): a running agent checks in every few minutes. The contact state "unseen" of
// paddock_device_contact (migration 00049) uses the same 15 minutes as an SQL literal; change both together.
const AgentSilence = 15 * time.Minute

// AgentAbsence is how far apart two failing evaluations of the agent-running policy must be for a report while the
// device keeps checking in (plan M5a decision 8 as amended 2026-11-16 b): a genuine agent is absent that long only
// when it does not check in either. Independent of AgentSilence, which the contact state shares.
const AgentAbsence = 15 * time.Minute

// InventorySync stores the inventory system's data of mapped devices (plan M5a decisions 6 to 8).
type InventorySync struct {
	runner   *ActionRunner
	org      *db.OrgPool
	platform *db.PlatformPool
}

// NewInventorySync creates the use cases.
func NewInventorySync(runner *ActionRunner, org *db.OrgPool, platform *db.PlatformPool) *InventorySync {
	return &InventorySync{runner: runner, org: org, platform: platform}
}

// MappedDevice is the device a host belongs to.
type MappedDevice struct {
	DeviceID, OrganizationID uuid.UUID
}

// MapHosts maps hardware UUIDs to devices across organizations: a UUID maps only if exactly one active or quarantined
// device has it (case-insensitive) and no retired device still holds it (ADR 0057 decision 4). Unknown and ambiguous
// UUIDs are missing from the result.
func (s *InventorySync) MapHosts(ctx context.Context, uuids []string) (map[string]MappedDevice, error) {
	out := map[string]MappedDevice{}
	err := s.platform.InPlatform(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		rows, err := q.InventoryDevices(ctx, uuids)
		for _, r := range rows {
			out[r.HardwareUuid] = MappedDevice{DeviceID: r.DeviceID, OrganizationID: r.OrganizationID}
		}
		return err
	})
	return out, err
}

// StoreHost replaces the stored inventory of a device of the organization in ctx in one transaction: reference,
// software, vulnerability findings (enriched with Ubuntu's data) and policy results; rows the host no longer reports
// are deleted.
func (s *InventorySync) StoreHost(ctx context.Context, device uuid.UUID, ref ports.HostRef, inv ports.HostInventory) error {
	return s.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		org := mustOrg(ctx)
		// The previous host is reserved before the reference moves, so that a restart cannot lose it (review round 2).
		if err := q.RecordReplacedInventoryHost(ctx, pgstore.RecordReplacedInventoryHostParams{DeviceID: device,
			ExternalID: string(ref)}); err != nil {
			return err
		}
		if err := q.ForgetLeftInventoryHost(ctx, pgstore.ForgetLeftInventoryHostParams{DeviceID: device, HostID: string(ref)}); err != nil {
			return err
		}
		if err := q.UpsertInventoryRef(ctx, pgstore.UpsertInventoryRefParams{
			DeviceID: device, OrganizationID: org, ExternalID: string(ref), LastSeenAt: inv.LastSeenAt,
			OsVersion: inv.OSVersion, FleetdVersion: inv.AgentVersion,
			HardwareVendor: inv.Hardware.Vendor, HardwareModel: inv.Hardware.Model, HardwareSerial: inv.Hardware.Serial,
			CpuBrand: inv.Hardware.CPUBrand, CpuCores: int32(min(inv.Hardware.CPUCores, math.MaxInt32)), //nolint:gosec // bounded
			MemoryBytes: inv.Hardware.MemoryBytes, DiskTotalBytes: inv.Hardware.DiskTotalBytes,
			PolicyUpdatedAt: inv.PolicyUpdatedAt,
		}); err != nil {
			return err
		}
		sw, findings := flatten(inv.Software)
		if err := q.InsertInstalledSoftware(ctx, pgstore.InsertInstalledSoftwareParams{
			DeviceID: device, OrganizationID: org, Names: sw.names, Versions: sw.versions, Sources: sw.sources,
		}); err != nil {
			return err
		}
		if err := q.DeleteMissingSoftware(ctx, pgstore.DeleteMissingSoftwareParams{
			DeviceID: device, Names: sw.names, Versions: sw.versions, Sources: sw.sources,
		}); err != nil {
			return err
		}
		if err := q.UpsertVulnerabilityFindings(ctx, pgstore.UpsertVulnerabilityFindingsParams{
			DeviceID: device, OrganizationID: org, Cves: findings.cves, Names: findings.names, Versions: findings.versions,
			Cvss: findings.cvss, Severities: findings.severities, Fixed: findings.fixed,
		}); err != nil {
			return err
		}
		if err := q.DeleteMissingFindings(ctx, pgstore.DeleteMissingFindingsParams{
			DeviceID: device, Cves: findings.cves, Names: findings.names, Versions: findings.versions,
		}); err != nil {
			return err
		}
		// Ubuntu's data replaces what the inventory system reports in the same transaction (plan M5c decision 2).
		if _, err := q.EnrichFindings(ctx, uuid.NullUUID{UUID: device, Valid: true}); err != nil {
			return err
		}
		keys := []string{}
		for _, p := range inv.Policies {
			keys = append(keys, p.Key)
			if err := q.UpsertPolicyResult(ctx, pgstore.UpsertPolicyResultParams{
				DeviceID: device, OrganizationID: org, PolicyKey: p.Key, Passing: p.Passing,
				EvaluatedAt: inv.PolicyUpdatedAt,
			}); err != nil {
				return err
			}
		}
		// Not nil: a NULL array would keep every reported row.
		unanswered := append([]string{}, inv.UnansweredPolicies...)
		return q.DeleteMissingPolicyResults(ctx, pgstore.DeleteMissingPolicyResultsParams{
			DeviceID: device, Keys: keys, Unanswered: unanswered,
		})
	})
}

// softwareColumns and findingColumns are the parallel arrays of the bulk statements.
type softwareColumns struct{ names, versions, sources []string }

type findingColumns struct {
	cves, names, versions, severities, fixed []string
	cvss                                     []float64
}

// flatten turns the host's software into deduplicated rows; an unknown CVSS score is -1.
func flatten(software []ports.SoftwarePackage) (softwareColumns, findingColumns) {
	sw := softwareColumns{names: []string{}, versions: []string{}, sources: []string{}}
	f := findingColumns{cves: []string{}, names: []string{}, versions: []string{}, severities: []string{}, fixed: []string{}, cvss: []float64{}}
	seenSW, seenF := map[[3]string]bool{}, map[[3]string]bool{}
	for _, p := range software {
		if k := [3]string{p.Name, p.Version, p.Source}; !seenSW[k] {
			seenSW[k] = true
			sw.names, sw.versions, sw.sources = append(sw.names, p.Name), append(sw.versions, p.Version), append(sw.sources, p.Source)
		}
		for _, v := range p.Vulnerabilities {
			cve := strings.ToUpper(strings.TrimSpace(v.CVE))
			k := [3]string{cve, p.Name, p.Version}
			if cve == "" || seenF[k] {
				continue
			}
			seenF[k] = true
			score := -1.0
			if v.CVSSScore != nil && *v.CVSSScore >= 0 && *v.CVSSScore <= 10 {
				score = *v.CVSSScore
			}
			f.cves, f.names, f.versions = append(f.cves, cve), append(f.names, p.Name), append(f.versions, p.Version)
			f.cvss, f.severities, f.fixed = append(f.cvss, score), append(f.severities, inventory.Severity(v.CVSSScore)), append(f.fixed, v.FixedVersion)
		}
	}
	return sw, f
}

// ReportAgentNotRunning records device.tamper_agent_not_running for every active device of the organization in ctx
// whose agent-running policy fails (the mutual watch, plan M5a decision 8 as amended 2026-11-16 b) and that either
// has not checked in for AgentSilence, or whose policy failed in evaluations at least AgentAbsence apart in the
// inventory system's clock although the device may keep checking in. A device whose inventory host was enrolled again
// within inventory.ClaimQuiet waits (ADR 0057, H8). It reports once per failure: the event and the
// mark are one transaction. It returns the reported devices.
func (s *InventorySync) ReportAgentNotRunning(ctx context.Context, now time.Time) ([]uuid.UUID, error) {
	var rows []pgstore.ListAgentNotRunningRow
	err := s.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		var err error
		rows, err = q.ListAgentNotRunning(ctx, pgstore.ListAgentNotRunningParams{
			PolicyKey: inventory.PolicyAgentRunning, Before: now.Add(-AgentSilence),
			AbsentForS: AgentAbsence.Seconds(), HeldBefore: now.Add(-inventory.ClaimQuiet),
		})
		return err
	})
	if err != nil {
		return nil, err
	}
	var reported []uuid.UUID
	for _, r := range rows {
		params := map[string]any{"policy": inventory.PolicyAgentRunning}
		if r.LastContactAt != nil {
			params["last_contact_at"] = audit.Timestamp(*r.LastContactAt).Format(time.RFC3339Nano)
		}
		if r.FailingSince != nil {
			params["failing_since"] = audit.Timestamp(*r.FailingSince).Format(time.RFC3339Nano)
		}
		if r.EvaluatedAt != nil {
			params["evaluated_at"] = audit.Timestamp(*r.EvaluatedAt).Format(time.RFC3339Nano)
		}
		spec := ActionSpec{
			Code: audit.CodeDeviceTamperAgentNotRunning, Target: &audit.Target{Type: "device", ID: r.DeviceID.String()},
			Params: params,
		}
		err := s.runner.RunTx(ctx, ScopeOrg, spec, func(ctx context.Context, q *pgstore.Queries, rec Recorder) error {
			if err := q.MarkAgentNotRunningReported(ctx, pgstore.MarkAgentNotRunningReportedParams{
				DeviceID: r.DeviceID, PolicyKey: inventory.PolicyAgentRunning,
			}); err != nil {
				return err
			}
			org, err := orgOf(ctx)
			if err != nil {
				return err
			}
			return UpsertTamperFinding(ctx, q, org, r.DeviceID, audit.CodeDeviceTamperAgentNotRunning, "", rec.ActionID(), now)
		})
		if err != nil {
			return reported, err
		}
		reported = append(reported, r.DeviceID)
	}
	return reported, nil
}

// PublishedAgentHashes returns the SHA-256 of every artifact of every published agent release, all architectures:
// the hash set of the agent binary policy (plan M5a amendment 2026-11-16, A2).
func (s *InventorySync) PublishedAgentHashes(ctx context.Context) ([]string, error) {
	var hashes []string
	err := s.platform.InPlatform(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		var err error
		hashes, err = q.ListPublishedAgentHashes(ctx)
		return err
	})
	return hashes, err
}

// ReportAgentBinaryUnknown records device.tamper_agent_binary_changed for every active device of the organization in
// ctx whose agent binary policy fails and whose host evaluated its policies at or after evaluatedAfter (plan M5a
// amendment 2026-11-16, A3), once per failure: the event, the mark and the tamper finding are one transaction. There
// is no check-in silence rule, because a replaced agent keeps checking in. knownHashes is the size of the hash set the
// policy accepts. A device whose inventory host was enrolled again within inventory.ClaimQuiet before now waits (ADR
// 0057, H8). It returns the reported devices.
func (s *InventorySync) ReportAgentBinaryUnknown(ctx context.Context, now, evaluatedAfter time.Time, knownHashes int) ([]uuid.UUID, error) {
	var rows []pgstore.ListAgentBinaryUnknownRow
	err := s.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		var err error
		rows, err = q.ListAgentBinaryUnknown(ctx, pgstore.ListAgentBinaryUnknownParams{
			PolicyKey: inventory.PolicyAgentBinaryKnown, EvaluatedAfter: evaluatedAfter,
			HeldBefore: now.Add(-inventory.ClaimQuiet),
		})
		return err
	})
	if err != nil {
		return nil, err
	}
	var reported []uuid.UUID
	for _, r := range rows {
		params := map[string]any{
			"policy":       inventory.PolicyAgentBinaryKnown,
			"evaluated_at": audit.Timestamp(r.EvaluatedAt).Format(time.RFC3339Nano),
			"known_hashes": knownHashes,
		}
		if r.AgentVersion != nil {
			params["agent_version"] = *r.AgentVersion
		}
		spec := ActionSpec{
			Code: audit.CodeDeviceTamperAgentBinaryChanged, Target: &audit.Target{Type: "device", ID: r.DeviceID.String()},
			Params: params,
		}
		err := s.runner.RunTx(ctx, ScopeOrg, spec, func(ctx context.Context, q *pgstore.Queries, rec Recorder) error {
			if err := q.MarkAgentNotRunningReported(ctx, pgstore.MarkAgentNotRunningReportedParams{
				DeviceID: r.DeviceID, PolicyKey: inventory.PolicyAgentBinaryKnown,
			}); err != nil {
				return err
			}
			org, err := orgOf(ctx)
			if err != nil {
				return err
			}
			return UpsertTamperFinding(ctx, q, org, r.DeviceID, audit.CodeDeviceTamperAgentBinaryChanged, "", rec.ActionID(), r.EvaluatedAt)
		})
		if err != nil {
			return reported, err
		}
		reported = append(reported, r.DeviceID)
	}
	return reported, nil
}

// nullTime turns the 'epoch' that the binding queries return for NULL back into nil.
func nullTime(t time.Time) *time.Time {
	if t.Unix() == 0 {
		return nil
	}
	return &t
}

// InventoryBindings returns the bindings of the active and quarantined devices across organizations (platform), oldest
// pending token first (ADR 0057, H5).
func (s *InventorySync) InventoryBindings(ctx context.Context) ([]inventory.Binding, error) {
	var out []inventory.Binding
	err := s.platform.InPlatform(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		rows, err := q.InventoryBindings(ctx)
		for _, r := range rows {
			out = append(out, inventory.Binding{DeviceID: r.DeviceID, OrganizationID: r.OrganizationID,
				HardwareUUID: r.HardwareUuid, Host: ports.HostRef(r.HostID), PendingToken: r.PendingToken,
				TokenReportedAt: nullTime(r.TokenReportedAt), ResetAnnouncedAt: nullTime(r.ResetAnnouncedAt),
				BoundAt: nullTime(r.BoundAt), SuspendedAt: nullTime(r.SuspendedAt)})
		}
		return err
	})
	return out, err
}

// ExpireFleetDeviceTokens clears every device token reported before before, of devices in any state (platform; ADR
// 0057, H13), and returns how many it cleared.
func (s *InventorySync) ExpireFleetDeviceTokens(ctx context.Context, before time.Time) (int64, error) {
	var n int64
	err := s.platform.InPlatform(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		var err error
		n, err = q.ExpireFleetDeviceTokens(ctx, before)
		return err
	})
	return n, err
}

// BindInventoryHost binds a device of the organization in ctx to host and clears its token, unless a newer token was
// reported after reportedAt; it reports whether it bound.
func (s *InventorySync) BindInventoryHost(ctx context.Context, device uuid.UUID, reportedAt time.Time, host ports.HostRef,
	now time.Time) (bool, error) {
	var n int64
	hostID := string(host)
	err := s.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		var err error
		n, err = q.BindInventoryHost(ctx, pgstore.BindInventoryHostParams{HostID: &hostID, At: now,
			DeviceID: device, TokenReportedAt: reportedAt})
		if err != nil || n == 0 {
			return err
		}
		return q.ForgetLeftInventoryHost(ctx, pgstore.ForgetLeftInventoryHostParams{DeviceID: device, HostID: hostID})
	})
	return n == 1, err
}

// ClearFleetDeviceToken clears the decided token of a device of the organization in ctx, unless a newer token was
// reported after reportedAt.
func (s *InventorySync) ClearFleetDeviceToken(ctx context.Context, device uuid.UUID, reportedAt time.Time) error {
	return s.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		_, err := q.ClearFleetDeviceToken(ctx, pgstore.ClearFleetDeviceTokenParams{DeviceID: device, TokenReportedAt: reportedAt})
		return err
	})
}

// SuspendInventoryBindings suspends the bindings of suspend that are not suspended yet and resumes those of resume, in
// the organization of ctx (review round 1, F1).
func (s *InventorySync) SuspendInventoryBindings(ctx context.Context, suspend, resume []uuid.UUID, now time.Time) error {
	return s.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		if err := q.SuspendInventoryBindings(ctx, pgstore.SuspendInventoryBindingsParams{At: now, DeviceIds: nonNilIDs(suspend)}); err != nil {
			return err
		}
		return q.ResumeInventoryBindings(ctx, nonNilIDs(resume))
	})
}

// InventoryClaimDevices returns the active and quarantined devices with a stored host across organizations (platform;
// ADR 0057, H7).
func (s *InventorySync) InventoryClaimDevices(ctx context.Context) ([]inventory.ClaimDevice, error) {
	var out []inventory.ClaimDevice
	err := s.platform.InPlatform(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		rows, err := q.InventoryClaimDevices(ctx)
		for _, r := range rows {
			out = append(out, inventory.ClaimDevice{DeviceID: r.DeviceID, OrganizationID: r.OrganizationID,
				HardwareUUID: r.HardwareUuid, ExternalID: ports.HostRef(r.ExternalID), BoundHost: ports.HostRef(r.BoundHost),
				ResetAnnouncedAt: nullTime(r.ResetAnnouncedAt), BoundAt: nullTime(r.BoundAt),
				EnrolledAt: nullTime(r.FleetEnrolledAt), ReenrolledAt: nullTime(r.FleetReenrolledAt),
				ClaimSince: nullTime(r.FleetClaimSince), ClaimReportedAt: nullTime(r.FleetClaimReportedAt),
				SuspendedAt: nullTime(r.SuspendedAt), Active: r.Active})
		}
		return err
	})
	return out, err
}

// ApplyClaimWatch applies the organization's part of a claim watch round in one transaction, then records
// device.tamper_fleet_host_claimed with a tamper finding for each claim, once per episode: the mark and the event are one
// transaction, and a claim already marked records nothing. It returns the reported devices.
func (s *InventorySync) ApplyClaimWatch(ctx context.Context, w inventory.ClaimWatch, now time.Time) ([]uuid.UUID, error) {
	err := s.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		for device, at := range w.Enrolled {
			if err := q.SetFleetEnrolledAt(ctx, pgstore.SetFleetEnrolledAtParams{EnrolledAt: at, DeviceID: device}); err != nil {
				return err
			}
		}
		if err := q.MarkFleetReenrolled(ctx, pgstore.MarkFleetReenrolledParams{At: now, DeviceIds: nonNilIDs(w.Reenrolled)}); err != nil {
			return err
		}
		if err := q.StartFleetClaim(ctx, pgstore.StartFleetClaimParams{At: now, DeviceIds: nonNilIDs(w.ClaimStart)}); err != nil {
			return err
		}
		return q.ClearFleetClaim(ctx, nonNilIDs(w.ClaimClear))
	})
	if err != nil {
		return nil, err
	}
	var reported []uuid.UUID
	for _, c := range w.Claims {
		params := map[string]any{"kind": c.Kind, "binding": c.Binding, "bound_host": string(c.Bound), "hosts": c.Hosts,
			"claim_since": audit.Timestamp(c.Since).Format(time.RFC3339Nano)}
		if len(c.Others) > 0 {
			others := make([]string, 0, inventory.ClaimHostsInParam)
			for _, h := range c.Others[:min(len(c.Others), inventory.ClaimHostsInParam)] {
				others = append(others, string(h))
			}
			params["other_hosts"] = strings.Join(others, ",")
		}
		if c.SpeakingEnrolledAt != nil {
			params["enrolled_at"] = audit.Timestamp(*c.SpeakingEnrolledAt).Format(time.RFC3339Nano)
		}
		spec := ActionSpec{Code: audit.CodeDeviceTamperFleetHostClaimed,
			Target: &audit.Target{Type: "device", ID: c.DeviceID.String()}, Params: params}
		device := c.DeviceID
		recorded, err := s.runner.RecordOnce(ctx, spec, func(ctx context.Context, q *pgstore.Queries) (bool, error) {
			n, err := q.MarkFleetClaimReported(ctx, pgstore.MarkFleetClaimReportedParams{At: now, DeviceID: device})
			return n == 1, err
		}, func(ctx context.Context, q *pgstore.Queries, eventID uuid.UUID) error {
			return UpsertTamperFinding(ctx, q, mustOrg(ctx), device, audit.CodeDeviceTamperFleetHostClaimed, "", eventID, now)
		})
		if err != nil {
			return reported, err
		}
		if recorded {
			reported = append(reported, device)
		}
	}
	return reported, nil
}

// FleetWatchDevices reads every active device with an inventory reference across organizations (platform pool; plan
// M5a amendment 2026-11-16 c).
func (s *InventorySync) FleetWatchDevices(ctx context.Context) ([]inventory.WatchedDevice, error) {
	var out []inventory.WatchedDevice
	err := s.platform.InPlatform(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		rows, err := q.FleetWatchDevices(ctx)
		for _, r := range rows {
			out = append(out, inventory.WatchedDevice{DeviceID: r.DeviceID, OrganizationID: r.OrganizationID,
				HardwareUUID: r.HardwareUuid, ExternalID: ports.HostRef(r.ExternalID), BoundHost: ports.HostRef(r.BoundHost),
				LastContactAt: nullTime(r.LastContactAt), LastSeenAt: nullTime(r.LastSeenAt),
				PolicyUpdatedAt: nullTime(r.PolicyUpdatedAt), SilentSince: nullTime(r.FleetSilentSince),
				ReportedAt: nullTime(r.FleetSilentReportedAt)})
		}
		return err
	})
	return out, err
}

// ApplyFleetWatch applies the decisions of w that concern the organization in ctx: Start, Reset and Clear in one
// transaction, then each report as device.tamper_fleetd_silent with a tamper finding, once per silence: the mark and
// the event are one transaction, and a device already marked records nothing. It returns the reported devices.
func (s *InventorySync) ApplyFleetWatch(ctx context.Context, w inventory.FleetWatch, now time.Time) ([]uuid.UUID, error) {
	err := s.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		if err := q.StartFleetSilence(ctx, pgstore.StartFleetSilenceParams{At: now, DeviceIds: nonNilIDs(w.Start)}); err != nil {
			return err
		}
		if err := q.ResetFleetSilence(ctx, nonNilIDs(w.Reset)); err != nil {
			return err
		}
		return q.ClearFleetSilence(ctx, nonNilIDs(w.Clear))
	})
	if err != nil {
		return nil, err
	}
	stamp := func(t *time.Time) string { return audit.Timestamp(*t).Format(time.RFC3339Nano) }
	var reported []uuid.UUID
	for _, d := range w.Report {
		params := map[string]any{"reason": d.Reason, "silent_since": stamp(d.SilentSince)}
		for key, at := range map[string]*time.Time{"fleetd_seen_at": d.FleetdSeenAt,
			"policy_updated_at": d.FleetdPolicyUpdatedAt, "last_contact_at": d.LastContactAt} {
			if at != nil {
				params[key] = stamp(at)
			}
		}
		spec := ActionSpec{Code: audit.CodeDeviceTamperFleetdSilent,
			Target: &audit.Target{Type: "device", ID: d.DeviceID.String()}, Params: params}
		device := d.DeviceID
		recorded, err := s.runner.RecordOnce(ctx, spec, func(ctx context.Context, q *pgstore.Queries) (bool, error) {
			n, err := q.MarkFleetSilentReported(ctx, pgstore.MarkFleetSilentReportedParams{At: now, DeviceID: device})
			return n == 1, err
		}, func(ctx context.Context, q *pgstore.Queries, eventID uuid.UUID) error {
			return UpsertTamperFinding(ctx, q, mustOrg(ctx), device, audit.CodeDeviceTamperFleetdSilent, "", eventID, now)
		})
		if err != nil {
			return reported, err
		}
		if recorded {
			reported = append(reported, device)
		}
	}
	return reported, nil
}

// nonNilIDs keeps a nil slice from becoming a NULL array.
func nonNilIDs(ids []uuid.UUID) []uuid.UUID {
	if ids == nil {
		return []uuid.UUID{}
	}
	return ids
}

// SpecDeviceInventoryHostRemoved records the removal of a left host; system principal only.
var SpecDeviceInventoryHostRemoved = ActionSpec{Code: audit.CodeDeviceInventoryHostRemoved}

// LeftHostOutcome is the result of RemoveLeftInventoryHost.
type LeftHostOutcome int

// Outcomes of RemoveLeftInventoryHost.
const (
	LeftHostRemoved LeftHostOutcome = iota // deleted from the inventory system (or unknown to it)
	LeftHostInUse                          // another device uses it; the reservation was deleted, nothing recorded
)

// InventoryLeftHosts returns the reservations of every organization, oldest first (platform pool).
func (s *InventorySync) InventoryLeftHosts(ctx context.Context) ([]inventory.LeftHost, error) {
	var out []inventory.LeftHost
	err := s.platform.InPlatform(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		rows, err := q.InventoryLeftHosts(ctx)
		for _, r := range rows {
			out = append(out, inventory.LeftHost{DeviceID: r.DeviceID, OrganizationID: r.OrganizationID,
				Host: ports.HostRef(r.HostID), Reason: r.Reason, Hostname: r.Hostname, LeftAt: r.LeftAt,
				AttemptedAt: nullTime(r.AttemptedAt), OrgActive: r.OrgActive})
		}
		return err
	})
	return out, err
}

// RecordLeftInventoryHosts records relisted stored hosts of devices of the organization in ctx as left hosts.
func (s *InventorySync) RecordLeftInventoryHosts(ctx context.Context, hosts []inventory.LeftHost, now time.Time) error {
	return s.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		for _, h := range hosts {
			if err := q.RecordRelistedInventoryHost(ctx, pgstore.RecordRelistedInventoryHostParams{DeviceID: h.DeviceID,
				OrganizationID: h.OrganizationID, HostID: string(h.Host), LeftAt: now}); err != nil {
				return err
			}
		}
		return nil
	})
}

// RemoveLeftInventoryHost removes one reserved left host of a device of the organization in ctx from the inventory
// system, recorded as device.inventory_host_removed, unless another device uses it: then only the reservation goes,
// and nothing is recorded, so that the device's organization does not learn of the other device. It returns
// problem.UpstreamUnavailable or problem.InvalidState from DeleteHost wrapped.
func (s *InventorySync) RemoveLeftInventoryHost(ctx context.Context, h inventory.LeftHost,
	admin ports.InventoryAdmin) (LeftHostOutcome, error) {
	key := pgstore.ForgetLeftInventoryHostParams{DeviceID: h.DeviceID, HostID: string(h.Host)}
	use, err := s.platform.FleetHostInUse(ctx, h.DeviceID, string(h.Host))
	if err != nil {
		return 0, err
	}
	if use == db.FleetHostUsedByRef {
		return LeftHostInUse, s.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
			return q.ForgetLeftInventoryHost(ctx, key)
		})
	}
	spec := SpecDeviceInventoryHostRemoved
	spec.Target = &audit.Target{Type: "device", ID: h.DeviceID.String(), Display: h.Hostname}
	spec.Params = map[string]any{"hostname": h.Hostname, "fleet_host": string(h.Host), "reason": h.Reason,
		"left_at": audit.Timestamp(h.LeftAt).Format(time.RFC3339Nano), "fleet_host_deleted": false}
	err = s.runner.RunExternal(ctx, ScopeOrg, spec, func(ctx context.Context, q *pgstore.Queries, _ Recorder) error {
		if _, err := q.LockLeftInventoryHost(ctx, pgstore.LockLeftInventoryHostParams(key)); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return problem.NotFound
			}
			return err
		}
		return nil
	}, func(ctx context.Context) error {
		ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		return admin.DeleteHost(ctx, h.Host)
	}, func(ctx context.Context, q *pgstore.Queries, rec Recorder, externalErr error) error {
		switch {
		case externalErr == nil:
			rec.SetParam("fleet_host_deleted", true)
			return q.MarkLeftInventoryHostRemoved(ctx, pgstore.MarkLeftInventoryHostRemovedParams(key))
		case errors.Is(externalErr, problem.InvalidState):
			return q.MarkLeftInventoryHostAttempted(ctx, pgstore.MarkLeftInventoryHostAttemptedParams(key))
		}
		return nil
	})
	return LeftHostRemoved, err
}
