package app

import (
	"context"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
	"github.com/phischl/paddock-mdm/server/internal/inventory"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/ports"
)

// AgentSilence is how long a device must have been without check-in before a failing agent-running policy is reported
// (plan M5a decision 8): a running agent checks in every few minutes.
const AgentSilence = 15 * time.Minute

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
// device has it (case-insensitive). Unknown and ambiguous UUIDs are missing from the result.
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
// software, vulnerability findings and policy results; rows the host no longer reports are deleted.
func (s *InventorySync) StoreHost(ctx context.Context, device uuid.UUID, ref ports.HostRef, inv ports.HostInventory) error {
	return s.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		org := mustOrg(ctx)
		if err := q.UpsertInventoryRef(ctx, pgstore.UpsertInventoryRefParams{
			DeviceID: device, OrganizationID: org, ExternalID: string(ref), LastSeenAt: inv.LastSeenAt,
			OsVersion: inv.OSVersion, FleetdVersion: inv.AgentVersion,
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
		keys := []string{}
		for _, p := range inv.Policies {
			keys = append(keys, p.Key)
			if err := q.UpsertPolicyResult(ctx, pgstore.UpsertPolicyResultParams{
				DeviceID: device, OrganizationID: org, PolicyKey: p.Key, Passing: p.Passing,
			}); err != nil {
				return err
			}
		}
		return q.DeleteMissingPolicyResults(ctx, pgstore.DeleteMissingPolicyResultsParams{DeviceID: device, Keys: keys})
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
// whose agent-running policy fails and whose last check-in is older than AgentSilence (the mutual watch, plan M5a
// decision 8), once per failure: the event and the mark are one transaction. It returns the reported devices.
func (s *InventorySync) ReportAgentNotRunning(ctx context.Context, now time.Time) ([]uuid.UUID, error) {
	var rows []pgstore.ListAgentNotRunningRow
	err := s.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		var err error
		rows, err = q.ListAgentNotRunning(ctx, pgstore.ListAgentNotRunningParams{
			PolicyKey: inventory.PolicyAgentRunning, Before: now.Add(-AgentSilence),
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
		spec := ActionSpec{
			Code: audit.CodeDeviceTamperAgentNotRunning, Target: &audit.Target{Type: "device", ID: r.DeviceID.String()},
			Params: params,
		}
		err := s.runner.RunTx(ctx, ScopeOrg, spec, func(ctx context.Context, q *pgstore.Queries, _ Recorder) error {
			return q.MarkAgentNotRunningReported(ctx, pgstore.MarkAgentNotRunningReportedParams{
				DeviceID: r.DeviceID, PolicyKey: inventory.PolicyAgentRunning,
			})
		})
		if err != nil {
			return reported, err
		}
		reported = append(reported, r.DeviceID)
	}
	return reported, nil
}
