-- Inventory sync of the worker (plan M5a decisions 6 to 8).

-- The devices of hardware UUIDs, across organizations (platform pool); ambiguous and unknown UUIDs are missing.
-- name: InventoryDevices :many
SELECT hardware_uuid::text, device_id::uuid, organization_id::uuid FROM paddock_inventory_devices(@uuids::text[]);

-- name: UpsertInventoryRef :exec
INSERT INTO device_inventory_ref (device_id, organization_id, external_id, last_seen_at, os_version, fleetd_version, synced_at,
                                  hardware_vendor, hardware_model, hardware_serial, cpu_brand, cpu_cores, memory_bytes, disk_total_bytes,
                                  policy_updated_at)
VALUES (@device_id, @organization_id, @external_id, sqlc.narg(last_seen_at), @os_version, @fleetd_version, now(),
        @hardware_vendor, @hardware_model, @hardware_serial, @cpu_brand, @cpu_cores, @memory_bytes, @disk_total_bytes,
        sqlc.narg(policy_updated_at))
ON CONFLICT (device_id) DO UPDATE
  SET external_id = EXCLUDED.external_id, last_seen_at = EXCLUDED.last_seen_at, os_version = EXCLUDED.os_version,
      fleetd_version = EXCLUDED.fleetd_version, synced_at = now(),
      hardware_vendor = EXCLUDED.hardware_vendor, hardware_model = EXCLUDED.hardware_model,
      hardware_serial = EXCLUDED.hardware_serial, cpu_brand = EXCLUDED.cpu_brand, cpu_cores = EXCLUDED.cpu_cores,
      memory_bytes = EXCLUDED.memory_bytes, disk_total_bytes = EXCLUDED.disk_total_bytes,
      policy_updated_at = EXCLUDED.policy_updated_at,
      -- Another stored host is a rebinding, not a re-enrollment: its enrollment time is first observed anew (ADR 0057).
      fleet_enrolled_at = CASE WHEN device_inventory_ref.external_id = EXCLUDED.external_id
                               THEN device_inventory_ref.fleet_enrolled_at END;

-- name: GetDeviceHardware :one
SELECT hardware_vendor, hardware_model, hardware_serial, cpu_brand, cpu_cores, memory_bytes, disk_total_bytes
FROM device_inventory_ref WHERE device_id = @device_id;

-- name: InsertInstalledSoftware :exec
INSERT INTO installed_software (device_id, organization_id, name, version, source)
SELECT @device_id, @organization_id, unnest(@names::text[]), unnest(@versions::text[]), unnest(@sources::text[])
ON CONFLICT DO NOTHING;

-- name: DeleteMissingSoftware :exec
DELETE FROM installed_software s
WHERE s.device_id = @device_id
  AND (s.name, s.version, s.source) NOT IN (
    SELECT unnest(@names::text[]), unnest(@versions::text[]), unnest(@sources::text[]));

-- The arrays are parallel; cvss -1 and empty strings stand for unknown values. The CVSS vector comes from Ubuntu's
-- data only: the enrichment in the same transaction sets it again (plan M5c decision 2).
-- name: UpsertVulnerabilityFindings :exec
INSERT INTO vulnerability_finding (device_id, organization_id, cve, software_name, software_version, cvss_score, severity, fixed_version,
                                   fleet_severity, fleet_fixed_version)
SELECT @device_id, @organization_id, k.cve, k.name, k.version, NULLIF(k.cvss, -1)::numeric(3,1), NULLIF(k.severity, ''),
       NULLIF(k.fixed, ''), NULLIF(k.severity, ''), NULLIF(k.fixed, '')
FROM (SELECT unnest(@cves::text[]) AS cve, unnest(@names::text[]) AS name, unnest(@versions::text[]) AS version,
             unnest(@cvss::float8[]) AS cvss, unnest(@severities::text[]) AS severity, unnest(@fixed::text[]) AS fixed) k
ON CONFLICT (device_id, cve, software_name, software_version) DO UPDATE
  SET cvss_score = EXCLUDED.cvss_score, severity = EXCLUDED.severity, fixed_version = EXCLUDED.fixed_version,
      fleet_severity = EXCLUDED.fleet_severity, fleet_fixed_version = EXCLUDED.fleet_fixed_version, cvss_vector = NULL;

-- name: DeleteMissingFindings :exec
DELETE FROM vulnerability_finding f
WHERE f.device_id = @device_id
  AND (f.cve, f.software_name, f.software_version) NOT IN (
    SELECT unnest(@cves::text[]), unnest(@names::text[]), unnest(@versions::text[]));

-- name: InventoryRejectionDue :one
-- Whether a skipped inventory store of the device starts a new episode: no tamper finding of the code was seen since
-- the device's inventory was last stored (PDK-1122k). No row for a device outside the organization. seen_at is the
-- database's time for the finding: last_seen_at and synced_at must come from the same clock.
SELECT NOT EXISTS (
  SELECT 1 FROM finding f
  WHERE f.device_id = d.id AND f.kind = 'tamper' AND f.code = @code
    AND f.last_seen_at >= COALESCE((SELECT r.synced_at FROM device_inventory_ref r WHERE r.device_id = d.id), '-infinity')
)::boolean AS due, now()::timestamptz AS seen_at
FROM device d WHERE d.id = @device_id;

-- updated_at is when the result last changed; a policy that passes again ends its mutual watch alert.
-- name: UpsertPolicyResult :exec
INSERT INTO inventory_policy_result (device_id, organization_id, policy_key, passing, updated_at, failing_since)
VALUES (@device_id, @organization_id, @policy_key, @passing, now(),
        CASE WHEN @passing::boolean THEN NULL ELSE sqlc.narg(evaluated_at)::timestamptz END)
ON CONFLICT (device_id, policy_key) DO UPDATE
  SET passing = EXCLUDED.passing,
      updated_at = CASE WHEN inventory_policy_result.passing = EXCLUDED.passing THEN inventory_policy_result.updated_at ELSE now() END,
      alerted_at = CASE WHEN EXCLUDED.passing THEN NULL ELSE inventory_policy_result.alerted_at END,
      failing_since = CASE WHEN EXCLUDED.passing THEN NULL
                           ELSE COALESCE(inventory_policy_result.failing_since, EXCLUDED.failing_since) END;

-- A reported result whose policy the host has not answered since its query changed keeps its row and mark, so that the
-- same failure is not reported again (plan M5a amendment 2026-11-16, review round 1, A7).
-- name: DeleteMissingPolicyResults :exec
DELETE FROM inventory_policy_result
WHERE device_id = @device_id AND NOT (policy_key = ANY(@keys::text[]))
  AND NOT (policy_key = ANY(@unanswered::text[]) AND alerted_at IS NOT NULL);

-- Active devices whose agent-running policy fails, not yet reported, and that either have not checked in since before
-- or whose policy failed in evaluations at least absent_for_s apart (plan M5a decision 8 as amended 2026-11-16 b).
-- name: ListAgentNotRunning :many
SELECT r.device_id, s.last_contact_at, r.failing_since, i.policy_updated_at AS evaluated_at
FROM inventory_policy_result r JOIN device d ON d.id = r.device_id
     LEFT JOIN device_status s ON s.device_id = r.device_id
     LEFT JOIN device_inventory_ref i ON i.device_id = r.device_id
WHERE d.state = 'active' AND r.policy_key = @policy_key AND NOT r.passing AND r.alerted_at IS NULL
  AND (s.last_contact_at IS NULL OR s.last_contact_at < @before::timestamptz
       OR i.policy_updated_at >= r.failing_since + make_interval(secs => @absent_for_s::double precision))
  AND (i.fleet_reenrolled_at IS NULL OR i.fleet_reenrolled_at < @held_before::timestamptz)
ORDER BY r.device_id;

-- name: MarkAgentNotRunningReported :exec
UPDATE inventory_policy_result SET alerted_at = now() WHERE device_id = @device_id AND policy_key = @policy_key;

-- Active devices whose agent binary policy fails, not yet reported, and whose host evaluated its policies at or after
-- evaluated_after (plan M5a amendment 2026-11-16, A3): an older evaluation may predate the current definition.
-- name: ListAgentBinaryUnknown :many
SELECT r.device_id, i.policy_updated_at::timestamptz AS evaluated_at, s.agent_version
FROM inventory_policy_result r JOIN device d ON d.id = r.device_id
     JOIN device_inventory_ref i ON i.device_id = r.device_id LEFT JOIN device_status s ON s.device_id = r.device_id
WHERE d.state = 'active' AND r.policy_key = @policy_key AND NOT r.passing AND r.alerted_at IS NULL
  AND i.policy_updated_at >= @evaluated_after::timestamptz
  AND (i.fleet_reenrolled_at IS NULL OR i.fleet_reenrolled_at < @held_before::timestamptz)
ORDER BY r.device_id;

-- List queries of the admin API (plan M5a decision 9, ADR 0018); see device_group.sql.

-- name: ListDeviceSoftware :many
SELECT name, version, source FROM installed_software
WHERE device_id = @device_id
  AND (sqlc.narg(q_pattern)::text IS NULL OR name ILIKE sqlc.narg(q_pattern)::text ESCAPE '\')
ORDER BY
  CASE WHEN @sort::text = 'name' THEN name END ASC,
  CASE WHEN @sort::text = '-name' THEN name END DESC,
  CASE WHEN @sort::text = 'version' THEN version END ASC,
  CASE WHEN @sort::text = '-version' THEN version END DESC,
  name, version, source
LIMIT @max_rows OFFSET @skip_rows;

-- name: CountDeviceSoftware :one
SELECT count(*) FROM (
  SELECT 1 FROM installed_software
  WHERE device_id = @device_id
    AND (sqlc.narg(q_pattern)::text IS NULL OR name ILIKE sqlc.narg(q_pattern)::text ESCAPE '\')
  LIMIT @count_limit
) matching;

-- Severity "unknown" selects findings without severity (no Ubuntu priority and no score); unknown scores and
-- severities sort last both ways. In ORDER BY, severity is the inner query's rank (critical highest): names inside an
-- expression resolve to input columns, not to the output column of the same name.
-- name: ListDeviceVulnerabilities :many
SELECT cve, software_name, software_version, cvss_score, coalesce(label, 'unknown')::text AS severity, fixed_version,
       cvss_vector, first_seen_at
FROM (
  SELECT cve, software_name, software_version, cvss_score, severity AS label, fixed_version, cvss_vector, first_seen_at,
         CASE severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 END AS severity
  FROM vulnerability_finding
  WHERE device_id = @device_id
    AND (sqlc.narg(q_pattern)::text IS NULL OR cve ILIKE sqlc.narg(q_pattern)::text ESCAPE '\'
         OR software_name ILIKE sqlc.narg(q_pattern)::text ESCAPE '\')
    AND (sqlc.narg(severities)::text[] IS NULL OR coalesce(severity, 'unknown') = ANY(sqlc.narg(severities)::text[]))
) findings
ORDER BY
  CASE WHEN @sort::text = 'cvss_score' THEN cvss_score END ASC,
  CASE WHEN @sort::text = '-cvss_score' THEN cvss_score END DESC NULLS LAST,
  CASE WHEN @sort::text = 'severity' THEN severity END ASC,
  CASE WHEN @sort::text = '-severity' THEN severity END DESC NULLS LAST,
  CASE WHEN @sort::text = 'cve' THEN cve END ASC,
  CASE WHEN @sort::text = '-cve' THEN cve END DESC,
  cve, software_name, software_version
LIMIT @max_rows OFFSET @skip_rows;

-- name: CountDeviceVulnerabilities :one
SELECT count(*) FROM (
  SELECT 1 FROM vulnerability_finding
  WHERE device_id = @device_id
    AND (sqlc.narg(q_pattern)::text IS NULL OR cve ILIKE sqlc.narg(q_pattern)::text ESCAPE '\'
         OR software_name ILIKE sqlc.narg(q_pattern)::text ESCAPE '\')
    AND (sqlc.narg(severities)::text[] IS NULL OR coalesce(severity, 'unknown') = ANY(sqlc.narg(severities)::text[]))
  LIMIT @count_limit
) matching;

-- The organization-wide views count only the devices the inventory sync maps (active or quarantined); a retired
-- device keeps its last inventory on its own pages.

-- Software of the organization per name and version.
-- name: ListSoftware :many
SELECT name, version, device_count, has_vulnerabilities FROM (
  SELECT s.name, s.version, count(DISTINCT s.device_id)::int AS device_count,
         EXISTS (SELECT 1 FROM vulnerability_finding f WHERE f.software_name = s.name AND f.software_version = s.version)
           AS has_vulnerabilities
  FROM installed_software s JOIN device d ON d.id = s.device_id AND d.state IN ('active','quarantined')
  WHERE sqlc.narg(q_pattern)::text IS NULL OR s.name ILIKE sqlc.narg(q_pattern)::text ESCAPE '\'
  GROUP BY s.name, s.version
) software
WHERE sqlc.narg(has_vulnerabilities)::boolean IS NULL OR has_vulnerabilities = sqlc.narg(has_vulnerabilities)::boolean
ORDER BY
  CASE WHEN @sort::text = 'name' THEN name END ASC,
  CASE WHEN @sort::text = '-name' THEN name END DESC,
  CASE WHEN @sort::text = 'version' THEN version END ASC,
  CASE WHEN @sort::text = '-version' THEN version END DESC,
  CASE WHEN @sort::text = 'device_count' THEN device_count END ASC,
  CASE WHEN @sort::text = '-device_count' THEN device_count END DESC,
  name, version
LIMIT @max_rows OFFSET @skip_rows;

-- name: CountSoftware :one
SELECT count(*) FROM (
  SELECT 1 FROM installed_software s JOIN device d ON d.id = s.device_id AND d.state IN ('active','quarantined')
  WHERE (sqlc.narg(q_pattern)::text IS NULL OR s.name ILIKE sqlc.narg(q_pattern)::text ESCAPE '\')
    AND (sqlc.narg(has_vulnerabilities)::boolean IS NULL OR sqlc.narg(has_vulnerabilities)::boolean = EXISTS (
          SELECT 1 FROM vulnerability_finding f WHERE f.software_name = s.name AND f.software_version = s.version))
  GROUP BY s.name, s.version
  LIMIT @count_limit
) matching;

-- Vulnerabilities of the organization per CVE: the finding with the highest severity, then score (its fixed version
-- and CVSS vector, if known) and the number of affected devices; CountVulnerabilities picks the same finding. In ORDER
-- BY, severity is the rank (see ListDeviceVulnerabilities).
-- name: ListVulnerabilities :many
SELECT cve, cvss_score, label AS severity, device_count, fixed_version, cvss_vector FROM (
  SELECT DISTINCT ON (f.cve) f.cve, f.cvss_score, coalesce(f.severity, 'unknown')::text AS label,
         CASE f.severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 END AS severity,
         (SELECT count(DISTINCT g.device_id) FROM vulnerability_finding g
            JOIN device gd ON gd.id = g.device_id AND gd.state IN ('active','quarantined') WHERE g.cve = f.cve)::int AS device_count,
         f.fixed_version, f.cvss_vector
  FROM vulnerability_finding f JOIN device d ON d.id = f.device_id AND d.state IN ('active','quarantined')
  WHERE sqlc.narg(q_pattern)::text IS NULL OR f.cve ILIKE sqlc.narg(q_pattern)::text ESCAPE '\'
  ORDER BY f.cve, CASE f.severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 END DESC NULLS LAST, f.cvss_score DESC NULLS LAST,
    f.fixed_version NULLS LAST
) vulnerabilities
WHERE sqlc.narg(severities)::text[] IS NULL OR label = ANY(sqlc.narg(severities)::text[])
ORDER BY
  CASE WHEN @sort::text = 'cvss_score' THEN cvss_score END ASC,
  CASE WHEN @sort::text = '-cvss_score' THEN cvss_score END DESC NULLS LAST,
  CASE WHEN @sort::text = 'severity' THEN severity END ASC,
  CASE WHEN @sort::text = '-severity' THEN severity END DESC NULLS LAST,
  CASE WHEN @sort::text = 'cve' THEN cve END ASC,
  CASE WHEN @sort::text = '-cve' THEN cve END DESC,
  CASE WHEN @sort::text = 'device_count' THEN device_count END ASC,
  CASE WHEN @sort::text = '-device_count' THEN device_count END DESC,
  cve
LIMIT @max_rows OFFSET @skip_rows;

-- name: CountVulnerabilities :one
SELECT count(*) FROM (
  SELECT cve FROM (
    SELECT DISTINCT ON (f.cve) f.cve, coalesce(f.severity, 'unknown') AS severity
    FROM vulnerability_finding f JOIN device d ON d.id = f.device_id AND d.state IN ('active','quarantined')
    WHERE sqlc.narg(q_pattern)::text IS NULL OR f.cve ILIKE sqlc.narg(q_pattern)::text ESCAPE '\'
    ORDER BY f.cve, CASE f.severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 END DESC NULLS LAST,
      f.cvss_score DESC NULLS LAST
  ) vulnerabilities
  WHERE sqlc.narg(severities)::text[] IS NULL OR severity = ANY(sqlc.narg(severities)::text[])
  LIMIT @count_limit
) matching;

-- name: ListVulnerabilityDevices :many
SELECT device_id, hostname, software_name, software_version FROM (
  SELECT f.device_id, d.hostname, f.software_name, f.software_version
  FROM vulnerability_finding f JOIN device d ON d.id = f.device_id AND d.state IN ('active','quarantined')
  WHERE f.cve = @cve
) affected
WHERE sqlc.narg(q_pattern)::text IS NULL OR hostname ILIKE sqlc.narg(q_pattern)::text ESCAPE '\'
  OR software_name ILIKE sqlc.narg(q_pattern)::text ESCAPE '\'
ORDER BY
  CASE WHEN @sort::text = 'hostname' THEN hostname END ASC,
  CASE WHEN @sort::text = '-hostname' THEN hostname END DESC,
  device_id, software_name, software_version
LIMIT @max_rows OFFSET @skip_rows;

-- name: CountVulnerabilityDevices :one
SELECT count(*) FROM (
  SELECT 1 FROM vulnerability_finding f JOIN device d ON d.id = f.device_id AND d.state IN ('active','quarantined')
  WHERE f.cve = @cve
    AND (sqlc.narg(q_pattern)::text IS NULL OR d.hostname ILIKE sqlc.narg(q_pattern)::text ESCAPE '\'
         OR f.software_name ILIKE sqlc.narg(q_pattern)::text ESCAPE '\')
  LIMIT @count_limit
) matching;

-- The organization's devices (not findings) that carry cve; the count of a recorded CVE device-list view
-- (plan M10 amendment 2026-10-31, PDK-606).
-- name: CountDevicesWithVulnerability :one
SELECT count(DISTINCT f.device_id)::int FROM vulnerability_finding f
JOIN device d ON d.id = f.device_id AND d.state IN ('active','quarantined')
WHERE f.cve = @cve;

-- The dashboard tile (plan M5a decision 10): devices with critical or high findings, and devices with findings of
-- unknown severity.
-- name: VulnerabilitySummary :one
SELECT count(DISTINCT f.device_id) FILTER (WHERE f.severity IN ('critical','high'))::int AS critical_high_devices,
       count(DISTINCT f.device_id) FILTER (WHERE f.severity IS NULL)::int AS unknown_severity_devices,
       count(DISTINCT f.device_id)::int AS affected_devices
FROM vulnerability_finding f JOIN device d ON d.id = f.device_id AND d.state IN ('active','quarantined');

-- name: DeviceExists :one
SELECT EXISTS (SELECT 1 FROM device WHERE id = @id);

-- Retention of retired devices' inventory (ADR 0032, plan M10 decision 16). The sync never writes the rows of a device
-- that is not active or quarantined, so a retired device's rows only shrink.

-- The retired devices of the organization whose retirement is older than cutoff and that still have inventory rows,
-- longest retired first, after the keyset (after_changed, after_id) of the previous page.
-- name: ListRetiredDevicesWithInventory :many
SELECT d.id, d.hostname, d.state_changed_at FROM device d
WHERE d.state = 'retired' AND d.state_changed_at < @cutoff
  AND (d.state_changed_at, d.id) > (@after_changed::timestamptz, @after_id::uuid)
  AND (EXISTS (SELECT 1 FROM device_inventory_ref r WHERE r.device_id = d.id)
    OR EXISTS (SELECT 1 FROM installed_software s WHERE s.device_id = d.id)
    OR EXISTS (SELECT 1 FROM vulnerability_finding f WHERE f.device_id = d.id)
    OR EXISTS (SELECT 1 FROM inventory_policy_result p WHERE p.device_id = d.id))
ORDER BY d.state_changed_at, d.id
LIMIT @max_devices;

-- The inventory rows of a device and its Fleet host reference ('' without one).
-- name: CountDeviceInventory :one
SELECT coalesce((SELECT r.external_id FROM device_inventory_ref r WHERE r.device_id = @device_id), '')::text AS external_id,
       (SELECT count(*) FROM installed_software s WHERE s.device_id = @device_id)::bigint AS software,
       (SELECT count(*) FROM vulnerability_finding f WHERE f.device_id = @device_id)::bigint AS findings,
       (SELECT count(*) FROM inventory_policy_result p WHERE p.device_id = @device_id)::bigint AS policy_results;

-- keep_ref keeps the Fleet host reference, so the device is listed again until its host is decided.
-- name: DeleteDeviceInventory :one
WITH s AS (DELETE FROM installed_software x WHERE x.device_id = @device_id RETURNING 1),
     f AS (DELETE FROM vulnerability_finding x WHERE x.device_id = @device_id RETURNING 1),
     p AS (DELETE FROM inventory_policy_result x WHERE x.device_id = @device_id RETURNING 1),
     r AS (DELETE FROM device_inventory_ref x WHERE x.device_id = @device_id AND NOT @keep_ref::boolean RETURNING 1)
SELECT (SELECT count(*) FROM s)::bigint AS software, (SELECT count(*) FROM f)::bigint AS findings,
       (SELECT count(*) FROM p)::bigint AS policy_results, (SELECT count(*) FROM r)::bigint AS refs;

-- The answer the retention round last recorded an event for while it keeps a retired device's Fleet host, '' without
-- one (plan M10 amendment 2026-10-30, PDK-583 round 2).
-- name: InventoryHold :one
SELECT coalesce((SELECT h.last_answer FROM retention_inventory_hold h WHERE h.device_id = @device_id), '')::text AS last_answer,
       coalesce((SELECT h.unchanged_rounds FROM retention_inventory_hold h WHERE h.device_id = @device_id), 0)::int AS unchanged_rounds,
       coalesce((SELECT h.retired_at FROM retention_inventory_hold h WHERE h.device_id = @device_id), 'epoch')::timestamptz AS retired_at;

-- Counts one more round without a change of the held answer and returns the rounds counted.
-- name: CountInventoryHoldRound :one
UPDATE retention_inventory_hold SET unchanged_rounds = unchanged_rounds + 1
WHERE device_id = @device_id AND last_answer = @last_answer
RETURNING unchanged_rounds;

-- Holds the answer with the device's current retirement.
-- name: SetInventoryHold :exec
INSERT INTO retention_inventory_hold (device_id, organization_id, last_answer, retired_at, unchanged_rounds, last_event_at)
SELECT d.id, d.organization_id, @last_answer, d.state_changed_at, 0, now() FROM device d WHERE d.id = @device_id
ON CONFLICT (device_id) DO UPDATE SET last_answer = excluded.last_answer, retired_at = excluded.retired_at,
  unchanged_rounds = 0, last_event_at = now();

-- name: DeleteInventoryHold :exec
DELETE FROM retention_inventory_hold WHERE device_id = @device_id;

-- Whether a device of any organization other than retired_device still uses the Fleet host ('ref') or may use it
-- through the retired device's hardware ('hardware'), or neither ('none') (platform pool, plan M10 amendments
-- 2026-10-30): never another organization's rows.
-- name: FleetHostInUse :one
SELECT paddock_fleet_host_in_use(@retired_device::uuid, @host::text)::text;

-- Like FleetHostInUse for the deletion of a whole organization: every device of org is ignored, so only another
-- organization's reference or hardware keeps the host (platform pool, plan M17 amendment l point 1).
-- name: FleetHostInUseOutside :one
SELECT paddock_fleet_host_in_use_outside(@org::uuid, @host::text)::text;

-- Inventory host bindings and the claim watch (ADR 0057; plan M5a amendment 2026-11-17 e).

-- The platform functions' columns are not typed for sqlc: 'epoch' stands for NULL (never a real time here).
-- name: InventoryBindings :many
SELECT b.device_id::uuid AS device_id, b.organization_id::uuid AS organization_id, coalesce(b.hardware_uuid, '')::text AS hardware_uuid,
       coalesce(b.host_id, '')::text AS host_id, coalesce(b.pending_token, '')::text AS pending_token,
       coalesce(b.token_reported_at, 'epoch')::timestamptz AS token_reported_at,
       coalesce(b.reset_announced_at, 'epoch')::timestamptz AS reset_announced_at,
       coalesce(b.bound_at, 'epoch')::timestamptz AS bound_at,
       coalesce(b.suspended_at, 'epoch')::timestamptz AS suspended_at
FROM paddock_inventory_bindings() b ORDER BY b.token_reported_at NULLS LAST, b.device_id;

-- name: BindInventoryHost :execrows
UPDATE device_fleet_binding SET host_id = @host_id, bound_at = @at::timestamptz, pending_token = NULL, suspended_at = NULL
WHERE device_id = @device_id AND token_reported_at = @token_reported_at::timestamptz;

-- name: ClearFleetDeviceToken :execrows
UPDATE device_fleet_binding SET pending_token = NULL
WHERE device_id = @device_id AND token_reported_at = @token_reported_at::timestamptz;

-- name: ExpireFleetDeviceTokens :one
SELECT paddock_expire_fleet_device_tokens(@before::timestamptz)::bigint AS expired;

-- name: InventoryClaimDevices :many
SELECT c.device_id::uuid AS device_id, c.organization_id::uuid AS organization_id, coalesce(c.hardware_uuid, '')::text AS hardware_uuid,
       c.external_id::text AS external_id, coalesce(c.bound_host, '')::text AS bound_host,
       coalesce(c.reset_announced_at, 'epoch')::timestamptz AS reset_announced_at,
       coalesce(c.bound_at, 'epoch')::timestamptz AS bound_at,
       coalesce(c.fleet_enrolled_at, 'epoch')::timestamptz AS fleet_enrolled_at,
       coalesce(c.fleet_reenrolled_at, 'epoch')::timestamptz AS fleet_reenrolled_at,
       coalesce(c.fleet_claim_since, 'epoch')::timestamptz AS fleet_claim_since,
       coalesce(c.fleet_claim_reported_at, 'epoch')::timestamptz AS fleet_claim_reported_at,
       coalesce(c.suspended_at, 'epoch')::timestamptz AS suspended_at, c.active::boolean AS active
FROM paddock_inventory_claim_devices() c ORDER BY c.device_id;

-- name: SetFleetEnrolledAt :exec
UPDATE device_inventory_ref SET fleet_enrolled_at = @enrolled_at WHERE device_id = @device_id;

-- name: MarkFleetReenrolled :exec
UPDATE device_inventory_ref SET fleet_reenrolled_at = @at::timestamptz WHERE device_id = ANY(@device_ids::uuid[]);

-- name: StartFleetClaim :exec
UPDATE device_inventory_ref SET fleet_claim_since = @at::timestamptz
WHERE device_id = ANY(@device_ids::uuid[]) AND fleet_claim_since IS NULL;

-- name: ClearFleetClaim :exec
UPDATE device_inventory_ref SET fleet_claim_since = NULL, fleet_claim_reported_at = NULL
WHERE device_id = ANY(@device_ids::uuid[]);

-- name: MarkFleetClaimReported :execrows
UPDATE device_inventory_ref SET fleet_claim_reported_at = @at::timestamptz
WHERE device_id = @device_id AND fleet_claim_reported_at IS NULL;

-- name: SuspendInventoryBindings :exec
UPDATE device_fleet_binding SET suspended_at = @at::timestamptz
WHERE device_id = ANY(@device_ids::uuid[]) AND suspended_at IS NULL;

-- name: ResumeInventoryBindings :exec
UPDATE device_fleet_binding SET suspended_at = NULL WHERE device_id = ANY(@device_ids::uuid[]);

-- Hosts a device left (review round 2).

-- name: RecordReplacedInventoryHost :exec
INSERT INTO device_inventory_left_host (device_id, organization_id, host_id, reason, left_at)
SELECT r.device_id, r.organization_id, r.external_id, 'replaced', now() FROM device_inventory_ref r
WHERE r.device_id = @device_id AND r.external_id <> '' AND r.external_id <> @external_id::text
ON CONFLICT (device_id, host_id) DO NOTHING;

-- name: RecordRelistedInventoryHost :exec
INSERT INTO device_inventory_left_host (device_id, organization_id, host_id, reason, left_at)
VALUES (@device_id, @organization_id, @host_id, 'relisted', @left_at)
ON CONFLICT (device_id, host_id) DO NOTHING;

-- name: ForgetLeftInventoryHost :exec
DELETE FROM device_inventory_left_host WHERE device_id = @device_id AND host_id = @host_id;

-- name: LockLeftInventoryHost :one
SELECT host_id FROM device_inventory_left_host
WHERE device_id = @device_id AND host_id = @host_id AND removed_at IS NULL FOR UPDATE;

-- name: MarkLeftInventoryHostRemoved :exec
UPDATE device_inventory_left_host SET removed_at = now() WHERE device_id = @device_id AND host_id = @host_id;

-- name: MarkLeftInventoryHostAttempted :exec
UPDATE device_inventory_left_host SET attempted_at = now() WHERE device_id = @device_id AND host_id = @host_id;

-- name: InventoryLeftHosts :many
SELECT l.device_id::uuid AS device_id, l.organization_id::uuid AS organization_id, l.host_id::text AS host_id,
       l.reason::text AS reason, l.left_at::timestamptz AS left_at,
       coalesce(l.attempted_at, 'epoch')::timestamptz AS attempted_at, l.hostname::text AS hostname,
       l.org_active::boolean AS org_active
FROM paddock_inventory_left_hosts() l;

-- name: RecordRetiredInventoryHost :exec
INSERT INTO device_inventory_left_host (device_id, organization_id, host_id, reason, left_at)
SELECT r.device_id, r.organization_id, r.external_id, 'retired', now() FROM device_inventory_ref r
WHERE r.device_id = @device_id AND r.external_id <> ''
ON CONFLICT (device_id, host_id) DO NOTHING;
