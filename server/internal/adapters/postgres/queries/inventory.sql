-- Inventory sync of the worker (plan M5a decisions 6 to 8).

-- The devices of hardware UUIDs, across organizations (platform pool); ambiguous and unknown UUIDs are missing.
-- name: InventoryDevices :many
SELECT hardware_uuid::text, device_id::uuid, organization_id::uuid FROM paddock_inventory_devices(@uuids::text[]);

-- name: UpsertInventoryRef :exec
INSERT INTO device_inventory_ref (device_id, organization_id, external_id, last_seen_at, os_version, fleetd_version, synced_at)
VALUES (@device_id, @organization_id, @external_id, sqlc.narg(last_seen_at), @os_version, @fleetd_version, now())
ON CONFLICT (device_id) DO UPDATE
  SET external_id = EXCLUDED.external_id, last_seen_at = EXCLUDED.last_seen_at, os_version = EXCLUDED.os_version,
      fleetd_version = EXCLUDED.fleetd_version, synced_at = now();

-- name: InsertInstalledSoftware :exec
INSERT INTO installed_software (device_id, organization_id, name, version, source)
SELECT @device_id, @organization_id, unnest(@names::text[]), unnest(@versions::text[]), unnest(@sources::text[])
ON CONFLICT DO NOTHING;

-- name: DeleteMissingSoftware :exec
DELETE FROM installed_software s
WHERE s.device_id = @device_id
  AND (s.name, s.version, s.source) NOT IN (
    SELECT unnest(@names::text[]), unnest(@versions::text[]), unnest(@sources::text[]));

-- The arrays are parallel; cvss -1 and empty strings stand for unknown values.
-- name: UpsertVulnerabilityFindings :exec
INSERT INTO vulnerability_finding (device_id, organization_id, cve, software_name, software_version, cvss_score, severity, fixed_version)
SELECT @device_id, @organization_id, k.cve, k.name, k.version, NULLIF(k.cvss, -1)::numeric(3,1), NULLIF(k.severity, ''),
       NULLIF(k.fixed, '')
FROM (SELECT unnest(@cves::text[]) AS cve, unnest(@names::text[]) AS name, unnest(@versions::text[]) AS version,
             unnest(@cvss::float8[]) AS cvss, unnest(@severities::text[]) AS severity, unnest(@fixed::text[]) AS fixed) k
ON CONFLICT (device_id, cve, software_name, software_version) DO UPDATE
  SET cvss_score = EXCLUDED.cvss_score, severity = EXCLUDED.severity, fixed_version = EXCLUDED.fixed_version;

-- name: DeleteMissingFindings :exec
DELETE FROM vulnerability_finding f
WHERE f.device_id = @device_id
  AND (f.cve, f.software_name, f.software_version) NOT IN (
    SELECT unnest(@cves::text[]), unnest(@names::text[]), unnest(@versions::text[]));

-- updated_at is when the result last changed; a policy that passes again ends its mutual watch alert.
-- name: UpsertPolicyResult :exec
INSERT INTO inventory_policy_result (device_id, organization_id, policy_key, passing, updated_at)
VALUES (@device_id, @organization_id, @policy_key, @passing, now())
ON CONFLICT (device_id, policy_key) DO UPDATE
  SET passing = EXCLUDED.passing,
      updated_at = CASE WHEN inventory_policy_result.passing = EXCLUDED.passing THEN inventory_policy_result.updated_at ELSE now() END,
      alerted_at = CASE WHEN EXCLUDED.passing THEN NULL ELSE inventory_policy_result.alerted_at END;

-- name: DeleteMissingPolicyResults :exec
DELETE FROM inventory_policy_result WHERE device_id = @device_id AND NOT (policy_key = ANY(@keys::text[]));

-- Active devices whose agent-running policy fails, not yet reported, and that have not checked in since before (plan
-- M5a decision 8).
-- name: ListAgentNotRunning :many
SELECT r.device_id, s.last_contact_at
FROM inventory_policy_result r JOIN device d ON d.id = r.device_id LEFT JOIN device_status s ON s.device_id = r.device_id
WHERE d.state = 'active' AND r.policy_key = @policy_key AND NOT r.passing AND r.alerted_at IS NULL
  AND (s.last_contact_at IS NULL OR s.last_contact_at < @before::timestamptz)
ORDER BY r.device_id;

-- name: MarkAgentNotRunningReported :exec
UPDATE inventory_policy_result SET alerted_at = now() WHERE device_id = @device_id AND policy_key = @policy_key;

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

-- Severity "unknown" selects findings without severity (Fleet free reports none); unknown scores sort last both ways.
-- name: ListDeviceVulnerabilities :many
SELECT cve, software_name, software_version, cvss_score, coalesce(severity, 'unknown')::text AS severity, fixed_version,
       first_seen_at
FROM vulnerability_finding
WHERE device_id = @device_id
  AND (sqlc.narg(q_pattern)::text IS NULL OR cve ILIKE sqlc.narg(q_pattern)::text ESCAPE '\'
       OR software_name ILIKE sqlc.narg(q_pattern)::text ESCAPE '\')
  AND (sqlc.narg(severities)::text[] IS NULL OR coalesce(severity, 'unknown') = ANY(sqlc.narg(severities)::text[]))
ORDER BY
  CASE WHEN @sort::text = 'cvss_score' THEN cvss_score END ASC,
  CASE WHEN @sort::text = '-cvss_score' THEN cvss_score END DESC NULLS LAST,
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

-- Vulnerabilities of the organization per CVE: the finding with the highest score (its severity and fixed version, if
-- the inventory system knows them) and the number of affected devices.
-- name: ListVulnerabilities :many
SELECT cve, cvss_score, severity, device_count, fixed_version FROM (
  SELECT DISTINCT ON (f.cve) f.cve, f.cvss_score, coalesce(f.severity, 'unknown')::text AS severity,
         (SELECT count(DISTINCT g.device_id) FROM vulnerability_finding g
            JOIN device gd ON gd.id = g.device_id AND gd.state IN ('active','quarantined') WHERE g.cve = f.cve)::int AS device_count,
         f.fixed_version
  FROM vulnerability_finding f JOIN device d ON d.id = f.device_id AND d.state IN ('active','quarantined')
  WHERE sqlc.narg(q_pattern)::text IS NULL OR f.cve ILIKE sqlc.narg(q_pattern)::text ESCAPE '\'
  ORDER BY f.cve, f.cvss_score DESC NULLS LAST, f.fixed_version NULLS LAST
) vulnerabilities
WHERE sqlc.narg(severities)::text[] IS NULL OR severity = ANY(sqlc.narg(severities)::text[])
ORDER BY
  CASE WHEN @sort::text = 'cvss_score' THEN cvss_score END ASC,
  CASE WHEN @sort::text = '-cvss_score' THEN cvss_score END DESC NULLS LAST,
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
    ORDER BY f.cve, f.cvss_score DESC NULLS LAST
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

-- The dashboard tile (plan M5a decision 10): devices with critical or high findings, and devices with findings of
-- unknown severity.
-- name: VulnerabilitySummary :one
SELECT count(DISTINCT f.device_id) FILTER (WHERE f.severity IN ('critical','high'))::int AS critical_high_devices,
       count(DISTINCT f.device_id) FILTER (WHERE f.severity IS NULL)::int AS unknown_severity_devices,
       count(DISTINCT f.device_id)::int AS affected_devices
FROM vulnerability_finding f JOIN device d ON d.id = f.device_id AND d.state IN ('active','quarantined');

-- name: DeviceExists :one
SELECT EXISTS (SELECT 1 FROM device WHERE id = @id);
