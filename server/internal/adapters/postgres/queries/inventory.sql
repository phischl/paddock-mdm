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
