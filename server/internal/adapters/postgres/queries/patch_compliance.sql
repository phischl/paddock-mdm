-- Patch SLA and the patch compliance report (plan M13c decisions 17 and 18). The tenant policy limits every statement
-- to the organization of the transaction. The report covers active devices the inventory system knows
-- (device_inventory_ref), optionally only the members of one device group.

-- name: GetPatchSLA :one
SELECT * FROM organization_patch_sla;

-- name: UpsertPatchSLA :one
INSERT INTO organization_patch_sla (organization_id, critical_days, high_days, medium_days, low_days, updated_at,
  updated_by)
VALUES (@organization_id, @critical_days, @high_days, @medium_days, @low_days, now(), sqlc.narg(updated_by))
ON CONFLICT (organization_id) DO UPDATE
SET critical_days = excluded.critical_days, high_days = excluded.high_days, medium_days = excluded.medium_days,
    low_days = excluded.low_days, updated_at = excluded.updated_at, updated_by = excluded.updated_by
RETURNING *;

-- name: ListPatchComplianceDevices :many
SELECT d.id, d.hostname FROM device d JOIN device_inventory_ref r ON r.device_id = d.id
WHERE d.state = 'active'
  AND (sqlc.narg(device_group_id)::uuid IS NULL OR EXISTS (
    SELECT 1 FROM device_group_member m WHERE m.device_id = d.id AND m.device_group_id = sqlc.narg(device_group_id)::uuid))
ORDER BY d.id;

-- name: ListPatchComplianceGroups :many
-- The device groups of the devices in scope, one row per membership; with a group filter only that group.
SELECT g.id AS device_group_id, g.name, m.device_id
FROM device_group g JOIN device_group_member m ON m.device_group_id = g.id
JOIN device d ON d.id = m.device_id JOIN device_inventory_ref r ON r.device_id = d.id
WHERE d.state = 'active' AND (sqlc.narg(device_group_id)::uuid IS NULL OR g.id = sqlc.narg(device_group_id)::uuid)
ORDER BY g.name, g.id, m.device_id;

-- name: ListPatchComplianceFindings :many
-- Open findings with a severity and a fixed version of the devices in scope (the report is a snapshot, plan M13c
-- amendment 2026-11-14).
SELECT f.device_id, f.cve, f.software_name, f.severity::text AS severity, f.fixed_version::text AS fixed_version,
       f.first_seen_at
FROM vulnerability_finding f JOIN device d ON d.id = f.device_id JOIN device_inventory_ref r ON r.device_id = d.id
WHERE d.state = 'active' AND f.severity IS NOT NULL AND f.fixed_version IS NOT NULL
  AND (sqlc.narg(device_group_id)::uuid IS NULL OR EXISTS (
    SELECT 1 FROM device_group_member m WHERE m.device_id = d.id AND m.device_group_id = sqlc.narg(device_group_id)::uuid))
ORDER BY f.device_id, f.cve, f.software_name;

-- name: ListPinnedRequiredAssignments :many
SELECT a.id, e.name AS entry, a.version::text AS required_version
FROM software_assignment a JOIN software_catalog_entry e ON e.id = a.catalog_entry_id
WHERE a.intent = 'required' AND a.update_rule = 'pinned' AND a.version IS NOT NULL
ORDER BY e.name, a.version, a.id;

-- name: ListPinnedRequiredInstalls :many
-- The installed Debian packages of the pinned required assignments on the devices in scope the assignment targets:
-- the organization, a device group of the device, an owner of the device or a user group one of its owners is in (the
-- compiler's rule, plan M13b decision 8). The caller compares the versions.
SELECT a.id AS assignment_id, s.device_id, s.version AS installed_version
FROM software_assignment a
JOIN software_catalog_entry e ON e.id = a.catalog_entry_id
JOIN installed_software s ON s.source = 'deb_packages'
  AND s.name IN (SELECT p ->> 'package' FROM jsonb_array_elements(e.packages) p WHERE coalesce(p ->> 'package', '') <> '')
JOIN device d ON d.id = s.device_id JOIN device_inventory_ref r ON r.device_id = d.id
WHERE a.intent = 'required' AND a.update_rule = 'pinned' AND a.version IS NOT NULL AND d.state = 'active'
  AND (sqlc.narg(device_group_id)::uuid IS NULL OR EXISTS (
    SELECT 1 FROM device_group_member m WHERE m.device_id = d.id AND m.device_group_id = sqlc.narg(device_group_id)::uuid))
  AND CASE
    WHEN a.device_group_id IS NOT NULL THEN EXISTS (
      SELECT 1 FROM device_group_member m WHERE m.device_id = d.id AND m.device_group_id = a.device_group_id)
    WHEN a.user_id IS NOT NULL THEN EXISTS (
      SELECT 1 FROM device_owner o WHERE o.device_id = d.id AND o.user_id = a.user_id)
    WHEN a.user_group_id IS NOT NULL THEN EXISTS (
      SELECT 1 FROM device_owner o JOIN user_group_member g ON g.user_id = o.user_id
      WHERE o.device_id = d.id AND g.group_id = a.user_group_id)
    ELSE true END
ORDER BY a.id, s.device_id;

-- name: VulnerabilitySLASummaryClaimed :one
-- Whether the day already has its summary, checked before any finding is read.
SELECT EXISTS (SELECT 1 FROM vulnerability_sla_summary WHERE day = @day::date) AS claimed;

-- name: ClaimVulnerabilitySLASummary :execrows
INSERT INTO vulnerability_sla_summary (organization_id, day) VALUES (@organization_id, @day::date)
ON CONFLICT (organization_id, day) DO NOTHING;
