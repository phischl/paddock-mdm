-- Update management (plan M5b decisions 1–4 and 9). Without a settings row the defaults apply.

-- name: GetUpdateSettings :one
SELECT * FROM organization_update_settings;

-- name: UpsertUpdateSettings :one
INSERT INTO organization_update_settings (organization_id, security_daily_at, regular_schedule, regular_updates_enabled,
  max_random_delay_min, staleness_warning_h, staleness_critical_h, updated_at, updated_by)
VALUES (@organization_id, @security_daily_at, @regular_schedule, @regular_updates_enabled, @max_random_delay_min,
  @staleness_warning_h, @staleness_critical_h, now(), sqlc.narg(updated_by))
ON CONFLICT (organization_id) DO UPDATE
SET security_daily_at = excluded.security_daily_at, regular_schedule = excluded.regular_schedule,
    regular_updates_enabled = excluded.regular_updates_enabled, max_random_delay_min = excluded.max_random_delay_min,
    staleness_warning_h = excluded.staleness_warning_h, staleness_critical_h = excluded.staleness_critical_h,
    updated_at = excluded.updated_at, updated_by = excluded.updated_by
RETURNING *;

-- name: InsertPackageHold :one
INSERT INTO package_hold (id, organization_id, device_group_id, package, version, reason, created_by)
VALUES (@id, @organization_id, sqlc.narg(device_group_id), @package, sqlc.narg(version), @reason, sqlc.narg(created_by))
RETURNING *;

-- name: GetPackageHold :one
SELECT * FROM package_hold WHERE id = @id;

-- name: UpdatePackageHold :one
UPDATE package_hold SET version = sqlc.narg(version), reason = @reason, updated_at = now()
WHERE id = @id
RETURNING *;

-- name: DeletePackageHold :execrows
DELETE FROM package_hold WHERE id = @id;

-- name: ListPackageHolds :many
SELECT * FROM package_hold
WHERE (sqlc.narg(q_pattern)::text IS NULL OR package ILIKE sqlc.narg(q_pattern)::text ESCAPE '\')
  AND (sqlc.narg(device_group_id)::uuid IS NULL OR device_group_id = sqlc.narg(device_group_id)::uuid)
ORDER BY
  CASE WHEN @sort::text = 'package' THEN package END ASC,
  CASE WHEN @sort::text = '-package' THEN package END DESC,
  CASE WHEN @sort::text = 'created_at' THEN created_at END ASC,
  CASE WHEN @sort::text = '-created_at' THEN created_at END DESC,
  CASE WHEN @sort::text = 'updated_at' THEN updated_at END ASC,
  CASE WHEN @sort::text = '-updated_at' THEN updated_at END DESC,
  id
LIMIT @max_rows OFFSET @skip_rows;

-- name: CountPackageHolds :one
SELECT count(*) FROM (
  SELECT 1 FROM package_hold
  WHERE (sqlc.narg(q_pattern)::text IS NULL OR package ILIKE sqlc.narg(q_pattern)::text ESCAPE '\')
    AND (sqlc.narg(device_group_id)::uuid IS NULL OR device_group_id = sqlc.narg(device_group_id)::uuid)
  LIMIT @count_limit
) matching;

-- name: ListAllPackageHolds :many
-- Every hold of the organization (compiler), in a stable order.
SELECT * FROM package_hold ORDER BY package, device_group_id NULLS FIRST, id;

-- name: ListDeviceHolds :many
-- The holds that apply to a device: organization-wide and those of its device groups.
SELECT h.* FROM package_hold h
WHERE h.device_group_id IS NULL
   OR h.device_group_id IN (SELECT m.device_group_id FROM device_group_member m WHERE m.device_id = @device_id)
ORDER BY h.package, h.device_group_id NULLS FIRST, h.id;

-- name: ListGroupMembersHolds :many
-- The holds that apply to any active member of a device group: organization-wide and those of every group of a
-- member.
SELECT h.* FROM package_hold h
WHERE h.device_group_id IS NULL
   OR h.device_group_id IN (
     SELECT m2.device_group_id FROM device_group_member m
     JOIN device d ON d.id = m.device_id AND d.state = 'active'
     JOIN device_group_member m2 ON m2.device_id = m.device_id
     WHERE m.device_group_id = @device_group_id)
ORDER BY h.package, h.id;
