-- name: InsertDeviceGroup :one
INSERT INTO device_group (id, organization_id, name, description)
VALUES (@id, @organization_id, @name, @description)
RETURNING *;

-- name: GetDeviceGroup :one
SELECT * FROM device_group WHERE id = @id;

-- List queries (ADR 0018): one ascending and one descending ORDER BY branch per allowed sort value, id as
-- tie-breaker; the count repeats the filter and stops at @count_limit rows.

-- name: ListDeviceGroups :many
SELECT * FROM device_group
WHERE (sqlc.narg(q_pattern)::text IS NULL
       OR name ILIKE sqlc.narg(q_pattern)::text ESCAPE '\'
       OR description ILIKE sqlc.narg(q_pattern)::text ESCAPE '\')
ORDER BY
  CASE WHEN @sort::text = 'name' THEN name END ASC,
  CASE WHEN @sort::text = '-name' THEN name END DESC,
  CASE WHEN @sort::text = 'created_at' THEN created_at END ASC,
  CASE WHEN @sort::text = '-created_at' THEN created_at END DESC,
  CASE WHEN @sort::text = 'updated_at' THEN updated_at END ASC,
  CASE WHEN @sort::text = '-updated_at' THEN updated_at END DESC,
  id
LIMIT @max_rows OFFSET @skip_rows;

-- name: CountDeviceGroups :one
SELECT count(*) FROM (
  SELECT 1 FROM device_group
  WHERE (sqlc.narg(q_pattern)::text IS NULL
         OR name ILIKE sqlc.narg(q_pattern)::text ESCAPE '\'
         OR description ILIKE sqlc.narg(q_pattern)::text ESCAPE '\')
  LIMIT @count_limit
) matching;

-- name: UpdateDeviceGroup :one
UPDATE device_group SET name = @name, description = @description, updated_at = now()
WHERE id = @id
RETURNING *;

-- name: DeleteDeviceGroup :execrows
DELETE FROM device_group WHERE id = @id;

-- Declarative configuration (plan M6c decision 16): every device group of the organization.
-- name: ListAllDeviceGroups :many
SELECT * FROM device_group ORDER BY name, id;

-- Declarative configuration (review 3 of PDK-008): the deletion of a device group locks it, so that no scoped row or
-- member can be added until the transaction ends, and then counts what still references it.
-- name: LockDeviceGroup :one
SELECT id FROM device_group WHERE id = @id FOR UPDATE;

-- name: CountDeviceGroupMembers :one
SELECT count(*) FROM device_group_member WHERE device_group_id = @id;

-- name: CountDeviceGroupScopedRows :one
SELECT ((SELECT count(*) FROM managed_file f WHERE f.device_group_id = @id::uuid)
      + (SELECT count(*) FROM managed_unit u WHERE u.device_group_id = @id::uuid)
      + (SELECT count(*) FROM package_hold h WHERE h.device_group_id = @id::uuid)
      + (SELECT count(*) FROM profile_assignment a WHERE a.device_group_id = @id::uuid))::bigint AS scoped;
