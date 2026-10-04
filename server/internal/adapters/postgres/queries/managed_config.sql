-- name: InsertManagedFile :one
INSERT INTO managed_file (id, organization_id, device_group_id, path, mode, owner, grp, content)
VALUES (@id, @organization_id, sqlc.narg(device_group_id), @path, @mode, @owner, @grp, @content)
RETURNING *;

-- name: GetManagedFile :one
SELECT * FROM managed_file WHERE id = @id;

-- List queries (ADR 0018): see device_group.sql.

-- name: ListManagedFiles :many
SELECT * FROM managed_file
WHERE (sqlc.narg(q_pattern)::text IS NULL OR path ILIKE sqlc.narg(q_pattern)::text ESCAPE '\')
  AND (sqlc.narg(device_group_id)::uuid IS NULL OR device_group_id = sqlc.narg(device_group_id)::uuid)
ORDER BY
  CASE WHEN @sort::text = 'path' THEN path END ASC,
  CASE WHEN @sort::text = '-path' THEN path END DESC,
  CASE WHEN @sort::text = 'created_at' THEN created_at END ASC,
  CASE WHEN @sort::text = '-created_at' THEN created_at END DESC,
  CASE WHEN @sort::text = 'updated_at' THEN updated_at END ASC,
  CASE WHEN @sort::text = '-updated_at' THEN updated_at END DESC,
  id
LIMIT @max_rows OFFSET @skip_rows;

-- name: CountManagedFiles :one
SELECT count(*) FROM (
  SELECT 1 FROM managed_file
  WHERE (sqlc.narg(q_pattern)::text IS NULL OR path ILIKE sqlc.narg(q_pattern)::text ESCAPE '\')
    AND (sqlc.narg(device_group_id)::uuid IS NULL OR device_group_id = sqlc.narg(device_group_id)::uuid)
  LIMIT @count_limit
) matching;

-- name: UpdateManagedFile :one
UPDATE managed_file SET path = @path, mode = @mode, owner = @owner, grp = @grp, content = @content, updated_at = now()
WHERE id = @id
RETURNING *;

-- name: DeleteManagedFile :execrows
DELETE FROM managed_file WHERE id = @id;

-- name: ListAllManagedFiles :many
SELECT * FROM managed_file ORDER BY id;

-- name: InsertManagedUnit :one
INSERT INTO managed_unit (id, organization_id, device_group_id, unit, enabled, active)
VALUES (@id, @organization_id, sqlc.narg(device_group_id), @unit, @enabled, @active)
RETURNING *;

-- name: GetManagedUnit :one
SELECT * FROM managed_unit WHERE id = @id;

-- name: ListManagedUnits :many
SELECT * FROM managed_unit
WHERE (sqlc.narg(q_pattern)::text IS NULL OR unit ILIKE sqlc.narg(q_pattern)::text ESCAPE '\')
  AND (sqlc.narg(device_group_id)::uuid IS NULL OR device_group_id = sqlc.narg(device_group_id)::uuid)
ORDER BY
  CASE WHEN @sort::text = 'unit' THEN unit END ASC,
  CASE WHEN @sort::text = '-unit' THEN unit END DESC,
  CASE WHEN @sort::text = 'created_at' THEN created_at END ASC,
  CASE WHEN @sort::text = '-created_at' THEN created_at END DESC,
  CASE WHEN @sort::text = 'updated_at' THEN updated_at END ASC,
  CASE WHEN @sort::text = '-updated_at' THEN updated_at END DESC,
  id
LIMIT @max_rows OFFSET @skip_rows;

-- name: CountManagedUnits :one
SELECT count(*) FROM (
  SELECT 1 FROM managed_unit
  WHERE (sqlc.narg(q_pattern)::text IS NULL OR unit ILIKE sqlc.narg(q_pattern)::text ESCAPE '\')
    AND (sqlc.narg(device_group_id)::uuid IS NULL OR device_group_id = sqlc.narg(device_group_id)::uuid)
  LIMIT @count_limit
) matching;

-- name: UpdateManagedUnit :one
UPDATE managed_unit SET unit = @unit, enabled = @enabled, active = @active, updated_at = now()
WHERE id = @id
RETURNING *;

-- name: DeleteManagedUnit :execrows
DELETE FROM managed_unit WHERE id = @id;

-- name: ListAllManagedUnits :many
SELECT * FROM managed_unit ORDER BY id;
