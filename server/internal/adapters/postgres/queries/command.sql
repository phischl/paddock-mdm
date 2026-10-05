-- Device commands (plan M4a decisions 1–3).

-- name: InsertDeviceCommand :one
INSERT INTO device_command (id, organization_id, device_id, type, params, status, issued_by, issued_at, expires_at, not_before)
VALUES (@id, @organization_id, @device_id, @type, @params, 'pending', sqlc.narg(issued_by), @issued_at, @expires_at,
        sqlc.narg(not_before))
RETURNING *;

-- name: GetDeviceCommand :one
SELECT * FROM device_command WHERE id = @id;

-- List queries (ADR 0018): see device_group.sql.

-- name: ListDeviceCommands :many
SELECT * FROM device_command
WHERE device_id = @device_id
  AND (sqlc.narg(q_pattern)::text IS NULL OR type ILIKE sqlc.narg(q_pattern)::text ESCAPE '\')
  AND (sqlc.narg(statuses)::text[] IS NULL OR status = ANY(sqlc.narg(statuses)::text[]))
  AND (sqlc.narg(types)::text[] IS NULL OR type = ANY(sqlc.narg(types)::text[]))
ORDER BY
  CASE WHEN @sort::text = 'issued_at' THEN issued_at END ASC,
  CASE WHEN @sort::text = '-issued_at' THEN issued_at END DESC,
  CASE WHEN @sort::text = 'expires_at' THEN expires_at END ASC,
  CASE WHEN @sort::text = '-expires_at' THEN expires_at END DESC,
  CASE WHEN @sort::text = 'type' THEN type END ASC,
  CASE WHEN @sort::text = '-type' THEN type END DESC,
  CASE WHEN @sort::text = 'status' THEN status END ASC,
  CASE WHEN @sort::text = '-status' THEN status END DESC,
  id
LIMIT @max_rows OFFSET @skip_rows;

-- name: CountDeviceCommands :one
SELECT count(*) FROM (
  SELECT 1 FROM device_command
  WHERE device_id = @device_id
    AND (sqlc.narg(q_pattern)::text IS NULL OR type ILIKE sqlc.narg(q_pattern)::text ESCAPE '\')
    AND (sqlc.narg(statuses)::text[] IS NULL OR status = ANY(sqlc.narg(statuses)::text[]))
    AND (sqlc.narg(types)::text[] IS NULL OR type = ANY(sqlc.narg(types)::text[]))
  LIMIT @count_limit
) matching;

-- name: ListDueDeviceCommands :many
-- Open commands that are due and not expired: the worker makes sure each one is in cmd:<device_id>.
SELECT * FROM device_command
WHERE status IN ('pending','delivered') AND expires_at > @now AND (not_before IS NULL OR not_before <= @now)
ORDER BY issued_at, id;

-- name: ExpireDeviceCommands :many
UPDATE device_command SET status = 'expired', finished_at = @now::timestamptz
WHERE status IN ('pending','delivered') AND expires_at <= @now::timestamptz
RETURNING id, device_id;

-- name: MarkDeviceCommandsDelivered :execrows
UPDATE device_command SET status = 'delivered', delivered_at = @delivered_at::timestamptz
WHERE device_id = @device_id AND id = ANY(@ids::uuid[]) AND status = 'pending';

-- name: FinishDeviceCommand :execrows
-- The first result counts; a command that is already finished or expired keeps its state.
UPDATE device_command SET status = @status, result = @result, finished_at = @finished_at::timestamptz,
  delivered_at = coalesce(delivered_at, @finished_at::timestamptz)
WHERE id = @id AND device_id = @device_id AND status IN ('pending','delivered');
