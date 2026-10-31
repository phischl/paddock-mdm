-- Login history (plan M8d decisions 14–19).

-- name: InsertDeviceLoginEvent :exec
INSERT INTO device_login_event (id, organization_id, device_id, username, at)
VALUES (@id, @organization_id, @device_id, @username, @at)
ON CONFLICT DO NOTHING;

-- name: DeleteAllDeviceLoginEvents :execrows
-- Every row of the context's organization (row-level security): the history was switched off.
DELETE FROM device_login_event;

-- name: HasDeviceLoginEventsBefore :one
SELECT EXISTS (SELECT 1 FROM device_login_event WHERE at < @cutoff::timestamptz);

-- name: PurgeDeviceLoginEvents :execrows
-- One batch of rows older than the cutoff; the retention round runs each batch in its own transaction until one
-- deletes fewer than 1 000 rows (plan M10 amendment 2026-10-30).
DELETE FROM device_login_event WHERE ctid IN (
  SELECT ctid FROM device_login_event WHERE at < @cutoff::timestamptz LIMIT 1000
);

-- List queries (ADR 0018): see device_group.sql.

-- name: ListDeviceLoginEvents :many
SELECT * FROM device_login_event
WHERE device_id = @device_id
  AND (sqlc.narg(q_pattern)::text IS NULL OR username ILIKE sqlc.narg(q_pattern)::text ESCAPE '\')
  AND (sqlc.narg(username)::text IS NULL OR username = sqlc.narg(username)::text)
ORDER BY
  CASE WHEN @sort::text = 'at' THEN at END ASC,
  CASE WHEN @sort::text = '-at' THEN at END DESC,
  CASE WHEN @sort::text = 'username' THEN username END ASC,
  CASE WHEN @sort::text = '-username' THEN username END DESC,
  id
LIMIT @max_rows OFFSET @skip_rows;

-- name: CountDeviceLoginEvents :one
SELECT count(*) FROM (
  SELECT 1 FROM device_login_event
  WHERE device_id = @device_id
    AND (sqlc.narg(q_pattern)::text IS NULL OR username ILIKE sqlc.narg(q_pattern)::text ESCAPE '\')
    AND (sqlc.narg(username)::text IS NULL OR username = sqlc.narg(username)::text)
  LIMIT @count_limit
) matching;
