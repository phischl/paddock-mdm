-- API tokens (plan M6c decision 1).

-- name: InsertApiToken :one
INSERT INTO api_token (id, organization_id, name, role, secret_sha256, prefix, created_by, expires_at)
VALUES (@id, @organization_id, @name, @role, @secret_sha256, @prefix, @created_by, @expires_at)
RETURNING id;

-- name: GetApiToken :one
SELECT * FROM api_token_listed
WHERE id = @id;

-- List queries (ADR 0018): see device_group.sql.

-- name: ListApiTokens :many
SELECT * FROM api_token_listed
WHERE (sqlc.narg(q_pattern)::text IS NULL OR name ILIKE sqlc.narg(q_pattern)::text ESCAPE '\')
  AND (sqlc.narg(statuses)::text[] IS NULL OR status = ANY(sqlc.narg(statuses)::text[]))
ORDER BY
  CASE WHEN @sort::text = 'name' THEN name END ASC,
  CASE WHEN @sort::text = '-name' THEN name END DESC,
  CASE WHEN @sort::text = 'created_at' THEN created_at END ASC,
  CASE WHEN @sort::text = '-created_at' THEN created_at END DESC,
  CASE WHEN @sort::text = 'expires_at' THEN expires_at END ASC,
  CASE WHEN @sort::text = '-expires_at' THEN expires_at END DESC,
  CASE WHEN @sort::text = 'last_used_at' THEN last_used_at END ASC,
  CASE WHEN @sort::text = '-last_used_at' THEN last_used_at END DESC,
  id
LIMIT @max_rows OFFSET @skip_rows;

-- name: CountApiTokens :one
SELECT count(*) FROM (
  SELECT 1 FROM api_token_listed
  WHERE (sqlc.narg(q_pattern)::text IS NULL OR name ILIKE sqlc.narg(q_pattern)::text ESCAPE '\')
    AND (sqlc.narg(statuses)::text[] IS NULL OR status = ANY(sqlc.narg(statuses)::text[]))
  LIMIT @count_limit
) matching;

-- name: RevokeApiToken :execrows
UPDATE api_token SET revoked_at = now(), revoked_by = @by
WHERE id = @id AND revoked_at IS NULL;

-- name: LookupApiToken :one
-- The api's bearer authentication (plan M6c decision 9), before an organization context exists.
SELECT l.id::uuid AS id, l.organization_id::uuid AS organization_id, l.name::text AS name, l.role::text AS role,
       l.created_by::uuid AS created_by, l.expires_at::timestamptz AS expires_at,
       (l.revoked_at IS NOT NULL)::boolean AS revoked
FROM paddock_api_token_lookup(@hash::bytea) l;
