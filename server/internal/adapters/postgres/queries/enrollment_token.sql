-- name: InsertEnrollmentToken :one
INSERT INTO enrollment_token (id, organization_id, name, secret_sha256, device_group_id, auto_approve, max_uses,
                              expires_at, created_by)
VALUES (@id, @organization_id, @name, @secret_sha256, sqlc.narg(device_group_id), @auto_approve, @max_uses,
        @expires_at, @created_by)
RETURNING *;

-- name: GetEnrollmentToken :one
SELECT * FROM enrollment_token WHERE id = @id;

-- List queries (ADR 0018): see device_group.sql.

-- name: ListEnrollmentTokens :many
SELECT * FROM enrollment_token
WHERE (sqlc.narg(q_pattern)::text IS NULL OR name ILIKE sqlc.narg(q_pattern)::text ESCAPE '\')
ORDER BY
  CASE WHEN @sort::text = 'name' THEN name END ASC,
  CASE WHEN @sort::text = '-name' THEN name END DESC,
  CASE WHEN @sort::text = 'created_at' THEN created_at END ASC,
  CASE WHEN @sort::text = '-created_at' THEN created_at END DESC,
  CASE WHEN @sort::text = 'expires_at' THEN expires_at END ASC,
  CASE WHEN @sort::text = '-expires_at' THEN expires_at END DESC,
  id
LIMIT @max_rows OFFSET @skip_rows;

-- name: CountEnrollmentTokens :one
SELECT count(*) FROM (
  SELECT 1 FROM enrollment_token
  WHERE (sqlc.narg(q_pattern)::text IS NULL OR name ILIKE sqlc.narg(q_pattern)::text ESCAPE '\')
  LIMIT @count_limit
) matching;

-- Revoking twice keeps the first revocation time.
-- name: RevokeEnrollmentToken :one
UPDATE enrollment_token SET revoked_at = coalesce(revoked_at, now())
WHERE id = @id
RETURNING *;

-- Worker: the row lock serializes concurrent enrollments with the same token.
-- name: LockEnrollmentTokenBySecret :one
SELECT * FROM enrollment_token WHERE secret_sha256 = @secret_sha256 FOR UPDATE;

-- name: ConsumeEnrollmentTokenUse :exec
UPDATE enrollment_token SET uses = uses + 1 WHERE id = @id;

-- Worker cache sync: every token of the organization that has not expired yet.
-- name: ListLiveEnrollmentTokens :many
SELECT * FROM enrollment_token WHERE expires_at > now() ORDER BY id;

-- Paddock autoinstall (plan M4b decision 2): the token of an enrollment configuration, within the organization.
-- name: GetEnrollmentTokenBySecret :one
SELECT * FROM enrollment_token WHERE secret_sha256 = @secret_sha256;
