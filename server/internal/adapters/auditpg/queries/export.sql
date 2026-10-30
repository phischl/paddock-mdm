-- name: InsertAuditExport :one
-- The reader role inserts the request of its own organization (RLS WITH CHECK, plan M10 decision 29); the audit
-- writer moves it on from pending.
INSERT INTO audit_export (id, organization_id, status, from_day, to_day, purpose, requested_by, correlation_id)
VALUES (@id, @organization_id, 'pending', @from_day, @to_day, @purpose, @requested_by, @correlation_id)
RETURNING *;

-- name: GetAuditExport :one
SELECT * FROM audit_export WHERE id = @id;

-- name: ListAuditExports :many
SELECT * FROM audit_export
WHERE (sqlc.narg(statuses)::text[] IS NULL OR status = ANY(sqlc.narg(statuses)::text[]))
  AND (sqlc.narg(q_pattern)::text IS NULL OR purpose ILIKE sqlc.narg(q_pattern)::text ESCAPE '\'
       OR requested_by->>'display' ILIKE sqlc.narg(q_pattern)::text ESCAPE '\')
ORDER BY
  CASE WHEN @sort::text = 'requested_at' THEN requested_at END ASC,
  CASE WHEN @sort::text = '-requested_at' THEN requested_at END DESC,
  CASE WHEN @sort::text = 'status' THEN status END ASC,
  CASE WHEN @sort::text = '-status' THEN status END DESC,
  CASE WHEN @sort::text = 'from_day' THEN from_day END ASC,
  CASE WHEN @sort::text = '-from_day' THEN from_day END DESC,
  CASE WHEN @sort::text = 'to_day' THEN to_day END ASC,
  CASE WHEN @sort::text = '-to_day' THEN to_day END DESC,
  id
LIMIT @max_rows OFFSET @skip_rows;

-- name: CountAuditExports :one
SELECT count(*) FROM (
  SELECT 1 FROM audit_export
  WHERE (sqlc.narg(statuses)::text[] IS NULL OR status = ANY(sqlc.narg(statuses)::text[]))
    AND (sqlc.narg(q_pattern)::text IS NULL OR purpose ILIKE sqlc.narg(q_pattern)::text ESCAPE '\'
         OR requested_by->>'display' ILIKE sqlc.narg(q_pattern)::text ESCAPE '\')
  LIMIT @count_limit
) matching;

-- name: CountOpenAuditExports :one
SELECT count(*) FROM audit_export WHERE status IN ('pending', 'running');
