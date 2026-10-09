-- Change sets of the declarative configuration (plan M6c decision 17).

-- name: LockConfigApply :exec
-- Serializes the declarative applies and dry runs of the transaction's organization (PDK-016): two concurrent applies
-- would otherwise take device group locks in different orders and deadlock. Released at the end of the transaction.
SELECT pg_advisory_xact_lock(hashtextextended('config_apply:' || current_setting('paddock.org_id'), 0));

-- name: InsertChangeSet :exec
INSERT INTO change_set (id, organization_id, actor, source, created_n, updated_n, deleted_n, sections, plan)
VALUES (@id, @organization_id, @actor, @source, @created_n, @updated_n, @deleted_n, @sections, @plan);

-- name: GetChangeSet :one
SELECT * FROM change_set WHERE id = @id;

-- List queries (ADR 0018): see device_group.sql.

-- name: ListChangeSets :many
SELECT * FROM change_set
WHERE (sqlc.narg(q_pattern)::text IS NULL OR actor->>'display' ILIKE sqlc.narg(q_pattern)::text ESCAPE '\')
  AND (sqlc.narg(sources)::text[] IS NULL OR source = ANY(sqlc.narg(sources)::text[]))
ORDER BY
  CASE WHEN @sort::text = 'applied_at' THEN applied_at END ASC,
  CASE WHEN @sort::text = '-applied_at' THEN applied_at END DESC,
  id
LIMIT @max_rows OFFSET @skip_rows;

-- name: CountChangeSets :one
SELECT count(*) FROM (
  SELECT 1 FROM change_set
  WHERE (sqlc.narg(q_pattern)::text IS NULL OR actor->>'display' ILIKE sqlc.narg(q_pattern)::text ESCAPE '\')
    AND (sqlc.narg(sources)::text[] IS NULL OR source = ANY(sqlc.narg(sources)::text[]))
  LIMIT @count_limit
) matching;
