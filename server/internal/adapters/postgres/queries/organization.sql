-- name: InsertOrganization :one
INSERT INTO organization (id, slug, name, status)
VALUES (@id, @slug, @name, @status)
RETURNING *;

-- name: GetOrganization :one
SELECT * FROM organization WHERE id = @id;

-- name: GetOrganizationBySlug :one
SELECT * FROM organization WHERE slug = @slug;

-- List queries (ADR 0018): see device_group.sql.

-- name: ListOrganizations :many
SELECT * FROM organization
WHERE (sqlc.narg(q_pattern)::text IS NULL
       OR slug ILIKE sqlc.narg(q_pattern)::text ESCAPE '\'
       OR name ILIKE sqlc.narg(q_pattern)::text ESCAPE '\')
  AND (sqlc.narg(statuses)::text[] IS NULL OR status = ANY(sqlc.narg(statuses)::text[]))
ORDER BY
  CASE WHEN @sort::text = 'slug' THEN slug END ASC,
  CASE WHEN @sort::text = '-slug' THEN slug END DESC,
  CASE WHEN @sort::text = 'name' THEN name END ASC,
  CASE WHEN @sort::text = '-name' THEN name END DESC,
  CASE WHEN @sort::text = 'created_at' THEN created_at END ASC,
  CASE WHEN @sort::text = '-created_at' THEN created_at END DESC,
  CASE WHEN @sort::text = 'status' THEN status END ASC,
  CASE WHEN @sort::text = '-status' THEN status END DESC,
  id
LIMIT @max_rows OFFSET @skip_rows;

-- name: CountOrganizations :one
SELECT count(*) FROM (
  SELECT 1 FROM organization
  WHERE (sqlc.narg(q_pattern)::text IS NULL
         OR slug ILIKE sqlc.narg(q_pattern)::text ESCAPE '\'
         OR name ILIKE sqlc.narg(q_pattern)::text ESCAPE '\')
    AND (sqlc.narg(statuses)::text[] IS NULL OR status = ANY(sqlc.narg(statuses)::text[]))
  LIMIT @count_limit
) matching;

-- name: UpdateOrganizationStatus :one
UPDATE organization SET status = @status, name = @name, updated_at = now()
WHERE id = @id
RETURNING *;

-- Returns uuid.Nil when no active organization has this slug.
-- name: OrganizationIDBySlug :one
SELECT coalesce(paddock_org_id_by_slug(@slug), '00000000-0000-0000-0000-000000000000'::uuid)::uuid AS id;
