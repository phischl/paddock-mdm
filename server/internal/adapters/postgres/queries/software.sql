-- name: InsertSoftwareSource :one
INSERT INTO software_source (id, organization_id, slug, name, uris, suites, components, architectures, signing_key,
  fingerprint, weak_key, created_by)
VALUES (@id, @organization_id, @slug, @name, @uris, @suites, @components, @architectures, @signing_key, @fingerprint,
  @weak_key, sqlc.narg(created_by))
RETURNING *;

-- name: GetSoftwareSource :one
SELECT * FROM software_source WHERE id = @id;

-- name: UpdateSoftwareSource :one
UPDATE software_source SET name = @name, uris = @uris, suites = @suites, components = @components,
  architectures = @architectures, signing_key = @signing_key, fingerprint = @fingerprint, weak_key = @weak_key,
  updated_at = now()
WHERE id = @id
RETURNING *;

-- name: DeleteSoftwareSource :execrows
DELETE FROM software_source WHERE id = @id;

-- name: ListSoftwareSources :many
SELECT * FROM software_source
WHERE (sqlc.narg(q_pattern)::text IS NULL OR name ILIKE sqlc.narg(q_pattern)::text ESCAPE '\'
  OR slug ILIKE sqlc.narg(q_pattern)::text ESCAPE '\')
ORDER BY
  CASE WHEN @sort::text = 'name' THEN name END ASC,
  CASE WHEN @sort::text = '-name' THEN name END DESC,
  CASE WHEN @sort::text = 'created_at' THEN created_at END ASC,
  CASE WHEN @sort::text = '-created_at' THEN created_at END DESC,
  CASE WHEN @sort::text = 'updated_at' THEN updated_at END ASC,
  CASE WHEN @sort::text = '-updated_at' THEN updated_at END DESC,
  id
LIMIT @max_rows OFFSET @skip_rows;

-- name: CountSoftwareSources :one
SELECT count(*) FROM (
  SELECT 1 FROM software_source
  WHERE (sqlc.narg(q_pattern)::text IS NULL OR name ILIKE sqlc.narg(q_pattern)::text ESCAPE '\'
    OR slug ILIKE sqlc.narg(q_pattern)::text ESCAPE '\')
  LIMIT @count_limit
) matching;

-- name: ListAllSoftwareSources :many
-- Every source of the organization (compiler), in a stable order.
SELECT * FROM software_source ORDER BY slug, id;
