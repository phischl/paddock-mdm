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

-- name: GetSoftwareSourceForUpdate :one
-- The source locked for the rest of the transaction: an update writes every column back, so a concurrent update must
-- not interleave between its read and its write.
SELECT * FROM software_source WHERE id = @id FOR UPDATE;

-- name: CountSoftwareCatalogEntriesBySource :one
SELECT count(*) FROM software_catalog_entry WHERE source_id = @source_id;

-- name: InsertSoftwareCatalogEntry :exec
INSERT INTO software_catalog_entry (id, organization_id, name, description, category, source_id, packages, created_by)
VALUES (@id, @organization_id, @name, @description, @category, sqlc.narg(source_id), @packages, sqlc.narg(created_by));

-- name: GetSoftwareCatalogEntry :one
-- An entry as the API shows it: the icon itself stays out, has_icon says whether there is one.
SELECT e.id, e.organization_id, e.name, e.description, e.category, e.source_id, e.packages, e.created_by,
  e.created_at, e.updated_at, (e.icon IS NOT NULL)::boolean AS has_icon, coalesce(s.slug, '')::text AS source_slug,
  (SELECT count(*) FROM software_assignment a WHERE a.catalog_entry_id = e.id)::bigint AS assignment_count
FROM software_catalog_entry e LEFT JOIN software_source s ON s.id = e.source_id
WHERE e.id = @id;

-- name: GetSoftwareCatalogEntryForUpdate :one
-- The entry locked for the rest of the transaction: an update writes every column back and a delete counts the
-- assignments it removes, so a concurrent write must not interleave.
SELECT id, organization_id, name, description, category, source_id, packages, created_by, created_at, updated_at
FROM software_catalog_entry WHERE id = @id FOR UPDATE;

-- name: ListSoftwareAssignmentIntentsOfEntry :many
-- The intents the entry's assignments use: changed packages must stay assignable with each of them.
SELECT DISTINCT intent FROM software_assignment WHERE catalog_entry_id = @catalog_entry_id ORDER BY intent;

-- name: UpdateSoftwareCatalogEntry :execrows
UPDATE software_catalog_entry SET name = @name, description = @description, category = @category,
  source_id = sqlc.narg(source_id), packages = @packages, updated_at = now()
WHERE id = @id;

-- name: SetSoftwareCatalogEntryIcon :execrows
UPDATE software_catalog_entry SET icon = @icon, updated_at = now() WHERE id = @id;

-- name: GetSoftwareCatalogEntryIcon :one
SELECT icon FROM software_catalog_entry WHERE id = @id AND icon IS NOT NULL;

-- name: DeleteSoftwareCatalogEntry :execrows
DELETE FROM software_catalog_entry WHERE id = @id;

-- name: ListSoftwareCatalogEntries :many
SELECT e.id, e.organization_id, e.name, e.description, e.category, e.source_id, e.packages, e.created_by,
  e.created_at, e.updated_at, (e.icon IS NOT NULL)::boolean AS has_icon, coalesce(s.slug, '')::text AS source_slug,
  (SELECT count(*) FROM software_assignment a WHERE a.catalog_entry_id = e.id)::bigint AS assignment_count
FROM software_catalog_entry e LEFT JOIN software_source s ON s.id = e.source_id
WHERE (sqlc.narg(q_pattern)::text IS NULL OR e.name ILIKE sqlc.narg(q_pattern)::text ESCAPE '\'
  OR e.description ILIKE sqlc.narg(q_pattern)::text ESCAPE '\')
  AND (sqlc.narg(category)::text IS NULL OR e.category = sqlc.narg(category)::text)
  AND (sqlc.narg(source_id)::uuid IS NULL OR e.source_id = sqlc.narg(source_id)::uuid)
ORDER BY
  CASE WHEN @sort::text = 'name' THEN e.name END ASC,
  CASE WHEN @sort::text = '-name' THEN e.name END DESC,
  CASE WHEN @sort::text = 'category' THEN e.category END ASC,
  CASE WHEN @sort::text = '-category' THEN e.category END DESC,
  CASE WHEN @sort::text = 'created_at' THEN e.created_at END ASC,
  CASE WHEN @sort::text = '-created_at' THEN e.created_at END DESC,
  CASE WHEN @sort::text = 'updated_at' THEN e.updated_at END ASC,
  CASE WHEN @sort::text = '-updated_at' THEN e.updated_at END DESC,
  e.id
LIMIT @max_rows OFFSET @skip_rows;

-- name: CountSoftwareCatalogEntries :one
SELECT count(*) FROM (
  SELECT 1 FROM software_catalog_entry e
  WHERE (sqlc.narg(q_pattern)::text IS NULL OR e.name ILIKE sqlc.narg(q_pattern)::text ESCAPE '\'
    OR e.description ILIKE sqlc.narg(q_pattern)::text ESCAPE '\')
    AND (sqlc.narg(category)::text IS NULL OR e.category = sqlc.narg(category)::text)
    AND (sqlc.narg(source_id)::uuid IS NULL OR e.source_id = sqlc.narg(source_id)::uuid)
  LIMIT @count_limit
) matching;

-- name: ListAllSoftwareCatalogEntries :many
-- Every entry of the organization (compiler), in a stable order, without the icons the bundles do not carry.
SELECT id, organization_id, name, description, category, source_id, packages, created_by, created_at, updated_at
FROM software_catalog_entry ORDER BY name, id;

-- name: InsertSoftwareAssignment :exec
INSERT INTO software_assignment (id, organization_id, catalog_entry_id, device_group_id, intent, update_rule, version,
  reason, created_by)
VALUES (@id, @organization_id, @catalog_entry_id, sqlc.narg(device_group_id), @intent, @update_rule,
  sqlc.narg(version), @reason, sqlc.narg(created_by));

-- name: GetSoftwareAssignment :one
SELECT a.*, e.name AS app_name FROM software_assignment a JOIN software_catalog_entry e ON e.id = a.catalog_entry_id
WHERE a.id = @id;

-- name: GetSoftwareAssignmentForUpdate :one
-- The assignment locked for the rest of the transaction: an update writes the intent columns back.
SELECT * FROM software_assignment WHERE id = @id FOR UPDATE;

-- name: UpdateSoftwareAssignment :execrows
UPDATE software_assignment SET intent = @intent, update_rule = @update_rule, version = sqlc.narg(version),
  reason = @reason, updated_at = now()
WHERE id = @id;

-- name: DeleteSoftwareAssignment :execrows
DELETE FROM software_assignment WHERE id = @id;

-- name: ListSoftwareAssignments :many
SELECT a.*, e.name AS app_name FROM software_assignment a JOIN software_catalog_entry e ON e.id = a.catalog_entry_id
WHERE (sqlc.narg(q_pattern)::text IS NULL OR e.name ILIKE sqlc.narg(q_pattern)::text ESCAPE '\')
  AND (sqlc.narg(catalog_entry_id)::uuid IS NULL OR a.catalog_entry_id = sqlc.narg(catalog_entry_id)::uuid)
  AND (sqlc.narg(device_group_id)::uuid IS NULL OR a.device_group_id = sqlc.narg(device_group_id)::uuid)
  AND (sqlc.narg(intent)::text IS NULL OR a.intent = sqlc.narg(intent)::text)
ORDER BY
  CASE WHEN @sort::text = 'created_at' THEN a.created_at END ASC,
  CASE WHEN @sort::text = '-created_at' THEN a.created_at END DESC,
  CASE WHEN @sort::text = 'updated_at' THEN a.updated_at END ASC,
  CASE WHEN @sort::text = '-updated_at' THEN a.updated_at END DESC,
  CASE WHEN @sort::text = 'intent' THEN a.intent END ASC,
  CASE WHEN @sort::text = '-intent' THEN a.intent END DESC,
  a.id
LIMIT @max_rows OFFSET @skip_rows;

-- name: CountSoftwareAssignments :one
SELECT count(*) FROM (
  SELECT 1 FROM software_assignment a JOIN software_catalog_entry e ON e.id = a.catalog_entry_id
  WHERE (sqlc.narg(q_pattern)::text IS NULL OR e.name ILIKE sqlc.narg(q_pattern)::text ESCAPE '\')
    AND (sqlc.narg(catalog_entry_id)::uuid IS NULL OR a.catalog_entry_id = sqlc.narg(catalog_entry_id)::uuid)
    AND (sqlc.narg(device_group_id)::uuid IS NULL OR a.device_group_id = sqlc.narg(device_group_id)::uuid)
    AND (sqlc.narg(intent)::text IS NULL OR a.intent = sqlc.narg(intent)::text)
  LIMIT @count_limit
) matching;

-- name: ListAllSoftwareAssignments :many
-- Every assignment of the organization (compiler), in a stable order.
SELECT * FROM software_assignment ORDER BY catalog_entry_id, device_group_id NULLS FIRST, id;
