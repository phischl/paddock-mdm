-- name: InsertSoftwareSource :one
INSERT INTO software_source (id, organization_id, kind, slug, name, uris, suites, components, architectures,
  signing_key, fingerprint, weak_key, created_by)
VALUES (@id, @organization_id, @kind, @slug, @name, @uris, @suites, @components, @architectures, @signing_key,
  @fingerprint, @weak_key, sqlc.narg(created_by))
RETURNING *;

-- name: GetSoftwareSource :one
-- The source with the number of catalog entries that reference it, counted in the same statement.
SELECT sqlc.embed(s), (SELECT count(*) FROM software_catalog_entry e WHERE e.source_id = s.id)::bigint AS entry_count
FROM software_source s WHERE s.id = @id;

-- name: UpdateSoftwareSource :one
UPDATE software_source SET name = @name, uris = @uris, suites = @suites, components = @components,
  architectures = @architectures, signing_key = @signing_key, fingerprint = @fingerprint, weak_key = @weak_key,
  updated_at = now()
WHERE id = @id
RETURNING *;

-- name: DeleteSoftwareSource :execrows
DELETE FROM software_source WHERE id = @id;

-- name: ListSoftwareSources :many
-- The sources of a page with their catalog entry counts: one grouped count joined in, not one count per row.
SELECT sqlc.embed(s), coalesce(c.entry_count, 0)::bigint AS entry_count
FROM software_source s
LEFT JOIN (
  SELECT source_id, count(*) AS entry_count FROM software_catalog_entry WHERE source_id IS NOT NULL GROUP BY source_id
) c ON c.source_id = s.id
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
INSERT INTO software_catalog_entry (id, organization_id, name, description, category, source_id, packages, approval, created_by)
VALUES (@id, @organization_id, @name, @description, @category, sqlc.narg(source_id), @packages, @approval, sqlc.narg(created_by));

-- name: GetSoftwareCatalogEntry :one
-- An entry as the API shows it: the icon itself stays out, has_icon says whether there is one.
SELECT e.id, e.organization_id, e.name, e.description, e.category, e.source_id, e.packages, e.approval, e.created_by,
  e.created_at, e.updated_at, (e.icon IS NOT NULL)::boolean AS has_icon, coalesce(s.slug, '')::text AS source_slug,
  (SELECT count(*) FROM software_assignment a WHERE a.catalog_entry_id = e.id)::bigint AS assignment_count
FROM software_catalog_entry e LEFT JOIN software_source s ON s.id = e.source_id
WHERE e.id = @id;

-- name: GetSoftwareCatalogEntryForUpdate :one
-- The entry locked for the rest of the transaction: an update writes every column back and a delete counts the
-- assignments it removes, so a concurrent write must not interleave.
SELECT id, organization_id, name, description, category, source_id, packages, approval, created_by, created_at, updated_at
FROM software_catalog_entry WHERE id = @id FOR UPDATE;

-- name: ListSoftwareAssignmentIntentsOfEntry :many
-- The intents the entry's assignments use: changed packages must stay assignable with each of them.
SELECT DISTINCT intent FROM software_assignment WHERE catalog_entry_id = @catalog_entry_id ORDER BY intent;

-- name: UpdateSoftwareCatalogEntry :execrows
-- A change of the approval starts a new approval epoch: the requests and approvals of the old one no longer hold.
UPDATE software_catalog_entry SET name = @name, description = @description, category = @category,
  source_id = sqlc.narg(source_id), packages = @packages, approval = @approval,
  approval_epoch = approval_epoch + CASE WHEN approval = @approval THEN 0 ELSE 1 END, updated_at = now()
WHERE id = @id;

-- name: SetSoftwareCatalogEntryIcon :execrows
UPDATE software_catalog_entry SET icon = @icon, updated_at = now() WHERE id = @id;

-- name: GetSoftwareCatalogEntryIcon :one
SELECT icon FROM software_catalog_entry WHERE id = @id AND icon IS NOT NULL;

-- name: DeleteSoftwareCatalogEntry :execrows
DELETE FROM software_catalog_entry WHERE id = @id;

-- name: ListSoftwareCatalogEntries :many
SELECT e.id, e.organization_id, e.name, e.description, e.category, e.source_id, e.packages, e.approval, e.created_by,
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
SELECT id, organization_id, name, description, category, source_id, packages, approval, created_by, created_at, updated_at
FROM software_catalog_entry ORDER BY name, id;

-- name: ListSoftwareCatalogIcons :many
-- The icons of the organization's entries (compiler): it validates them, names their digests in the bundles and writes
-- them to object storage (architect decision A10-14).
SELECT id, icon::bytea AS icon FROM software_catalog_entry WHERE icon IS NOT NULL ORDER BY id;

-- name: ListSoftwareCatalogEntryIDsByName :many
-- The IDs of the named entries (the worker resolves the staged entries of a rollout, plan M13c decision 3).
SELECT id, name FROM software_catalog_entry WHERE name = ANY(@names::text[]) ORDER BY name;

-- name: InsertSoftwareAssignment :exec
INSERT INTO software_assignment (id, organization_id, catalog_entry_id, device_group_id, user_id, user_group_id, intent,
  update_rule, version, reason, created_by, urgent)
VALUES (@id, @organization_id, @catalog_entry_id, sqlc.narg(device_group_id), sqlc.narg(user_id),
  sqlc.narg(user_group_id), @intent, @update_rule, sqlc.narg(version), @reason, sqlc.narg(created_by), @urgent);

-- name: GetSoftwareAssignment :one
SELECT a.*, e.name AS app_name FROM software_assignment a JOIN software_catalog_entry e ON e.id = a.catalog_entry_id
WHERE a.id = @id;

-- name: GetSoftwareAssignmentForUpdate :one
-- The assignment locked for the rest of the transaction: an update writes the intent columns back.
SELECT * FROM software_assignment WHERE id = @id FOR UPDATE;

-- name: UpdateSoftwareAssignment :execrows
-- A NULL urgent keeps the stored flag: the declarative document does not carry it (PDK-809), so an apply that changes
-- only the reason keeps it and one that changes the effect passes false.
UPDATE software_assignment SET intent = @intent, update_rule = @update_rule, version = sqlc.narg(version),
  reason = @reason, urgent = COALESCE(sqlc.narg(urgent)::boolean, urgent), updated_at = now()
WHERE id = @id;

-- name: DeleteSoftwareAssignment :execrows
DELETE FROM software_assignment WHERE id = @id;

-- name: ListSoftwareAssignments :many
SELECT a.*, e.name AS app_name FROM software_assignment a JOIN software_catalog_entry e ON e.id = a.catalog_entry_id
WHERE (sqlc.narg(q_pattern)::text IS NULL OR e.name ILIKE sqlc.narg(q_pattern)::text ESCAPE '\')
  AND (sqlc.narg(catalog_entry_id)::uuid IS NULL OR a.catalog_entry_id = sqlc.narg(catalog_entry_id)::uuid)
  AND (sqlc.narg(device_group_id)::uuid IS NULL OR a.device_group_id = sqlc.narg(device_group_id)::uuid)
  AND (sqlc.narg(user_id)::uuid IS NULL OR a.user_id = sqlc.narg(user_id)::uuid)
  AND (sqlc.narg(user_group_id)::uuid IS NULL OR a.user_group_id = sqlc.narg(user_group_id)::uuid)
  AND (sqlc.narg(target)::text IS NULL OR sqlc.narg(target)::text = CASE
    WHEN a.device_group_id IS NOT NULL THEN 'device_group' WHEN a.user_id IS NOT NULL THEN 'user'
    WHEN a.user_group_id IS NOT NULL THEN 'user_group' ELSE 'organization' END)
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
    AND (sqlc.narg(user_id)::uuid IS NULL OR a.user_id = sqlc.narg(user_id)::uuid)
    AND (sqlc.narg(user_group_id)::uuid IS NULL OR a.user_group_id = sqlc.narg(user_group_id)::uuid)
    AND (sqlc.narg(target)::text IS NULL OR sqlc.narg(target)::text = CASE
      WHEN a.device_group_id IS NOT NULL THEN 'device_group' WHEN a.user_id IS NOT NULL THEN 'user'
      WHEN a.user_group_id IS NOT NULL THEN 'user_group' ELSE 'organization' END)
    AND (sqlc.narg(intent)::text IS NULL OR a.intent = sqlc.narg(intent)::text)
  LIMIT @count_limit
) matching;

-- name: ListSoftwareAssignmentTargetsOfEntry :many
-- The assignments that keep a catalog entry from being deleted, by target (plan M13c amendment 2026-11-09, A10-12):
-- the target type and the device group's name, the user's username or the user group's slug ('' for the organization).
SELECT a.id,
  (CASE WHEN a.device_group_id IS NOT NULL THEN 'device_group' WHEN a.user_id IS NOT NULL THEN 'user'
    WHEN a.user_group_id IS NOT NULL THEN 'user_group' ELSE 'organization' END)::text AS target,
  COALESCE(g.name, u.username, ug.slug, '')::text AS target_name
FROM software_assignment a
LEFT JOIN device_group g ON g.id = a.device_group_id
LEFT JOIN app_user u ON u.id = a.user_id
LEFT JOIN user_group ug ON ug.id = a.user_group_id
WHERE a.catalog_entry_id = @catalog_entry_id
ORDER BY 2, 3, a.id
LIMIT @max_rows;

-- name: ListAllSoftwareAssignments :many
-- Every assignment of the organization (compiler), in a stable order.
SELECT * FROM software_assignment ORDER BY catalog_entry_id, device_group_id NULLS FIRST, id;

-- name: UpsertDeviceSoftwareStatus :exec
-- Stores the items of a report (JSON array of {id, package, intent, state, version, reason, error, scope}); an item
-- whose id is not an entry of the organization is skipped, and a row of a newer report is never replaced.
INSERT INTO device_software_status (device_id, organization_id, catalog_entry_id, package, intent, state, version, reason, error, scope, reported_at)
SELECT @device_id, @organization_id, r.id, r.package, r.intent, r.state, r.version, r.reason, r.error, r.scope, @reported_at
FROM jsonb_to_recordset(@rows::jsonb) AS r(id uuid, package text, intent text, state text, version text, reason text, error text, scope text)
JOIN software_catalog_entry e ON e.id = r.id AND e.organization_id = @organization_id
ON CONFLICT (device_id, catalog_entry_id, scope, username) DO UPDATE SET
  package = EXCLUDED.package, intent = EXCLUDED.intent, state = EXCLUDED.state, version = EXCLUDED.version,
  reason = EXCLUDED.reason, error = EXCLUDED.error, reported_at = EXCLUDED.reported_at
WHERE device_software_status.reported_at <= EXCLUDED.reported_at;

-- name: DeleteDeviceSoftwareStatusNotIn :exec
-- The entries and scopes the report no longer names (keys: "<entry id>/<scope>"); rows a newer report wrote stay.
DELETE FROM device_software_status
WHERE device_id = @device_id AND reported_at <= @reported_at
  AND (catalog_entry_id::text || '/' || scope) <> ALL(@keys::text[]);

-- name: SetDeviceSoftwareDigest :exec
-- Only a changed digest writes: every check-in carries one, and device_status is the hottest table.
UPDATE device_status SET software_digest = @digest WHERE device_id = @device_id AND software_digest IS DISTINCT FROM @digest;

-- name: SetDeviceSoftwareTruncated :exec
UPDATE device_status SET software_truncated = @truncated
WHERE device_id = @device_id AND software_truncated IS DISTINCT FROM @truncated;

-- name: ListDeviceManagedSoftware :many
-- The entries a device manages: those assigned to it, through the organization or one of its groups, and those it
-- reported a row for, with the intents of the assignments (NULL: none) and the reported rows (state '': none; one per
-- scope, plan M13b decision 17). The page derives not_applicable and unknown from the rest and filters and sorts them
-- in memory (ADR 0028).
SELECT e.id AS catalog_entry_id, e.name, e.packages, t.intents, coalesce(s.package, '')::text AS package,
       coalesce(s.intent, '')::text AS intent, coalesce(s.state, '')::text AS state, coalesce(s.version, '')::text AS version,
       coalesce(s.reason, '')::text AS reason, coalesce(s.error, '')::text AS error, coalesce(s.scope, '')::text AS scope,
       s.reported_at
FROM software_catalog_entry e
LEFT JOIN device_software_status s ON s.catalog_entry_id = e.id AND s.device_id = @device_id
CROSS JOIN LATERAL (
  SELECT array_agg(DISTINCT a.intent ORDER BY a.intent)::text[] AS intents
  FROM software_assignment a
  WHERE a.catalog_entry_id = e.id
    AND ((a.device_group_id IS NULL AND a.user_id IS NULL AND a.user_group_id IS NULL)
      OR EXISTS (SELECT 1 FROM device_group_member m WHERE m.device_id = @device_id AND m.device_group_id = a.device_group_id))
) t
WHERE (s.device_id IS NOT NULL OR t.intents IS NOT NULL)
  AND (sqlc.narg(q_pattern)::text IS NULL OR e.name ILIKE sqlc.narg(q_pattern)::text ESCAPE '\')
ORDER BY e.name, e.id, s.scope;

-- name: GetDeviceSoftwareTarget :one
-- The platform a device's packages resolve for (software.Resolve): the canonical lowercase os-release keys and the
-- reported architecture.
SELECT coalesce(d.os_release ->> 'id', '')::text AS os_id, coalesce(d.os_release ->> 'version_id', '')::text AS os_version_id,
       coalesce(s.arch, '')::text AS arch, coalesce(s.software_truncated, false)::boolean AS truncated
FROM device d LEFT JOIN device_status s ON s.device_id = d.id
WHERE d.id = @id;

-- name: ListSoftwareCatalogDevices :many
-- The active devices the entry is assigned to, through the organization or one of their groups, and those that reported a
-- row for it (an entry that reaches a device through its owners, plan M13b), with the rows they reported for it
-- (state '': none; one per scope) and the intents of the assignments (NULL: none). The page filters and sorts the derived
-- states in memory (ADR 0028), so the query returns every match in hostname order.
SELECT d.id AS device_id, d.hostname, coalesce(d.name, '')::text AS name,
       coalesce((SELECT array_agg(g.device_group_id ORDER BY g.device_group_id) FROM device_group_member g
                 WHERE g.device_id = d.id), '{}')::uuid[] AS device_group_ids,
       coalesce(d.os_release ->> 'id', '')::text AS os_id,
       coalesce(d.os_release ->> 'version_id', '')::text AS os_version_id, coalesce(ds.arch, '')::text AS arch,
       t.intents, coalesce(st.package, '')::text AS package, coalesce(st.intent, '')::text AS intent,
       coalesce(st.state, '')::text AS state, coalesce(st.version, '')::text AS version, coalesce(st.reason, '')::text AS reason,
       coalesce(st.error, '')::text AS error, coalesce(st.scope, '')::text AS scope, st.reported_at
FROM device d
LEFT JOIN device_status ds ON ds.device_id = d.id
LEFT JOIN device_software_status st ON st.device_id = d.id AND st.catalog_entry_id = @catalog_entry_id
CROSS JOIN LATERAL (
  SELECT array_agg(DISTINCT a.intent ORDER BY a.intent)::text[] AS intents
  FROM software_assignment a
  WHERE a.catalog_entry_id = @catalog_entry_id
    AND ((a.device_group_id IS NULL AND a.user_id IS NULL AND a.user_group_id IS NULL)
      OR EXISTS (SELECT 1 FROM device_group_member m WHERE m.device_id = d.id AND m.device_group_id = a.device_group_id))
) t
WHERE d.state = 'active' AND (st.device_id IS NOT NULL OR t.intents IS NOT NULL)
  AND (sqlc.narg(device_group_id)::uuid IS NULL OR EXISTS (
        SELECT 1 FROM device_group_member m WHERE m.device_id = d.id AND m.device_group_id = sqlc.narg(device_group_id)::uuid))
  AND (sqlc.narg(q_pattern)::text IS NULL OR d.hostname ILIKE sqlc.narg(q_pattern)::text ESCAPE '\')
ORDER BY d.hostname, d.id, st.scope;

-- name: ListUserSoftware :many
-- The assignments that target a user (plan M13b decision 6): directly or through a user group the user is a member
-- of, with the entry's name and the group's name (empty for a direct target).
SELECT a.id, a.catalog_entry_id, e.name, a.intent, a.user_group_id, coalesce(g.name, '')::text AS user_group_name,
       a.reason
FROM software_assignment a
JOIN software_catalog_entry e ON e.id = a.catalog_entry_id
LEFT JOIN user_group g ON g.id = a.user_group_id
WHERE (a.user_id = @user_id
    OR EXISTS (SELECT 1 FROM user_group_member m WHERE m.group_id = a.user_group_id AND m.user_id = @user_id))
  AND (sqlc.narg(q_pattern)::text IS NULL OR e.name ILIKE sqlc.narg(q_pattern)::text ESCAPE '\')
  AND (sqlc.narg(intent)::text IS NULL OR a.intent = sqlc.narg(intent)::text)
ORDER BY
  CASE WHEN @sort::text = 'name' THEN e.name END ASC,
  CASE WHEN @sort::text = '-name' THEN e.name END DESC,
  CASE WHEN @sort::text = 'intent' THEN a.intent END ASC,
  CASE WHEN @sort::text = '-intent' THEN a.intent END DESC,
  a.id
LIMIT @max_rows OFFSET @skip_rows;

-- name: CountUserSoftware :one
SELECT count(*) FROM (
  SELECT 1 FROM software_assignment a JOIN software_catalog_entry e ON e.id = a.catalog_entry_id
  WHERE (a.user_id = @user_id
      OR EXISTS (SELECT 1 FROM user_group_member m WHERE m.group_id = a.user_group_id AND m.user_id = @user_id))
    AND (sqlc.narg(q_pattern)::text IS NULL OR e.name ILIKE sqlc.narg(q_pattern)::text ESCAPE '\')
    AND (sqlc.narg(intent)::text IS NULL OR a.intent = sqlc.narg(intent)::text)
  LIMIT @count_limit
) matching;
