-- name: InsertOrganization :one
INSERT INTO organization (id, slug, name, status)
VALUES (@id, @slug, @name, @status)
RETURNING *;

-- name: GetOrganization :one
SELECT * FROM organization WHERE id = @id;

-- name: GetOrganizationBySlug :one
SELECT * FROM organization WHERE slug = @slug;

-- name: ListOrganizations :many
SELECT * FROM organization
WHERE (sqlc.narg(before)::uuid IS NULL OR id < sqlc.narg(before)::uuid)
ORDER BY id DESC
LIMIT @max_rows;

-- name: UpdateOrganizationStatus :one
UPDATE organization SET status = @status, name = @name, updated_at = now()
WHERE id = @id
RETURNING *;

-- Returns uuid.Nil when no active organization has this slug.
-- name: OrganizationIDBySlug :one
SELECT coalesce(paddock_org_id_by_slug(@slug), '00000000-0000-0000-0000-000000000000'::uuid)::uuid AS id;
