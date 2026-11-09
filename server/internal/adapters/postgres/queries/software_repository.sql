-- name: GetSoftwareRepository :one
-- The repository of the context's organization (one row at most, RLS).
SELECT * FROM software_repository LIMIT 1;

-- name: InsertSoftwareRepository :execrows
-- Creates the repository with its first credential and queues the first rebuild, unless it exists (plan M13c
-- amendment 2026-11-09, A10-21): the worker generates the signing key at that rebuild.
INSERT INTO software_repository (organization_id, credential_ciphertext, credential_sha256, rebuild_requested_at)
VALUES (@organization_id, @credential_ciphertext, @credential_sha256, now())
ON CONFLICT (organization_id) DO NOTHING;

-- name: GetSoftwareRepositoryForUpdate :one
SELECT * FROM software_repository LIMIT 1 FOR UPDATE;

-- name: RotateSoftwareRepositoryCredential :one
-- The previous secret stays valid until @previous_expires_at (plan M13c §3.8 L6).
UPDATE software_repository SET previous_credential_sha256 = credential_sha256,
  previous_credential_expires_at = @previous_expires_at, credential_ciphertext = @credential_ciphertext,
  credential_sha256 = @credential_sha256, credential_rotated_at = now(), updated_at = now()
WHERE organization_id = @organization_id
RETURNING *;

-- name: RequestSoftwareRepositoryRebuild :exec
UPDATE software_repository SET rebuild_requested_at = now(), updated_at = now() WHERE organization_id = @organization_id;

-- name: GetPaddockSoftwareSource :one
-- The system source of the organization's Paddock repository (kind paddock, at most one).
SELECT * FROM software_source WHERE kind = 'paddock';

-- name: InsertSoftwarePackage :one
INSERT INTO software_package (id, organization_id, package, version, architecture, size, sha256, object_key, control,
  uploaded_by)
VALUES (@id, @organization_id, @package, @version, @architecture, @size, @sha256, @object_key, @control, @uploaded_by)
RETURNING *;

-- name: GetSoftwarePackage :one
SELECT * FROM software_package WHERE id = @id;

-- name: DeleteSoftwarePackage :execrows
DELETE FROM software_package WHERE id = @id;

-- name: ListPaddockCatalogPackages :many
-- The package references of the catalog entries whose source is the Paddock repository.
SELECT e.id, e.packages FROM software_catalog_entry e JOIN software_source s ON s.id = e.source_id
WHERE s.kind = 'paddock';

-- name: ListSoftwarePackages :many
SELECT * FROM software_package
WHERE (sqlc.narg(q_pattern)::text IS NULL OR package ILIKE sqlc.narg(q_pattern)::text ESCAPE '\'
    OR version ILIKE sqlc.narg(q_pattern)::text ESCAPE '\')
  AND (sqlc.narg(architecture)::text IS NULL OR architecture = sqlc.narg(architecture)::text)
ORDER BY
  CASE WHEN @sort::text = 'package' THEN package END ASC,
  CASE WHEN @sort::text = '-package' THEN package END DESC,
  CASE WHEN @sort::text = 'size' THEN size END ASC,
  CASE WHEN @sort::text = '-size' THEN size END DESC,
  CASE WHEN @sort::text = 'uploaded_at' THEN uploaded_at END ASC,
  CASE WHEN @sort::text = '-uploaded_at' THEN uploaded_at END DESC,
  id
LIMIT @max_rows OFFSET @skip_rows;

-- name: CountSoftwarePackages :one
SELECT count(*) FROM (
  SELECT 1 FROM software_package
  WHERE (sqlc.narg(q_pattern)::text IS NULL OR package ILIKE sqlc.narg(q_pattern)::text ESCAPE '\'
      OR version ILIKE sqlc.narg(q_pattern)::text ESCAPE '\')
    AND (sqlc.narg(architecture)::text IS NULL OR architecture = sqlc.narg(architecture)::text)
  LIMIT @count_limit
) matching;

-- name: CountAllSoftwarePackages :one
SELECT count(*) FROM software_package;
