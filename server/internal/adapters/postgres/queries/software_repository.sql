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

-- name: RequestSoftwareRepositoryKeyRotation :exec
-- The worker generates the new key at its next round (plan M13c decision 12, amendment 2026-11-09 (PDK-812)).
UPDATE software_repository SET key_rotation_requested_at = now(), rebuild_requested_at = now(), updated_at = now()
WHERE organization_id = @organization_id;

-- name: StoreSoftwareRepositorySigningKey :execrows
-- The worker's new signing key (PDK-813), unless another replica stored one since it read @expected_fingerprint. A
-- current key that the system source carries (published) becomes the previous one, which signs the index alongside the
-- new one for 30 days from the publication of the new one (§3.8 L5). A current key that was never published is replaced
-- and the previous key stays: no device can rely on the unpublished key, but devices still rely on the previous one, so
-- a rotation retried after a failed build never drops it. The rotation request it serves is cleared; a later one stays.
UPDATE software_repository SET
  previous_public_key = CASE WHEN signing_fingerprint = src.fingerprint THEN signing_public_key ELSE previous_public_key END,
  previous_fingerprint = CASE WHEN signing_fingerprint = src.fingerprint THEN signing_fingerprint ELSE previous_fingerprint END,
  previous_private_ciphertext = CASE WHEN signing_fingerprint = src.fingerprint THEN signing_private_ciphertext
    ELSE previous_private_ciphertext END,
  previous_retired_at = CASE WHEN signing_fingerprint = src.fingerprint THEN NULL ELSE previous_retired_at END,
  signing_public_key = @signing_public_key, signing_fingerprint = @signing_fingerprint,
  signing_private_ciphertext = @signing_private_ciphertext,
  key_rotation_requested_at = CASE WHEN key_rotation_requested_at IS NOT DISTINCT FROM sqlc.narg(served_rotation)::timestamptz
    THEN NULL ELSE key_rotation_requested_at END,
  updated_at = now()
FROM (SELECT (SELECT fingerprint FROM software_source WHERE kind = 'paddock') AS fingerprint) src
WHERE software_repository.organization_id = @organization_id
  AND software_repository.signing_fingerprint IS NOT DISTINCT FROM sqlc.narg(expected_fingerprint)::text;

-- name: MarkSoftwareRepositoryBuilt :execrows
-- A published build: the generation read (@built_on) plus one; the rebuild request it served is cleared, a later one
-- stays queued. The build moves the system source to the current key in the same transaction, so the 30 days of a
-- previous key start here, at the first publication of its successor, not when the successor was generated (§3.8 L5).
UPDATE software_repository SET generation = generation + 1, last_built_at = now(), last_error = NULL,
  previous_retired_at = CASE WHEN previous_fingerprint IS NOT NULL THEN coalesce(previous_retired_at, now()) END,
  rebuild_requested_at = CASE WHEN rebuild_requested_at IS NOT DISTINCT FROM sqlc.narg(served_request)::timestamptz
    THEN NULL ELSE rebuild_requested_at END,
  updated_at = now()
WHERE organization_id = @organization_id AND generation = @built_on;

-- name: MarkSoftwareRepositoryBuildFailed :execrows
-- Records a failed build; 0 rows when the same error is already recorded, so a failure repeated every round is audited
-- once.
UPDATE software_repository SET last_error = @last_error, updated_at = now()
WHERE organization_id = @organization_id AND last_error IS DISTINCT FROM @last_error;

-- name: ExpireSoftwareRepositoryPreviousKey :exec
-- The previous signing key signs the index alongside the current one until @retired_before (30 days after its
-- successor was first published, ADR 0050 decision 3, §3.8 L5; NULL while it is not, so it never expires then); dropping it queues a rebuild, so the index is then signed by the current key
-- alone.
UPDATE software_repository SET previous_public_key = NULL, previous_fingerprint = NULL, previous_retired_at = NULL,
  previous_private_ciphertext = NULL, rebuild_requested_at = now(), updated_at = now()
WHERE organization_id = @organization_id AND previous_retired_at < @retired_before;

-- name: ListSoftwarePackagesForIndex :many
-- Every stored package of the organization in the order of the published index.
SELECT * FROM software_package ORDER BY package, version, architecture, id;

-- name: InsertPaddockSoftwareSource :one
-- The system source of the organization's Paddock repository, created by the worker with the first published build.
INSERT INTO software_source (id, organization_id, slug, name, kind, uris, suites, components, architectures,
  signing_key, fingerprint)
VALUES (@id, @organization_id, @slug, @name, 'paddock', @uris, '{paddock}', '{main}', '{}', @signing_key, @fingerprint)
RETURNING *;

-- name: UpdatePaddockSoftwareSource :one
UPDATE software_source SET uris = @uris, signing_key = @signing_key, fingerprint = @fingerprint, updated_at = now()
WHERE kind = 'paddock' AND id = @id
RETURNING *;
