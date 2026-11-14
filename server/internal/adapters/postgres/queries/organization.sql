-- name: InsertOrganization :one
INSERT INTO organization (id, slug, name, status)
VALUES (@id, @slug, @name, @status)
RETURNING *;

-- name: GetOrganization :one
SELECT * FROM organization WHERE id = @id;

-- A deleted organization's tombstone keeps its slug (plan M17 decision 17); only a live organization owns it.
-- name: GetOrganizationBySlug :one
SELECT * FROM organization WHERE slug = @slug AND status <> 'deleted';

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

-- Worker and compiler loops: organization IDs without an organization context (SECURITY DEFINER function).
-- name: ListOrganizationIDs :many
SELECT id::uuid FROM paddock_organization_ids() AS id;

-- Every organization's slug for the platform pool (End all sessions lists the role groups, plan M8f decision 16).
-- name: ListOrganizationSlugs :many
SELECT slug FROM organization WHERE status <> 'deleted' ORDER BY slug;

-- Organization domains (plan M3a decision 1). The platform use case serializes domain changes with this advisory
-- lock, so two organizations can never claim the same domain concurrently.
-- name: LockOrganizationDomains :exec
SELECT pg_advisory_xact_lock(hashtext('paddock.organization.domains'));

-- name: ListOrganizationsClaimingDomains :many
SELECT id, slug FROM organization WHERE domains && @domains::text[] AND id <> @id AND status <> 'deleted' ORDER BY slug;

-- name: UpdateOrganizationDomains :one
UPDATE organization SET domains = @domains, updated_at = now() WHERE id = @id RETURNING *;

-- Organization offboarding (plan M17 decisions 1, 5, 6, 17; ADR 0052 decision 1). A deletion is pending while the
-- organization is active (or provisioning_failed) with delete_after set. Each transition is conditional on the state
-- it leaves, so a second request, a late cancel or a repeated step finds no row (pgx.ErrNoRows).

-- name: RequestOrganizationDeletion :one
UPDATE organization
SET deletion_requested_at = now(), deletion_requested_by = @requested_by, deletion_reason = @reason,
    delete_after = now() + make_interval(days => @grace_days::int), updated_at = now()
WHERE id = @id AND status IN ('active', 'provisioning_failed') AND delete_after IS NULL
RETURNING *;

-- name: CancelOrganizationDeletion :one
UPDATE organization
SET deletion_requested_at = NULL, deletion_requested_by = NULL, deletion_reason = NULL, delete_after = NULL,
    deletion_uninstalls_issued = NULL, deletion_uninstalls_skipped = NULL, updated_at = now()
WHERE id = @id AND status IN ('active', 'provisioning_failed') AND delete_after IS NOT NULL
RETURNING *;

-- The request's second transaction records the uninstall counts (plan M17 amendment c item 1); it finds no row when
-- the request it belongs to no longer is the pending one.
-- name: SetOrganizationDeletionUninstalls :one
UPDATE organization
SET deletion_uninstalls_issued = @issued::int, deletion_uninstalls_skipped = @skipped::int, updated_at = now()
WHERE id = @id AND status IN ('active', 'provisioning_failed') AND deletion_requested_at = @requested_at
  AND deletion_uninstalls_issued IS NULL
RETURNING *;

-- Cancelling a deletion holds the organization row while it withdraws the uninstalls, so the worker cannot start the
-- deletion in between.
-- FOR NO KEY UPDATE: it waits for and blocks the worker's UPDATE organization, but not the FOR KEY SHARE of the
-- foreign-key checks of the organization's inserts (plan M17 amendment e point 4).
-- name: LockOrganization :one
SELECT * FROM organization WHERE id = @id FOR NO KEY UPDATE;

-- A request whose uninstalls are still being issued (counts NULL) is not due yet: the deletion never starts before
-- every device was told to leave.
-- name: ListDueOrganizationDeletions :many
SELECT id FROM organization
WHERE status IN ('active', 'provisioning_failed') AND delete_after <= now() AND deletion_uninstalls_issued IS NOT NULL
ORDER BY delete_after, id;

-- name: StartOrganizationDeletion :one
UPDATE organization
SET status = 'deleting', offboarding_step = @step, offboarding_error_code = NULL, updated_at = now()
WHERE id = @id AND status IN ('active', 'provisioning_failed') AND delete_after <= now()
  AND deletion_uninstalls_issued IS NOT NULL
RETURNING *;

-- name: ListDeletingOrganizations :many
SELECT * FROM organization WHERE status = 'deleting' ORDER BY delete_after, id;

-- name: AdvanceOrganizationOffboardingStep :one
UPDATE organization SET offboarding_step = @next_step, offboarding_error_code = NULL, updated_at = now()
WHERE id = @id AND status = 'deleting' AND offboarding_step = @current_step
RETURNING *;

-- name: SetOrganizationOffboardingError :one
UPDATE organization SET offboarding_error_code = @error_code, updated_at = now()
WHERE id = @id AND status = 'deleting'
RETURNING *;

-- name: TombstoneOrganization :one
UPDATE organization
SET status = 'deleted', deleted_at = now(), domains = '{}', offboarding_error_code = NULL, idp_ensured_at = NULL,
    idp_ensure_revision = NULL, updated_at = now()
WHERE id = @id AND status = 'deleting'
RETURNING *;

-- Identity rounds (plan M17 decision 20): the worker records a successful EnsureOrganization in the organization's
-- own context; creation, a domain change or an Authentik error clears it to force the next ensure.

-- name: MarkOrganizationIdentityEnsured :exec
UPDATE organization SET idp_ensured_at = now(), idp_ensure_revision = @revision WHERE id = @id;

-- name: ClearOrganizationIdentityEnsured :exec
UPDATE organization SET idp_ensured_at = NULL WHERE id = @id;
