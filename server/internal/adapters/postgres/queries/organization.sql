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

-- A status change is the (re)creation of the organization: it clears idp_ensured_at, so the first identity round after
-- it checks the Authentik objects in full (plan M17 decision 20).
-- name: UpdateOrganizationStatus :one
UPDATE organization SET status = @status, name = @name, idp_ensured_at = NULL, updated_at = now()
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

-- A domain change clears idp_ensured_at, so the next identity round checks the Authentik objects in full (plan M17
-- decision 20).
-- An organization in an offboarding status keeps its domains: a tombstone's were cleared by finalize (PDK-1053).
-- name: UpdateOrganizationDomains :one
UPDATE organization SET domains = @domains, idp_ensured_at = NULL, updated_at = now()
WHERE id = @id AND status NOT IN ('deleting', 'deleted') RETURNING *;

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

-- The organizations the deletion job works on: every deleting one, and a deleted one whose tombstone is written but
-- whose organization.deleted is not recorded yet (offboarding_step still tombstone).
-- name: ListOffboardingOrganizations :many
SELECT * FROM organization
WHERE status = 'deleting' OR (status = 'deleted' AND offboarding_step = 'tombstone')
ORDER BY delete_after, id;

-- A step's checkpoint (plan M17 decision 6): the next step, the cleared error and what the step removed, only while the
-- organization is still at that step, so a step completes once.
-- name: CompleteOrganizationOffboardingStep :one
UPDATE organization
SET offboarding_step = @next_step, offboarding_error_code = NULL, updated_at = now(),
    offboarding_counts = offboarding_counts || jsonb_build_object(@current_step::text,
      coalesce((offboarding_counts ->> @current_step::text)::bigint, 0) + @added::bigint)
WHERE id = @id AND status = 'deleting' AND offboarding_step = @current_step
RETURNING *;

-- A failed attempt of a step: its error code and what it removed before failing.
-- name: FailOrganizationOffboardingStep :one
UPDATE organization
SET offboarding_error_code = @error_code, updated_at = now(),
    offboarding_counts = offboarding_counts || jsonb_build_object(@step::text,
      coalesce((offboarding_counts ->> @step::text)::bigint, 0) + @added::bigint)
WHERE id = @id AND status = 'deleting' AND offboarding_step = @step
RETURNING *;

-- Progress of the database step, stored per batch with the delete_order it reached (plan M17 amendment 2026-11-16 q
-- point 6), so neither a crash nor a yield at the round budget loses the count of what is gone or where the step
-- continues; a NULL position starts at the first registered table. A stored batch is progress, so it clears the error
-- code of an earlier failed attempt and with it the paddock_offboarding_step_failing gauge.
-- name: SaveOrganizationOffboardingDatabaseBatch :exec
UPDATE organization
SET offboarding_error_code = NULL,
    offboarding_counts = offboarding_counts || jsonb_build_object('database',
      coalesce((offboarding_counts ->> 'database')::bigint, 0) + @added::bigint),
    offboarding_db_order = sqlc.narg(db_order)::int
WHERE id = @id AND status = 'deleting' AND offboarding_step = 'database';

-- Step audit_final (plan M17 amendment o point 1): the claim of the one organization.audit_retirement_requested,
-- which also starts the step's wait.
-- name: ClaimOrganizationAuditRetirement :one
UPDATE organization SET audit_retirement_requested_at = now(), updated_at = now()
WHERE id = @id AND status = 'deleting' AND offboarding_step = 'audit_final' AND audit_retirement_requested_at IS NULL
RETURNING *;

-- The audit writer's acknowledgement (amendment o point 6), applied once and only while the organization is deleting;
-- a repeated acknowledgement changes nothing.
-- name: SetOrganizationAuditFinal :execrows
UPDATE organization SET audit_final_verified_at = @final_verified_at, audit_final_outcome = @final_outcome,
    updated_at = now()
WHERE id = @id AND status = 'deleting' AND audit_final_verified_at IS NULL;

-- organization.deleted is recorded exactly once, together with this: the tombstone no longer waits for its event.
-- name: CloseOrganizationOffboarding :one
UPDATE organization SET offboarding_step = NULL, updated_at = now()
WHERE id = @id AND status = 'deleted' AND offboarding_step = 'tombstone'
RETURNING *;

-- name: TombstoneOrganization :one
UPDATE organization
SET status = 'deleted', deleted_at = now(), domains = '{}', offboarding_error_code = NULL, idp_ensured_at = NULL,
    idp_ensure_revision = NULL, updated_at = now()
WHERE id = @id AND status = 'deleting'
RETURNING *;

-- Identity rounds (plan M17 decision 20): the worker records a successful EnsureOrganization in the organization's
-- own context; creation, a domain change or an Authentik error clears it to force the next ensure.

-- The mark applies only while the row is as the round read it: a domain change or a re-creation during the ensure
-- bumped updated_at and cleared the mark, and that clear must survive.
-- name: MarkOrganizationIdentityEnsured :exec
UPDATE organization SET idp_ensured_at = now(), idp_ensure_revision = @revision
WHERE id = @id AND updated_at = @seen_updated_at;

-- name: ClearOrganizationIdentityEnsured :exec
UPDATE organization SET idp_ensured_at = NULL WHERE id = @id;

-- Encrypted recovery export (plan M17 amendment b decisions 21 and 24, amendments g and h, migration 00133). An export
-- is open while the deletion is pending and delete_after lies more than the cutoff (app.RecoveryExportCutoff) ahead on
-- the database's clock, the clock of the worker's delete_after <= now(): an export then always finishes while the
-- deletion is still pending (amendment h point 1). Reserving counts one export of the pending deletion atomically, so
-- concurrent exports cannot pass the limit together; a count of an earlier (cancelled) deletion starts again at one.
-- No row: the export is not open or the limit is reached.

-- name: ReserveRecoveryExport :one
UPDATE organization
SET recovery_exports = CASE WHEN recovery_exports_since IS NOT DISTINCT FROM deletion_requested_at
                            THEN recovery_exports + 1 ELSE 1 END,
    recovery_exports_since = deletion_requested_at
WHERE id = @id AND status IN ('active', 'provisioning_failed') AND delete_after IS NOT NULL
  AND delete_after > now() + make_interval(secs => @cutoff_seconds::float8)
  AND (recovery_exports_since IS DISTINCT FROM deletion_requested_at OR recovery_exports < @max_exports::int)
RETURNING recovery_exports, recovery_exports_since;

-- A failed export gives its reservation back, only within the deletion it was reserved in.
-- name: ReleaseRecoveryExport :exec
UPDATE organization SET recovery_exports = recovery_exports - 1
WHERE id = @id AND recovery_exports_since = @since::timestamptz AND recovery_exports > 0;

-- Whether the export is open (see above): the api before it reserves, and the escrow-reader inside the organization
-- before it decrypts (it may read only these columns, migration 00133).
-- name: RecoveryExportOpen :one
SELECT EXISTS (SELECT 1 FROM organization WHERE id = @id AND status IN ('active', 'provisioning_failed')
  AND delete_after IS NOT NULL AND delete_after > now() + make_interval(secs => @cutoff_seconds::float8));
