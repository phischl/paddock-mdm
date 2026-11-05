-- Backup targets, schedule and runs (plan M15 decisions 10–14). Platform scope (paddock_platform). No query of the api
-- returns credentials_ciphertext: the api only encrypts credentials, the backup role decrypts them.

-- List queries (ADR 0018): see device_group.sql. A target with deleted_at waits for the host to remove its volume
-- (decision 10) and is no longer shown.

-- name: ListBackupTargets :many
SELECT id, name, type, enabled, settings, (credentials_ciphertext IS NOT NULL)::boolean AS has_credentials,
       host_state, host_revision, test_requested_at, last_test_at, last_test_ok, last_test_error, created_by,
       created_at, updated_at
FROM backup_target
WHERE deleted_at IS NULL
  AND (sqlc.narg(q_pattern)::text IS NULL OR name ILIKE sqlc.narg(q_pattern)::text ESCAPE '\')
  AND (sqlc.narg(types)::text[] IS NULL OR type = ANY(sqlc.narg(types)::text[]))
  AND (sqlc.narg(enabled)::boolean IS NULL OR enabled = sqlc.narg(enabled)::boolean)
  AND (sqlc.narg(host_states)::text[] IS NULL OR host_state = ANY(sqlc.narg(host_states)::text[]))
ORDER BY
  CASE WHEN @sort::text = 'name' THEN name END ASC,
  CASE WHEN @sort::text = '-name' THEN name END DESC,
  CASE WHEN @sort::text = 'type' THEN type END ASC,
  CASE WHEN @sort::text = '-type' THEN type END DESC,
  CASE WHEN @sort::text = 'created_at' THEN created_at END ASC,
  CASE WHEN @sort::text = '-created_at' THEN created_at END DESC,
  id
LIMIT @max_rows OFFSET @skip_rows;

-- name: CountBackupTargets :one
SELECT count(*) FROM (
  SELECT 1 FROM backup_target
  WHERE deleted_at IS NULL
    AND (sqlc.narg(q_pattern)::text IS NULL OR name ILIKE sqlc.narg(q_pattern)::text ESCAPE '\')
    AND (sqlc.narg(types)::text[] IS NULL OR type = ANY(sqlc.narg(types)::text[]))
    AND (sqlc.narg(enabled)::boolean IS NULL OR enabled = sqlc.narg(enabled)::boolean)
    AND (sqlc.narg(host_states)::text[] IS NULL OR host_state = ANY(sqlc.narg(host_states)::text[]))
  LIMIT @count_limit
) matching;

-- name: GetBackupTarget :one
SELECT id, name, type, enabled, settings, (credentials_ciphertext IS NOT NULL)::boolean AS has_credentials,
       host_state, host_revision, test_requested_at, last_test_at, last_test_ok, last_test_error, created_by,
       created_at, updated_at
FROM backup_target WHERE id = @id AND deleted_at IS NULL;

-- name: LockBackupTarget :one
SELECT id, name, type, enabled, settings, (credentials_ciphertext IS NOT NULL)::boolean AS has_credentials,
       host_state, host_revision
FROM backup_target WHERE id = @id AND deleted_at IS NULL
FOR UPDATE;

-- name: InsertBackupTarget :exec
INSERT INTO backup_target (id, name, type, enabled, settings, credentials_ciphertext, host_state, host_revision, created_by)
VALUES (@id, @name, @type, @enabled, @settings, sqlc.narg(credentials_ciphertext), @host_state, 1, @created_by);

-- name: UpdateBackupTarget :exec
-- A NULL credentials_ciphertext keeps the stored credentials (an update without the password or secret key).
UPDATE backup_target SET
  name = @name, enabled = @enabled, settings = @settings,
  credentials_ciphertext = coalesce(sqlc.narg(credentials_ciphertext), credentials_ciphertext),
  host_state = @host_state, host_revision = @host_revision, updated_at = now()
WHERE id = @id;

-- name: SetBackupTargetEnabled :exec
UPDATE backup_target SET enabled = @enabled, updated_at = now() WHERE id = @id;

-- A volume target stays until ./paddock backup-target apply removed its volume; disabled, so no mirror writes to it.
-- name: MarkBackupTargetDeleted :exec
UPDATE backup_target SET deleted_at = now(), enabled = false, updated_at = now() WHERE id = @id;

-- name: DeleteBackupTarget :exec
DELETE FROM backup_target WHERE id = @id;

-- name: RequestBackupTargetTest :exec
UPDATE backup_target SET test_requested_at = now() WHERE id = @id;

-- name: ListBackupTargetStatus :many
SELECT target_id, kind, last_success_at, last_error, last_error_at, bytes
FROM backup_target_status WHERE target_id = ANY(@target_ids::uuid[])
ORDER BY target_id, kind;

-- name: AllBackupTargets :many
SELECT id, name, type, enabled, settings, (credentials_ciphertext IS NOT NULL)::boolean AS has_credentials,
       host_state, host_revision, test_requested_at, last_test_at, last_test_ok, last_test_error, created_by,
       created_at, updated_at
FROM backup_target WHERE deleted_at IS NULL ORDER BY name, id;

-- name: GetBackupSchedule :one
SELECT * FROM backup_schedule WHERE singleton;

-- name: UpsertBackupSchedule :one
INSERT INTO backup_schedule (singleton, full_interval_hours, openbao_interval_hours, fleet_interval_hours,
  escrow_interval_hours, retention_full, openbao_keep_days, fleet_keep_days, updated_by, updated_at)
VALUES (true, @full_interval_hours, @openbao_interval_hours, @fleet_interval_hours, @escrow_interval_hours,
  @retention_full, @openbao_keep_days, @fleet_keep_days, @updated_by, now())
ON CONFLICT (singleton) DO UPDATE SET
  full_interval_hours = EXCLUDED.full_interval_hours, openbao_interval_hours = EXCLUDED.openbao_interval_hours,
  fleet_interval_hours = EXCLUDED.fleet_interval_hours, escrow_interval_hours = EXCLUDED.escrow_interval_hours,
  retention_full = EXCLUDED.retention_full, openbao_keep_days = EXCLUDED.openbao_keep_days,
  fleet_keep_days = EXCLUDED.fleet_keep_days, updated_by = EXCLUDED.updated_by, updated_at = now()
RETURNING *;

-- name: InsertBackupRun :one
INSERT INTO backup_run (id, kind, label, state, requested_by) VALUES (@id, @kind, @label, 'requested', @requested_by)
RETURNING *;

-- A requested run has no started_at yet: NULLS FIRST in descending order, so it leads the default sort.
-- name: ListBackupRuns :many
SELECT * FROM backup_run
WHERE (sqlc.narg(q_pattern)::text IS NULL OR kind ILIKE sqlc.narg(q_pattern)::text ESCAPE '\'
       OR label ILIKE sqlc.narg(q_pattern)::text ESCAPE '\')
  AND (sqlc.narg(kinds)::text[] IS NULL OR kind = ANY(sqlc.narg(kinds)::text[]))
  AND (sqlc.narg(outcomes)::text[] IS NULL OR outcome = ANY(sqlc.narg(outcomes)::text[]))
  AND (sqlc.narg(target_id)::text IS NULL
       OR targets @> jsonb_build_array(jsonb_build_object('target_id', sqlc.narg(target_id)::text)))
ORDER BY
  CASE WHEN @sort::text = 'started_at' THEN started_at END ASC,
  CASE WHEN @sort::text = '-started_at' THEN started_at END DESC,
  CASE WHEN @sort::text = 'kind' THEN kind END ASC,
  CASE WHEN @sort::text = '-kind' THEN kind END DESC,
  CASE WHEN @sort::text = 'outcome' THEN outcome END ASC,
  CASE WHEN @sort::text = '-outcome' THEN outcome END DESC,
  id
LIMIT @max_rows OFFSET @skip_rows;

-- name: CountBackupRuns :one
SELECT count(*) FROM (
  SELECT 1 FROM backup_run
  WHERE (sqlc.narg(q_pattern)::text IS NULL OR kind ILIKE sqlc.narg(q_pattern)::text ESCAPE '\'
         OR label ILIKE sqlc.narg(q_pattern)::text ESCAPE '\')
    AND (sqlc.narg(kinds)::text[] IS NULL OR kind = ANY(sqlc.narg(kinds)::text[]))
    AND (sqlc.narg(outcomes)::text[] IS NULL OR outcome = ANY(sqlc.narg(outcomes)::text[]))
    AND (sqlc.narg(target_id)::text IS NULL
         OR targets @> jsonb_build_array(jsonb_build_object('target_id', sqlc.narg(target_id)::text)))
  LIMIT @count_limit
) matching;

-- `paddock-server backup now --wait` follows its runs.
-- name: GetBackupRun :one
SELECT * FROM backup_run WHERE id = @id;

-- name: LatestBackupRuns :many
SELECT DISTINCT ON (kind) * FROM backup_run
ORDER BY kind, coalesce(started_at, created_at) DESC, id DESC;

-- name: LastSucceededBackupRuns :many
SELECT DISTINCT ON (kind) * FROM backup_run WHERE outcome = 'succeeded'
ORDER BY kind, finished_at DESC NULLS LAST, id DESC;

-- Key reads of the overview and of a run request (the key use cases are plan M15 decision 7). Never the ciphertext or
-- the challenge hash; the challenge positions only while the key waits for its confirmation (amendment 2026-11-04).
-- name: ActiveBackupKeyID :one
SELECT key_id FROM backup_key WHERE state = 'confirmed';

-- name: ListBackupKeyStates :many
SELECT key_id, fingerprint, state, created_at, created_by, confirmed_at, confirmed_by, retired_at, attempts, legacy,
       (CASE WHEN state = 'unconfirmed' THEN challenge_positions END)::int[] AS pending_positions
FROM backup_key WHERE state IN ('confirmed', 'unconfirmed', 'retired')
ORDER BY created_at DESC, key_id;
