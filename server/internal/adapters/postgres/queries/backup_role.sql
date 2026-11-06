-- Queries of the backup role (plan M15 decisions 15–16), role paddock_backup through db.BackupPool.InBackup. The role
-- reads the active key's ciphertext and the targets' credentials, which no query of the api returns.

-- name: BackupRoleActiveKey :one
SELECT key_id, ciphertext, fingerprint FROM backup_key WHERE state = 'confirmed';

-- Every key the database knows, with its retirement time: expire and the mirror keep a retired key's repository until
-- it is old enough, and hold a repository path no key names (plan M15, amendment 2026-11-05, A1–A3).
-- name: BackupRoleKeys :many
SELECT key_id, state, retired_at FROM backup_key ORDER BY key_id;

-- The audited evidence that a device's escrow was destroyed on purpose (the revocation-issuer's Destroy): the only
-- reason an escrowed header copy may leave the backup set (plan M15, amendment 2026-11-05, A2 note b; migration 00107
-- policy backup_escrow_evidence). Only the organization, the device and the time are read.
-- name: BackupRoleEscrowEvidence :many
SELECT organization_id, (target->>'id')::text AS device_id, max(finished_at)::timestamptz AS destroyed_at
FROM action
WHERE code = 'device.escrow_destroyed' AND status = 'finished' AND outcome = 'success'
  AND target->>'type' = 'device' AND finished_at IS NOT NULL
GROUP BY organization_id, target->>'id';

-- name: BackupRoleTargets :many
SELECT id, name, type, enabled, settings, credentials_ciphertext, host_state, host_revision, test_requested_at
FROM backup_target WHERE deleted_at IS NULL ORDER BY name, id;

-- name: BackupRoleSetHostState :exec
UPDATE backup_target SET host_state = @host_state WHERE id = @id AND host_state <> @host_state;

-- name: BackupRoleSetTestResult :exec
UPDATE backup_target SET test_requested_at = NULL, last_test_at = now(), last_test_ok = @ok,
  last_test_error = sqlc.narg(error_class)
WHERE id = @id;

-- name: BackupRoleUpsertTargetStatus :exec
INSERT INTO backup_target_status (target_id, kind, last_success_at, last_error, last_error_at, bytes)
VALUES (@target_id, @kind, sqlc.narg(last_success_at), sqlc.narg(last_error),
  CASE WHEN sqlc.narg(last_error)::text IS NULL THEN NULL ELSE now() END, @bytes)
ON CONFLICT (target_id, kind) DO UPDATE SET
  last_success_at = coalesce(EXCLUDED.last_success_at, backup_target_status.last_success_at),
  last_error = EXCLUDED.last_error,
  last_error_at = coalesce(EXCLUDED.last_error_at, backup_target_status.last_error_at),
  bytes = CASE WHEN EXCLUDED.last_error IS NULL THEN EXCLUDED.bytes ELSE backup_target_status.bytes END;

-- name: BackupRoleRequestedRuns :many
SELECT id, kind, label, created_at FROM backup_run WHERE state = 'requested' ORDER BY created_at, id;

-- The newest finished run of every kind, either outcome: a pgBackRest marker newer than it is a run not yet recorded.
-- name: BackupRoleLatestFinishedRuns :many
SELECT DISTINCT ON (kind) kind, outcome, finished_at FROM backup_run
WHERE state = 'finished' AND finished_at IS NOT NULL
ORDER BY kind, finished_at DESC, id DESC;

-- name: BackupRoleFinishRequestedRun :execrows
UPDATE backup_run SET state = 'finished', outcome = @outcome, started_at = @started_at, finished_at = @finished_at,
  bytes = @bytes, error_class = sqlc.narg(error_class), targets = @targets
WHERE id = @id AND state = 'requested';

-- name: BackupRoleInsertFinishedRun :exec
INSERT INTO backup_run (id, kind, label, state, outcome, started_at, finished_at, bytes, error_class, targets)
VALUES (@id, @kind, '', 'finished', @outcome, @started_at, @finished_at, @bytes, sqlc.narg(error_class), @targets);

-- A repository restore from a target refuses while a restore plan runs (plan M15, amendment 2026-11-05, A5).
-- name: BackupRoleRunningRestorePlans :one
SELECT count(*) FROM backup_restore_plan WHERE state = 'running';
