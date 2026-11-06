-- Restore plans (plan M15 decisions 25–26): approved by a platform administrator through the api (paddock_platform),
-- executed and reported by the host through the backup role (paddock_backup, db.BackupPool.InBackup, queries named
-- BackupRole…). An approved plan past expires_at reads as expired before any row is changed: the host refuses it either
-- way, and a list must not show a plan the host would refuse as approved.

-- List queries (ADR 0018): see device_group.sql.

-- name: ListBackupRestorePlans :many
WITH plan AS (
  SELECT p.id, p.kind, p.source, p.source_target_id, t.name AS source_target_name, p.at, p.components,
         (CASE WHEN p.state = 'approved' AND p.expires_at <= now() THEN 'expired' ELSE p.state END)::text AS state,
         p.created_by, p.created_at, p.expires_at, p.started_at, p.finished_at, p.outcome_detail
  FROM backup_restore_plan p LEFT JOIN backup_target t ON t.id = p.source_target_id
)
SELECT * FROM plan
WHERE (sqlc.narg(q_pattern)::text IS NULL OR created_by ILIKE sqlc.narg(q_pattern)::text ESCAPE '\'
       OR kind ILIKE sqlc.narg(q_pattern)::text ESCAPE '\')
  AND (sqlc.narg(states)::text[] IS NULL OR state = ANY(sqlc.narg(states)::text[]))
ORDER BY
  CASE WHEN @sort::text = 'created_at' THEN created_at END ASC,
  CASE WHEN @sort::text = '-created_at' THEN created_at END DESC,
  CASE WHEN @sort::text = 'state' THEN state END ASC,
  CASE WHEN @sort::text = '-state' THEN state END DESC,
  id
LIMIT @max_rows OFFSET @skip_rows;

-- name: CountBackupRestorePlans :one
SELECT count(*) FROM (
  SELECT 1 FROM backup_restore_plan
  WHERE (sqlc.narg(q_pattern)::text IS NULL OR created_by ILIKE sqlc.narg(q_pattern)::text ESCAPE '\'
         OR kind ILIKE sqlc.narg(q_pattern)::text ESCAPE '\')
    AND (sqlc.narg(states)::text[] IS NULL
         OR (CASE WHEN state = 'approved' AND expires_at <= now() THEN 'expired' ELSE state END) = ANY(sqlc.narg(states)::text[]))
  LIMIT @count_limit
) matching;

-- name: GetBackupRestorePlan :one
SELECT p.id, p.kind, p.source, p.source_target_id, t.name AS source_target_name, p.at, p.components,
       (CASE WHEN p.state = 'approved' AND p.expires_at <= now() THEN 'expired' ELSE p.state END)::text AS state,
       p.created_by, p.created_at, p.expires_at, p.started_at, p.finished_at, p.outcome_detail
FROM backup_restore_plan p LEFT JOIN backup_target t ON t.id = p.source_target_id
WHERE p.id = @id;

-- lapsed: an approved plan past its expiry, which reads as expired.
-- name: LockBackupRestorePlan :one
SELECT id, kind, source, source_target_id, at, components, state, started_at,
       (state = 'approved' AND expires_at <= now())::boolean AS lapsed
FROM backup_restore_plan WHERE id = @id
FOR UPDATE;

-- Lapsed approved plans no longer hold the one open place (index backup_restore_plan_one_open_idx).
-- name: ExpireLapsedBackupRestorePlans :exec
UPDATE backup_restore_plan SET state = 'expired', finished_at = expires_at
WHERE state = 'approved' AND expires_at <= now();

-- name: OpenBackupRestorePlan :one
SELECT id, state FROM backup_restore_plan WHERE state IN ('approved', 'running') ORDER BY created_at LIMIT 1;

-- The kinds that have a success at or before at (any success while at is NULL) on the source: the runs of the local
-- repository, or for a target the runs that reached it and its mirror state.
-- name: BackupRestoreAvailableKinds :many
SELECT DISTINCT available.kind::text AS kind FROM (
  SELECT r.kind FROM backup_run r
  WHERE r.outcome = 'succeeded' AND r.finished_at IS NOT NULL
    AND (sqlc.narg(at)::timestamptz IS NULL OR r.finished_at <= sqlc.narg(at)::timestamptz)
    AND (sqlc.narg(target_id)::uuid IS NULL OR r.targets @> jsonb_build_array(
         jsonb_build_object('target_id', sqlc.narg(target_id)::uuid::text, 'ok', true)))
  UNION
  SELECT s.kind FROM backup_target_status s
  WHERE s.target_id = sqlc.narg(target_id)::uuid AND s.last_success_at IS NOT NULL
    AND (sqlc.narg(at)::timestamptz IS NULL OR s.last_success_at <= sqlc.narg(at)::timestamptz)
) available
ORDER BY 1;

-- name: InsertBackupRestorePlan :exec
INSERT INTO backup_restore_plan (id, kind, source_target_id, source, at, components, state, created_by, expires_at)
VALUES (@id, @kind, sqlc.narg(source_target_id), @source, sqlc.narg(at), @components, 'approved', @created_by,
  now() + interval '24 hours');

-- name: CancelBackupRestorePlan :exec
UPDATE backup_restore_plan SET state = 'expired', finished_at = now() WHERE id = @id;

-- name: BackupRoleStartRestorePlan :exec
UPDATE backup_restore_plan SET state = 'running', started_at = now() WHERE id = @id;

-- name: BackupRoleFinishRestorePlan :exec
UPDATE backup_restore_plan SET state = @state, finished_at = now(), outcome_detail = sqlc.narg(outcome_detail)
WHERE id = @id;

-- A restore without a plan (a fresh installation, the repository alone), or a planned restore whose plan row the
-- restored database no longer holds: the row records what happened, so the portal shows it.
-- name: BackupRoleInsertFinishedRestorePlan :exec
INSERT INTO backup_restore_plan (id, kind, source, at, components, state, created_by, finished_at, outcome_detail)
VALUES (@id, @kind, @source, sqlc.narg(at), @components, @state, @created_by, now(), sqlc.narg(outcome_detail));

-- A running plan whose host never reported its end (PDK-832): abandoned, so it no longer holds the one open place and
-- the host's later report finds it finished.
-- name: AbandonBackupRestorePlan :exec
UPDATE backup_restore_plan SET state = 'abandoned', finished_at = now(), outcome_detail = @outcome_detail
WHERE id = @id AND state = 'running';
