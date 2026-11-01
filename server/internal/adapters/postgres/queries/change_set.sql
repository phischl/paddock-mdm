-- Change sets of the declarative configuration (plan M6c decision 17).

-- name: LockConfigApply :exec
-- Serializes the declarative applies and dry runs of the transaction's organization (PDK-016): two concurrent applies
-- would otherwise take device group locks in different orders and deadlock. Released at the end of the transaction.
SELECT pg_advisory_xact_lock(hashtextextended('config_apply:' || current_setting('paddock.org_id'), 0));

-- name: InsertChangeSet :exec
INSERT INTO change_set (id, organization_id, actor, source, created_n, updated_n, deleted_n, sections, plan, before, rollout,
  reverts_change_set_id, reason, urgent_reason)
VALUES (@id, @organization_id, @actor, @source, @created_n, @updated_n, @deleted_n, @sections, @plan, @before, @rollout,
  sqlc.narg(reverts_change_set_id), sqlc.narg(reason), sqlc.narg(urgent_reason));

-- name: GetChangeSetForRevert :one
-- The only query that reads "before" for the API (plan M11 decision 21); reverted_by as in GetChangeSet.
SELECT c.plan, c.before, c.before_purged_at,
  COALESCE((SELECT r.id FROM change_set r WHERE r.reverts_change_set_id = c.id ORDER BY r.applied_at DESC, r.id DESC LIMIT 1),
    '00000000-0000-0000-0000-000000000000'::uuid)::uuid AS reverted_by
FROM change_set c WHERE c.id = @id;

-- name: GetChangeSet :one
-- reverted_by is the nil UUID while nothing reverted the change set, rollout_id while it started no rollout. Never selects "before": it holds full file contents and is read only by the revert.
SELECT c.id, c.organization_id, c.applied_at, c.actor, c.source, c.created_n, c.updated_n, c.deleted_n, c.sections, c.plan,
  c.rollout, c.urgent_reason, c.reverts_change_set_id, (c.before IS NOT NULL)::boolean AS before_available,
  COALESCE((SELECT o.id FROM config_rollout o WHERE o.change_set_id = c.id), '00000000-0000-0000-0000-000000000000'::uuid)::uuid AS rollout_id,
  COALESCE((SELECT r.id FROM change_set r WHERE r.reverts_change_set_id = c.id ORDER BY r.applied_at DESC, r.id DESC LIMIT 1),
    '00000000-0000-0000-0000-000000000000'::uuid)::uuid AS reverted_by
FROM change_set c WHERE c.id = @id;

-- List queries (ADR 0018): see device_group.sql.

-- name: ListChangeSets :many
-- Columns as GetChangeSet: no "before", reverted_by the nil UUID while nothing reverted the change set.
SELECT id, organization_id, applied_at, actor, source, created_n, updated_n, deleted_n, sections, plan,
  rollout, urgent_reason, reverts_change_set_id, (before IS NOT NULL)::boolean AS before_available,
  COALESCE((SELECT o.id FROM config_rollout o WHERE o.change_set_id = change_set.id), '00000000-0000-0000-0000-000000000000'::uuid)::uuid AS rollout_id,
  COALESCE((SELECT r.id FROM change_set r WHERE r.reverts_change_set_id = change_set.id ORDER BY r.applied_at DESC, r.id DESC LIMIT 1),
    '00000000-0000-0000-0000-000000000000'::uuid)::uuid AS reverted_by
FROM change_set
WHERE (sqlc.narg(q_pattern)::text IS NULL OR actor->>'display' ILIKE sqlc.narg(q_pattern)::text ESCAPE '\')
  AND (sqlc.narg(sources)::text[] IS NULL OR source = ANY(sqlc.narg(sources)::text[]))
  AND (sqlc.narg(rollouts)::text[] IS NULL OR rollout = ANY(sqlc.narg(rollouts)::text[]))
ORDER BY
  CASE WHEN @sort::text = 'applied_at' THEN applied_at END ASC,
  CASE WHEN @sort::text = '-applied_at' THEN applied_at END DESC,
  id
LIMIT @max_rows OFFSET @skip_rows;

-- name: CountChangeSets :one
SELECT count(*) FROM (
  SELECT 1 FROM change_set
  WHERE (sqlc.narg(q_pattern)::text IS NULL OR actor->>'display' ILIKE sqlc.narg(q_pattern)::text ESCAPE '\')
    AND (sqlc.narg(sources)::text[] IS NULL OR source = ANY(sqlc.narg(sources)::text[]))
    AND (sqlc.narg(rollouts)::text[] IS NULL OR rollout = ANY(sqlc.narg(rollouts)::text[]))
  LIMIT @count_limit
) matching;

-- name: HasExpiredChangeSetBefore :one
SELECT EXISTS (SELECT 1 FROM change_set WHERE before IS NOT NULL AND applied_at < @cutoff::timestamptz);

-- name: PurgeExpiredChangeSetBefore :execrows
-- One batch of before-states older than the cutoff (plan M11 amendment 2026-10-29): the change set stays, its before
-- state is cleared and the time stamped.
UPDATE change_set SET before = NULL, before_purged_at = now() WHERE id IN (
  SELECT id FROM change_set WHERE before IS NOT NULL AND applied_at < @cutoff::timestamptz LIMIT 1000
);
