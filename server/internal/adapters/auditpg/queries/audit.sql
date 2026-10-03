-- name: EnsureAuditPartition :exec
SELECT audit_ensure_partition(@month::date);

-- name: TransactionTime :one
-- The recording time of everything a writer transaction stores (architecture §14.4).
SELECT transaction_timestamp()::timestamptz AS recorded_at;

-- name: InsertAuditEvent :one
INSERT INTO audit_event (event_id, organization_id, occurred_at, recorded_at, code, outcome, source, actor, target,
                         params, correlation_id, object_key)
VALUES (@event_id, @organization_id, @occurred_at, @recorded_at, @code, @outcome, @source, @actor, sqlc.narg(target),
        @params, @correlation_id, @object_key)
ON CONFLICT DO NOTHING
RETURNING event_id;

-- name: InsertAuditObject :exec
INSERT INTO audit_object (object_key, organization_id, day, event_count, sha256)
VALUES (@object_key, @organization_id, @day, @event_count, @sha256);

-- name: ListAuditObjectsForDay :many
SELECT * FROM audit_object WHERE organization_id = @organization_id AND day = @day ORDER BY object_key;

-- name: ListAuditObjectsInRange :many
SELECT * FROM audit_object
WHERE organization_id = @organization_id AND day BETWEEN @from_day AND @to_day
ORDER BY day, object_key;

-- name: InsertAuditManifest :exec
INSERT INTO audit_manifest (organization_id, day, sha256, prev_sha256, signature, key_version, object_key)
VALUES (@organization_id, @day, @sha256, sqlc.narg(prev_sha256), @signature, @key_version, @object_key);

-- name: GetAuditManifest :one
SELECT * FROM audit_manifest WHERE organization_id = @organization_id AND day = @day;

-- name: GetLatestAuditManifest :one
SELECT * FROM audit_manifest WHERE organization_id = @organization_id ORDER BY day DESC LIMIT 1;

-- name: ListAuditManifests :many
SELECT * FROM audit_manifest
WHERE organization_id = @organization_id AND day BETWEEN @from_day AND @to_day
ORDER BY day;

-- name: FirstAuditDay :one
SELECT LEAST(
  (SELECT min(o.day) FROM audit_object o WHERE o.organization_id = @organization_id),
  (SELECT min(m.day) FROM audit_manifest m WHERE m.organization_id = @organization_id)
)::date AS day;

-- name: ListAuditOrganizations :many
SELECT organization_id FROM audit_object
UNION
SELECT organization_id FROM audit_manifest
ORDER BY organization_id;

-- name: TryAuditSealLock :one
SELECT pg_try_advisory_lock(hashtext('audit-seal')) AS locked;

-- name: ReleaseAuditSealLock :one
SELECT pg_advisory_unlock(hashtext('audit-seal')) AS unlocked;

-- name: GetAuditEventTime :one
SELECT occurred_at FROM audit_event WHERE event_id = @event_id LIMIT 1;

-- List queries (ADR 0018): one ascending and one descending ORDER BY branch per allowed sort value, event_id as
-- tie-breaker; the count repeats the filter and stops at @count_limit rows.

-- name: ListAuditEvents :many
SELECT * FROM audit_event
WHERE occurred_at >= @from_time AND occurred_at < @to_time
  AND (sqlc.narg(codes)::text[] IS NULL OR code = ANY(sqlc.narg(codes)::text[]))
  AND (sqlc.narg(outcomes)::text[] IS NULL OR outcome = ANY(sqlc.narg(outcomes)::text[]))
  AND (sqlc.narg(actor_types)::text[] IS NULL OR actor->>'type' = ANY(sqlc.narg(actor_types)::text[]))
  AND (sqlc.narg(q_pattern)::text IS NULL
       OR code ILIKE sqlc.narg(q_pattern)::text ESCAPE '\'
       OR actor->>'display' ILIKE sqlc.narg(q_pattern)::text ESCAPE '\'
       OR target->>'display' ILIKE sqlc.narg(q_pattern)::text ESCAPE '\')
ORDER BY
  CASE WHEN @sort::text = 'occurred_at' THEN occurred_at END ASC,
  CASE WHEN @sort::text = '-occurred_at' THEN occurred_at END DESC,
  CASE WHEN @sort::text = 'code' THEN code END ASC,
  CASE WHEN @sort::text = '-code' THEN code END DESC,
  CASE WHEN @sort::text = 'outcome' THEN outcome END ASC,
  CASE WHEN @sort::text = '-outcome' THEN outcome END DESC,
  event_id
LIMIT @max_rows OFFSET @skip_rows;

-- name: CountAuditEvents :one
SELECT count(*) FROM (
  SELECT 1 FROM audit_event
  WHERE occurred_at >= @from_time AND occurred_at < @to_time
    AND (sqlc.narg(codes)::text[] IS NULL OR code = ANY(sqlc.narg(codes)::text[]))
    AND (sqlc.narg(outcomes)::text[] IS NULL OR outcome = ANY(sqlc.narg(outcomes)::text[]))
    AND (sqlc.narg(actor_types)::text[] IS NULL OR actor->>'type' = ANY(sqlc.narg(actor_types)::text[]))
    AND (sqlc.narg(q_pattern)::text IS NULL
         OR code ILIKE sqlc.narg(q_pattern)::text ESCAPE '\'
         OR actor->>'display' ILIKE sqlc.narg(q_pattern)::text ESCAPE '\'
         OR target->>'display' ILIKE sqlc.narg(q_pattern)::text ESCAPE '\')
  LIMIT @count_limit
) matching;
