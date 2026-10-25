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
  AND (sqlc.narg(target_id)::text IS NULL OR target->>'id' = sqlc.narg(target_id)::text)
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
    AND (sqlc.narg(target_id)::text IS NULL OR target->>'id' = sqlc.narg(target_id)::text)
    AND (sqlc.narg(q_pattern)::text IS NULL
         OR code ILIKE sqlc.narg(q_pattern)::text ESCAPE '\'
         OR actor->>'display' ILIKE sqlc.narg(q_pattern)::text ESCAPE '\'
         OR target->>'display' ILIKE sqlc.narg(q_pattern)::text ESCAPE '\')
  LIMIT @count_limit
) matching;

-- name: InsertAuditVerificationRun :exec
INSERT INTO audit_verification_run (id, organization_id, trigger, from_day, to_day, started_at, finished_at, days,
                                    objects, ok, problems, event_id)
VALUES (@id, @organization_id, @trigger, @from_day, @to_day, @started_at, @finished_at, @days, @objects, @ok,
        @problems, @event_id);

-- name: LatestNightlyRunFinished :one
-- The end of the newest nightly run of any organization; no row before the first one (plan M8b decision 27).
SELECT finished_at FROM audit_verification_run WHERE trigger = 'nightly' ORDER BY finished_at DESC LIMIT 1;

-- name: CountAuditVerificationRuns :many
-- The writer's paddock_audit_verify_runs_total for ok and failed runs of every process, the CLI included.
SELECT trigger, ok, count(*) AS runs FROM audit_verification_run GROUP BY trigger, ok;

-- name: TryAuditVerifyLock :one
SELECT pg_try_advisory_lock(hashtext('audit-verify')) AS locked;

-- name: ReleaseAuditVerifyLock :one
SELECT pg_advisory_unlock(hashtext('audit-verify')) AS unlocked;

-- Evidence integrity of the caller's organization (plan M8b decisions 30 and 31). The reader role sees only its
-- organization's rows (RLS); the list queries follow the ADR 0018 pattern of ListAuditEvents.

-- name: ListAuditVerificationRuns :many
SELECT * FROM audit_verification_run
WHERE (sqlc.narg(ok_filter)::boolean IS NULL OR ok = sqlc.narg(ok_filter)::boolean)
  AND (sqlc.narg(triggers)::text[] IS NULL OR trigger = ANY(sqlc.narg(triggers)::text[]))
  AND (sqlc.narg(q_pattern)::text IS NULL OR problems::text ILIKE sqlc.narg(q_pattern)::text ESCAPE '\')
ORDER BY
  CASE WHEN @sort::text = 'started_at' THEN started_at END ASC,
  CASE WHEN @sort::text = '-started_at' THEN started_at END DESC,
  CASE WHEN @sort::text = 'from_day' THEN from_day END ASC,
  CASE WHEN @sort::text = '-from_day' THEN from_day END DESC,
  CASE WHEN @sort::text = 'ok' THEN ok END ASC,
  CASE WHEN @sort::text = '-ok' THEN ok END DESC,
  id
LIMIT @max_rows OFFSET @skip_rows;

-- name: CountAuditVerificationRunsFiltered :one
SELECT count(*) FROM (
  SELECT 1 FROM audit_verification_run
  WHERE (sqlc.narg(ok_filter)::boolean IS NULL OR ok = sqlc.narg(ok_filter)::boolean)
    AND (sqlc.narg(triggers)::text[] IS NULL OR trigger = ANY(sqlc.narg(triggers)::text[]))
    AND (sqlc.narg(q_pattern)::text IS NULL OR problems::text ILIKE sqlc.narg(q_pattern)::text ESCAPE '\')
  LIMIT @count_limit
) matching;

-- name: GetLatestAuditVerificationRun :one
SELECT * FROM audit_verification_run ORDER BY started_at DESC, id DESC LIMIT 1;

-- name: GetLatestAuditVerificationRunByOK :one
SELECT * FROM audit_verification_run WHERE ok = @ok ORDER BY started_at DESC, id DESC LIMIT 1;

-- name: CountAuditManifests :one
SELECT count(*) FROM audit_manifest;

-- name: LatestAuditManifestDay :one
SELECT day FROM audit_manifest ORDER BY day DESC LIMIT 1;

-- name: ListAuditManifestsWithVerification :many
-- The newest run covering a day decides its result: a later failed run over a range that includes the day overrides
-- an earlier successful one (plan M8b gate V4).
SELECT m.day, m.sha256, m.prev_sha256, m.key_version, m.object_key,
       run.finished_at AS last_verified_at, run.ok AS last_verified_ok
FROM audit_manifest m
LEFT JOIN LATERAL (
  SELECT r.id FROM audit_verification_run r
  WHERE r.organization_id = m.organization_id AND r.from_day <= m.day AND r.to_day >= m.day
  ORDER BY r.started_at DESC, r.id DESC
  LIMIT 1
) newest ON true
-- Joined as a table, not selected in the lateral subquery, so that sqlc types the columns as nullable.
LEFT JOIN audit_verification_run run ON run.id = newest.id
WHERE (sqlc.narg(from_day)::date IS NULL OR m.day >= sqlc.narg(from_day)::date)
  AND (sqlc.narg(to_day)::date IS NULL OR m.day <= sqlc.narg(to_day)::date)
  AND (sqlc.narg(verified)::boolean IS NULL OR sqlc.narg(verified)::boolean = EXISTS (
        SELECT 1 FROM audit_verification_run v
        WHERE v.organization_id = m.organization_id AND v.ok AND v.from_day <= m.day AND v.to_day >= m.day))
  AND (sqlc.narg(q_pattern)::text IS NULL OR m.object_key ILIKE sqlc.narg(q_pattern)::text ESCAPE '\')
ORDER BY
  CASE WHEN @sort::text = 'day' THEN day END ASC,
  CASE WHEN @sort::text = '-day' THEN day END DESC,
  day
LIMIT @max_rows OFFSET @skip_rows;

-- name: CountAuditManifestsFiltered :one
SELECT count(*) FROM (
  SELECT 1 FROM audit_manifest m
  WHERE (sqlc.narg(from_day)::date IS NULL OR m.day >= sqlc.narg(from_day)::date)
    AND (sqlc.narg(to_day)::date IS NULL OR m.day <= sqlc.narg(to_day)::date)
    AND (sqlc.narg(verified)::boolean IS NULL OR sqlc.narg(verified)::boolean = EXISTS (
          SELECT 1 FROM audit_verification_run v
          WHERE v.organization_id = m.organization_id AND v.ok AND v.from_day <= m.day AND v.to_day >= m.day))
    AND (sqlc.narg(q_pattern)::text IS NULL OR m.object_key ILIKE sqlc.narg(q_pattern)::text ESCAPE '\')
  LIMIT @count_limit
) matching;
