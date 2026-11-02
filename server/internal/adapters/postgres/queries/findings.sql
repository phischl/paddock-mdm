-- Findings (plan M9 decisions 30–34): tamper events and attention conditions with a status, an assignee and a
-- reason. key is tamper:<device_id>:<code>:<subject> or attention:<attention_condition.id>.

-- name: UpsertTamperFinding :exec
-- A new tamper event opens a finding or counts against the open one of the same key (decision 31); a closed finding
-- is left alone and a new row is opened.
INSERT INTO finding (id, organization_id, kind, key, device_id, code, subject, status, opened_at, last_seen_at,
                     occurrences, first_event_id, last_event_id)
VALUES (@id, @organization_id, 'tamper', @key, @device_id, @code, @subject, 'open', @at, @at, 1, @event_id, @event_id)
ON CONFLICT (organization_id, key) WHERE kind = 'tamper' AND closed_at IS NULL
DO UPDATE SET occurrences = finding.occurrences + 1, last_seen_at = EXCLUDED.last_seen_at,
              last_event_id = EXCLUDED.last_event_id, updated_at = now();

-- name: ListAttentionConditionKeys :many
-- The open attention conditions of the organization, the source of the attention findings (decision 32).
SELECT id, kind, device_id, since, detail FROM attention_condition;

-- name: ListLiveAttentionFindings :many
SELECT id, key FROM finding WHERE kind = 'attention' AND cleared_at IS NULL;

-- name: InsertAttentionFinding :execrows
-- A concurrent round that inserted the same live key first wins; this one inserts nothing.
INSERT INTO finding (id, organization_id, kind, key, device_id, code, subject, status, opened_at, last_seen_at)
VALUES (@id, @organization_id, 'attention', @key, @device_id, @code, @subject, 'open', @opened_at, @last_seen_at)
ON CONFLICT (organization_id, key) WHERE kind = 'attention' AND cleared_at IS NULL DO NOTHING;

-- name: ClearAttentionFinding :execrows
UPDATE finding SET cleared_at = @cleared_at, updated_at = now()
WHERE id = @id AND kind = 'attention' AND cleared_at IS NULL;

-- name: LockFinding :one
SELECT f.*, d.hostname
FROM finding f JOIN device d ON d.id = f.device_id
WHERE f.id = @id
FOR UPDATE OF f;

-- name: GetFinding :one
SELECT f.id, f.kind, f.key, f.code, f.subject, f.device_id, d.hostname, f.status, f.assignee_account_id,
       a.username AS assignee_username, a.display_name AS assignee_display_name, f.opened_at, f.last_seen_at,
       f.occurrences, f.first_event_id, f.last_event_id, f.acknowledged_at, f.closed_at, f.closed_by, f.reason,
       f.external_ref, f.cleared_at
FROM finding f JOIN device d ON d.id = f.device_id LEFT JOIN admin_account a ON a.id = f.assignee_account_id
WHERE f.id = @id;

-- name: ListFindings :many
SELECT f.id, f.kind, f.key, f.code, f.subject, f.device_id, d.hostname, f.status, f.assignee_account_id,
       a.username AS assignee_username, a.display_name AS assignee_display_name, f.opened_at, f.last_seen_at,
       f.occurrences, f.first_event_id, f.last_event_id, f.acknowledged_at, f.closed_at, f.closed_by, f.reason,
       f.external_ref, f.cleared_at
FROM finding f JOIN device d ON d.id = f.device_id LEFT JOIN admin_account a ON a.id = f.assignee_account_id
WHERE (sqlc.narg(q_pattern)::text IS NULL
       OR d.hostname ILIKE sqlc.narg(q_pattern)::text ESCAPE '\'
       OR f.code ILIKE sqlc.narg(q_pattern)::text ESCAPE '\'
       OR f.subject ILIKE sqlc.narg(q_pattern)::text ESCAPE '\')
  AND (sqlc.narg(statuses)::text[] IS NULL OR f.status = ANY(sqlc.narg(statuses)::text[]))
  AND (sqlc.narg(kind)::text IS NULL OR f.kind = sqlc.narg(kind)::text)
  AND (sqlc.narg(device_id)::uuid IS NULL OR f.device_id = sqlc.narg(device_id)::uuid)
  AND (sqlc.narg(assignee_id)::uuid IS NULL OR f.assignee_account_id = sqlc.narg(assignee_id)::uuid)
  AND (f.cleared_at IS NOT NULL) = @cleared::boolean
ORDER BY
  CASE WHEN @sort::text = 'last_seen_at' THEN f.last_seen_at END ASC,
  CASE WHEN @sort::text = '-last_seen_at' THEN f.last_seen_at END DESC,
  CASE WHEN @sort::text = 'opened_at' THEN f.opened_at END ASC,
  CASE WHEN @sort::text = '-opened_at' THEN f.opened_at END DESC,
  CASE WHEN @sort::text = 'status' THEN f.status END ASC,
  CASE WHEN @sort::text = '-status' THEN f.status END DESC,
  CASE WHEN @sort::text = 'hostname' THEN d.hostname END ASC,
  CASE WHEN @sort::text = '-hostname' THEN d.hostname END DESC,
  CASE WHEN @sort::text = 'code' THEN f.code END ASC,
  CASE WHEN @sort::text = '-code' THEN f.code END DESC,
  f.id
LIMIT @max_rows OFFSET @skip_rows;

-- name: CountFindings :one
SELECT count(*) FROM (
  SELECT 1 FROM finding f JOIN device d ON d.id = f.device_id
  WHERE (sqlc.narg(q_pattern)::text IS NULL
         OR d.hostname ILIKE sqlc.narg(q_pattern)::text ESCAPE '\'
         OR f.code ILIKE sqlc.narg(q_pattern)::text ESCAPE '\'
         OR f.subject ILIKE sqlc.narg(q_pattern)::text ESCAPE '\')
    AND (sqlc.narg(statuses)::text[] IS NULL OR f.status = ANY(sqlc.narg(statuses)::text[]))
    AND (sqlc.narg(kind)::text IS NULL OR f.kind = sqlc.narg(kind)::text)
    AND (sqlc.narg(device_id)::uuid IS NULL OR f.device_id = sqlc.narg(device_id)::uuid)
    AND (sqlc.narg(assignee_id)::uuid IS NULL OR f.assignee_account_id = sqlc.narg(assignee_id)::uuid)
    AND (f.cleared_at IS NOT NULL) = @cleared::boolean
  LIMIT @count_limit
) matching;

-- name: AcknowledgeFinding :exec
UPDATE finding SET status = 'acknowledged', acknowledged_at = @at, updated_at = now() WHERE id = @id;

-- name: AssignFinding :exec
UPDATE finding SET status = 'in_progress', assignee_account_id = sqlc.narg(assignee_id)::uuid, updated_at = now()
WHERE id = @id;

-- name: CloseFinding :exec
UPDATE finding SET status = @status, closed_at = @at, closed_by = @closed_by, reason = @reason,
                   external_ref = sqlc.narg(external_ref)::text, updated_at = now()
WHERE id = @id;

-- name: ReopenFinding :exec
-- The previous reason stays in the audit event of the close; the row keeps the reopen reason (decision 33).
UPDATE finding SET status = 'open', closed_at = NULL, closed_by = NULL, reason = @reason, updated_at = now()
WHERE id = @id;
