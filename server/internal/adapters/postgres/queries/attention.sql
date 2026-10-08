-- The attention list (plan M5b decision 11) over the view attention_condition. Kinds: stale_warning, stale_critical,
-- presumed_lost, quarantined, disk_not_compliant, agent_outdated, login_apply_failed, sudo_apply_failed,
-- revocation_pending, revocation_expired.

-- name: ListAttention :many
SELECT * FROM attention_condition
WHERE (sqlc.narg(q_pattern)::text IS NULL OR hostname ILIKE sqlc.narg(q_pattern)::text ESCAPE '\')
  AND (sqlc.narg(kinds)::text[] IS NULL OR kind = ANY(sqlc.narg(kinds)::text[]))
ORDER BY
  CASE WHEN @sort::text = 'since' THEN since END ASC,
  CASE WHEN @sort::text = '-since' THEN since END DESC,
  CASE WHEN @sort::text = 'kind' THEN kind END ASC,
  CASE WHEN @sort::text = '-kind' THEN kind END DESC,
  CASE WHEN @sort::text = 'hostname' THEN hostname END ASC,
  CASE WHEN @sort::text = '-hostname' THEN hostname END DESC,
  device_id, kind
LIMIT @max_rows OFFSET @skip_rows;

-- name: CountAttention :one
SELECT count(*) FROM (
  SELECT 1 FROM attention_condition
  WHERE (sqlc.narg(q_pattern)::text IS NULL OR hostname ILIKE sqlc.narg(q_pattern)::text ESCAPE '\')
    AND (sqlc.narg(kinds)::text[] IS NULL OR kind = ANY(sqlc.narg(kinds)::text[]))
  LIMIT @count_limit
) matching;
