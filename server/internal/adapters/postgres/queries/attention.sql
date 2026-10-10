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
  id
LIMIT @max_rows OFFSET @skip_rows;

-- name: CountAttention :one
SELECT count(*) FROM (
  SELECT 1 FROM attention_condition
  WHERE (sqlc.narg(q_pattern)::text IS NULL OR hostname ILIKE sqlc.narg(q_pattern)::text ESCAPE '\')
    AND (sqlc.narg(kinds)::text[] IS NULL OR kind = ANY(sqlc.narg(kinds)::text[]))
  LIMIT @count_limit
) matching;

-- The attention list grouped by device (plan M7c decision 27): one row per device with an open condition, its
-- conditions most severe first (critical 2, warn 1, info 0; see the portal's attentionStatus). A kind filter selects
-- the devices with at least one matching condition; every condition of the device is listed.

-- name: ListAttentionDevices :many
WITH ranked AS (
  SELECT c.device_id, c.hostname, c.kind, c.since, c.detail,
         CASE WHEN c.kind IN ('presumed_lost', 'stale_critical', 'quarantined', 'revocation_expired') THEN 2
              WHEN c.kind = 'revocation_pending' THEN 0
              ELSE 1 END AS rank
  FROM attention_condition c
), grouped AS (
  SELECT r.device_id, r.hostname, max(r.rank)::int AS severity, max(r.since)::timestamptz AS since,
         json_agg(json_build_object('kind', r.kind, 'since', r.since, 'detail', r.detail) ORDER BY r.rank DESC, r.since DESC) AS conditions
  FROM ranked r
  WHERE (sqlc.narg(q_pattern)::text IS NULL OR r.hostname ILIKE sqlc.narg(q_pattern)::text ESCAPE '\')
    AND (sqlc.narg(kinds)::text[] IS NULL OR EXISTS (
          SELECT 1 FROM attention_condition k WHERE k.device_id = r.device_id AND k.kind = ANY(sqlc.narg(kinds)::text[])))
    AND (sqlc.narg(device_id)::uuid IS NULL OR r.device_id = sqlc.narg(device_id)::uuid)
  GROUP BY r.device_id, r.hostname
), page AS (
  SELECT g.device_id, g.hostname, g.severity, g.since, g.conditions, d.state, d.os_release, s.last_contact_at
  FROM grouped g JOIN device d ON d.id = g.device_id LEFT JOIN device_status s ON s.device_id = d.id
)
SELECT device_id, hostname, severity, since, conditions, state, os_release, last_contact_at
FROM page
ORDER BY
  CASE WHEN @sort::text = 'severity' THEN severity END ASC,
  CASE WHEN @sort::text = '-severity' THEN severity END DESC,
  CASE WHEN @sort::text = 'hostname' THEN hostname END ASC,
  CASE WHEN @sort::text = '-hostname' THEN hostname END DESC,
  CASE WHEN @sort::text = 'since' THEN since END ASC,
  CASE WHEN @sort::text = '-since' THEN since END DESC,
  hostname, device_id
LIMIT @max_rows OFFSET @skip_rows;

-- name: CountAttentionDevices :one
SELECT count(*) FROM (
  SELECT 1 FROM attention_condition c
  WHERE (sqlc.narg(q_pattern)::text IS NULL OR c.hostname ILIKE sqlc.narg(q_pattern)::text ESCAPE '\')
    AND (sqlc.narg(kinds)::text[] IS NULL OR c.kind = ANY(sqlc.narg(kinds)::text[]))
    AND (sqlc.narg(device_id)::uuid IS NULL OR c.device_id = sqlc.narg(device_id)::uuid)
  GROUP BY c.device_id
  LIMIT @count_limit
) matching;
