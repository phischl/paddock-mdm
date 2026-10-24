-- The attention list (plan M5b decision 11) over the view attention_condition. Kinds: stale_warning, stale_critical,
-- presumed_lost, quarantined, disk_not_compliant, agent_outdated, login_apply_failed, sudo_apply_failed,
-- revocation_pending, revocation_expired, agent_rollback_pending, agent_not_running, config_behind,
-- disk_conversion_failed (warn, plan M8e decision 6), clock_drift (warn, plan M8b decision 15), event_gap (warn, plan M8b
-- decision 23).

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
-- conditions most severe first (critical 2, warn 1, info 0; see the portal's attentionStatus), then newest, then by
-- kind: several kinds share a rank and a since (the device's last contact), and without the last key their order
-- depended on the plan (PDK-103). A kind filter selects the devices with at least one matching condition; every
-- condition of the device is listed.
--
-- Both queries read attention_condition exactly once, as a MATERIALIZED CTE, and apply the optional filters to its
-- rows (PDK-094). Inlined, PostgreSQL pushes the "narg IS NULL OR …" filters into every branch of the view; pgx
-- reuses prepared statements, so after five executions a generic plan estimates those filters as near-empty and
-- probes the view's tables once per device (list and count together about 300 ms instead of 85 ms at 10 000 stale
-- devices, docs/operations/capacity.md). The device page (device_id) reads the whole view as well, a few tens of
-- milliseconds.

-- name: ListAttentionDevices :many
WITH ranked AS MATERIALIZED (
  SELECT c.device_id, c.hostname, c.kind, c.since, c.detail,
         CASE WHEN c.kind IN ('presumed_lost', 'stale_critical', 'quarantined', 'revocation_expired') THEN 2
              WHEN c.kind = 'revocation_pending' THEN 0
              ELSE 1 END AS rank
  FROM attention_condition c
), grouped AS (
  SELECT r.device_id, r.hostname, max(r.rank)::int AS severity, max(r.since)::timestamptz AS since,
         json_agg(json_build_object('kind', r.kind, 'since', r.since, 'detail', r.detail) ORDER BY r.rank DESC, r.since DESC, r.kind) AS conditions
  FROM ranked r
  WHERE (sqlc.narg(q_pattern)::text IS NULL OR r.hostname ILIKE sqlc.narg(q_pattern)::text ESCAPE '\')
    AND (sqlc.narg(device_id)::uuid IS NULL OR r.device_id = sqlc.narg(device_id)::uuid)
  GROUP BY r.device_id, r.hostname
  HAVING sqlc.narg(kinds)::text[] IS NULL OR bool_or(r.kind = ANY(sqlc.narg(kinds)::text[]))
), page AS (
  -- The page is cut before the join, so device and device_status are read for its rows only.
  SELECT device_id, hostname, severity, since, conditions
  FROM grouped
  ORDER BY
    CASE WHEN @sort::text = 'severity' THEN severity END ASC,
    CASE WHEN @sort::text = '-severity' THEN severity END DESC,
    CASE WHEN @sort::text = 'hostname' THEN hostname END ASC,
    CASE WHEN @sort::text = '-hostname' THEN hostname END DESC,
    CASE WHEN @sort::text = 'since' THEN since END ASC,
    CASE WHEN @sort::text = '-since' THEN since END DESC,
    hostname, device_id
  LIMIT @max_rows OFFSET @skip_rows
)
SELECT p.device_id, p.hostname, p.severity, p.since, p.conditions, d.state, d.os_release, s.last_contact_at
FROM page p JOIN device d ON d.id = p.device_id LEFT JOIN device_status s ON s.device_id = d.id
ORDER BY
  CASE WHEN @sort::text = 'severity' THEN p.severity END ASC,
  CASE WHEN @sort::text = '-severity' THEN p.severity END DESC,
  CASE WHEN @sort::text = 'hostname' THEN p.hostname END ASC,
  CASE WHEN @sort::text = '-hostname' THEN p.hostname END DESC,
  CASE WHEN @sort::text = 'since' THEN p.since END ASC,
  CASE WHEN @sort::text = '-since' THEN p.since END DESC,
  p.hostname, p.device_id;

-- name: CountAttentionDevices :one
WITH condition AS MATERIALIZED (
  SELECT device_id, hostname, kind FROM attention_condition
)
SELECT count(*) FROM (
  SELECT 1 FROM condition c
  WHERE (sqlc.narg(q_pattern)::text IS NULL OR c.hostname ILIKE sqlc.narg(q_pattern)::text ESCAPE '\')
    AND (sqlc.narg(kinds)::text[] IS NULL OR c.kind = ANY(sqlc.narg(kinds)::text[]))
    AND (sqlc.narg(device_id)::uuid IS NULL OR c.device_id = sqlc.narg(device_id)::uuid)
  GROUP BY c.device_id
  LIMIT @count_limit
) matching;
