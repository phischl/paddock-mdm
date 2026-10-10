-- The overview page (plan M7c decision 26): the numbers of the caller's organization, read in one transaction.
-- A device counts once in its most severe contact bucket (paddock_device_contact); findings are bucketed by the
-- worst severity of the device.

-- name: OverviewDevices :one
SELECT count(*) FILTER (WHERE d.state IN ('pending', 'active', 'quarantined'))::int AS total,
       count(*) FILTER (WHERE d.state = 'active')::int AS active,
       count(*) FILTER (WHERE d.state = 'pending')::int AS pending,
       count(*) FILTER (WHERE d.state = 'quarantined')::int AS quarantined,
       count(*) FILTER (WHERE d.state = 'retired')::int AS retired,
       count(*) FILTER (WHERE d.state = 'rejected')::int AS rejected,
       count(*) FILTER (WHERE d.state = 'active' AND c.contact = 'ok')::int AS online,
       count(*) FILTER (WHERE d.state = 'active' AND c.contact = 'stale_warning')::int AS silent,
       count(*) FILTER (WHERE d.state = 'active' AND c.contact = 'stale_critical')::int AS silent_critical,
       count(*) FILTER (WHERE d.state = 'active' AND c.contact = 'presumed_lost')::int AS presumed_lost,
       count(*) FILTER (WHERE d.state = 'active' AND c.contact = 'never')::int AS never_contacted
FROM device d LEFT JOIN device_status s ON s.device_id = d.id
CROSS JOIN LATERAL (SELECT paddock_device_contact(d.state, s.last_contact_at, s.presumed_lost_at, d.id) AS contact) c;

-- name: OverviewEncryption :one
SELECT count(*) FILTER (WHERE s.health -> 'disk' ->> 'state' = 'compliant')::int AS encrypted,
       count(*) FILTER (WHERE s.health -> 'disk' ->> 'state' = 'not_encrypted')::int AS not_encrypted,
       count(*) FILTER (WHERE s.health -> 'disk' ->> 'state' IN ('unmanaged', 'tpm_missing', 'tpm_pin_missing', 'escrow_pending'))::int AS partial,
       count(*) FILTER (WHERE s.health -> 'disk' ->> 'state' IS NULL)::int AS not_reported
FROM device d LEFT JOIN device_status s ON s.device_id = d.id
WHERE d.state = 'active';

-- name: OverviewVulnerabilityBuckets :one
WITH worst AS (
  SELECT d.id,
         min(CASE WHEN f.cve IS NULL THEN NULL
                  WHEN f.severity = 'critical' THEN 0 WHEN f.severity = 'high' THEN 1
                  WHEN f.severity = 'medium' THEN 2 WHEN f.severity = 'low' THEN 3 ELSE 4 END) AS rank
  FROM device d LEFT JOIN vulnerability_finding f ON f.device_id = d.id
  WHERE d.state IN ('active', 'quarantined')
  GROUP BY d.id
)
SELECT count(*) FILTER (WHERE rank = 0)::int AS critical,
       count(*) FILTER (WHERE rank = 1)::int AS high,
       count(*) FILTER (WHERE rank = 2)::int AS medium,
       count(*) FILTER (WHERE rank = 3)::int AS low,
       count(*) FILTER (WHERE rank = 4)::int AS unknown,
       count(*) FILTER (WHERE rank IS NULL)::int AS none
FROM worst;

-- name: OverviewTopCVEs :many
SELECT f.cve,
       min(CASE WHEN f.severity = 'critical' THEN 0 WHEN f.severity = 'high' THEN 1
                WHEN f.severity = 'medium' THEN 2 WHEN f.severity = 'low' THEN 3 ELSE 4 END)::int AS rank,
       count(DISTINCT f.device_id)::int AS devices,
       (array_agg(DISTINCT f.software_name ORDER BY f.software_name))[1:3]::text[] AS packages
FROM vulnerability_finding f JOIN device d ON d.id = f.device_id AND d.state IN ('active', 'quarantined')
GROUP BY f.cve
ORDER BY rank, devices DESC, f.cve
LIMIT 5;

-- name: OverviewUpdates :one
SELECT count(*) FILTER (WHERE s.last_contact_at IS NOT NULL AND (
         s.login_state -> 'updates_security' IS NULL
         OR s.login_state -> 'updates_security' -> 'params' ->> 'result' IS DISTINCT FROM 'ok'
         OR (s.login_state -> 'updates_security' ->> 'occurred_at')::timestamptz < now() - @security_window::interval))::int AS security_overdue,
       count(*) FILTER (WHERE s.health ->> 'reboot_required' = 'true')::int AS reboot_required,
       count(*) FILTER (WHERE s.agent_version IS NOT NULL AND s.agent_version = r.version)::int AS agent_on_current,
       count(*) FILTER (WHERE s.agent_version IS NOT NULL AND r.version IS NOT NULL AND s.agent_version <> r.version)::int AS agent_outdated,
       count(*) FILTER (WHERE s.agent_version IS NULL)::int AS agent_unknown
FROM device d LEFT JOIN device_status s ON s.device_id = d.id
CROSS JOIN (SELECT paddock_current_agent_version() AS version) r
WHERE d.state = 'active';

-- name: CurrentAgentVersion :one
-- '' when no release is published (the function returns NULL then).
SELECT coalesce(paddock_current_agent_version(), '')::text AS version;

-- name: OverviewOSReleases :many
SELECT coalesce(d.os_release ->> 'VERSION_ID', 'unknown')::text AS release, count(*)::int AS devices
FROM device d
WHERE d.state = 'active'
GROUP BY 1
ORDER BY 1 DESC;

-- name: OverviewAttention :one
SELECT count(*)::int AS conditions, count(DISTINCT device_id)::int AS devices FROM attention_condition;
