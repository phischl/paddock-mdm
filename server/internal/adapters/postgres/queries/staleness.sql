-- Staleness alerts (plan M5b decision 10): at most one open alert per device.

-- name: ListStalenessCandidates :many
-- Active devices with their last contact and open alert, and devices that are no longer active but still have one.
-- group_warning_h and group_critical_h are the most lenient overrides of the device's groups (plan M8d decision 12),
-- 0 when none of its groups overrides the organization's thresholds (an override is at least 1 hour).
SELECT d.id, d.state, s.last_contact_at, a.kind AS open_kind, t.group_warning_h, t.group_critical_h
FROM device d
CROSS JOIN LATERAL (
  SELECT coalesce(max(g.staleness_warning_h), 0)::int AS group_warning_h,
         coalesce(max(g.staleness_critical_h), 0)::int AS group_critical_h
  FROM device_group_member m JOIN device_group g ON g.id = m.device_group_id
  WHERE m.device_id = d.id AND g.staleness_warning_h IS NOT NULL
) t
LEFT JOIN device_status s ON s.device_id = d.id
LEFT JOIN device_alert a ON a.device_id = d.id AND a.cleared_at IS NULL
WHERE d.state = 'active' OR a.id IS NOT NULL
ORDER BY d.id;

-- name: GetOpenDeviceAlertKind :one
SELECT kind FROM device_alert WHERE device_id = @device_id AND cleared_at IS NULL;

-- name: ClearDeviceAlerts :execrows
UPDATE device_alert SET cleared_at = @now::timestamptz WHERE device_id = @device_id AND cleared_at IS NULL;

-- name: RaiseDeviceAlert :execrows
INSERT INTO device_alert (id, organization_id, device_id, kind, raised_at)
VALUES (@id, @organization_id, @device_id, @kind, @now::timestamptz)
ON CONFLICT (device_id) WHERE cleared_at IS NULL DO NOTHING;

-- name: SetPresumedLost :exec
UPDATE device_status SET presumed_lost_at = @now::timestamptz WHERE device_id = @device_id AND presumed_lost_at IS NULL;

-- name: ClearPresumedLost :exec
UPDATE device_status SET presumed_lost_at = NULL WHERE device_id = @device_id AND presumed_lost_at IS NOT NULL;

-- name: GetDeviceLastContact :one
SELECT last_contact_at FROM device_status WHERE device_id = @device_id;

-- name: GetDeviceGroupStaleness :one
-- The most lenient staleness overrides of a device's groups (plan M8d decision 12); 0 without an override.
SELECT coalesce(max(g.staleness_warning_h), 0)::int AS group_warning_h,
       coalesce(max(g.staleness_critical_h), 0)::int AS group_critical_h
FROM device_group_member m JOIN device_group g ON g.id = m.device_group_id
WHERE m.device_id = @device_id AND g.staleness_warning_h IS NOT NULL;
