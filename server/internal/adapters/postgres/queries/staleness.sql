-- Staleness alerts (plan M5b decision 10): at most one open alert per device.

-- name: ListStalenessCandidates :many
-- Active devices with their last contact and open alert, and devices that are no longer active but still have one.
SELECT d.id, d.state, s.last_contact_at, a.kind AS open_kind
FROM device d
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
