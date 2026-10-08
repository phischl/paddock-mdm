-- Dead man's switch (plan M4c decisions 15–17). Without a row the switch is off with the defaults.

-- name: GetDMSSettings :one
SELECT * FROM organization_dms_settings;

-- name: UpsertDMSSettings :one
INSERT INTO organization_dms_settings (organization_id, enabled, period_days, warn_days, updated_at, updated_by)
VALUES (@organization_id, @enabled, @period_days, @warn_days, now(), sqlc.narg(updated_by))
ON CONFLICT (organization_id) DO UPDATE
SET enabled = excluded.enabled, period_days = excluded.period_days, warn_days = excluded.warn_days,
    updated_at = excluded.updated_at, updated_by = excluded.updated_by
RETURNING *;

-- name: CancelSelfLocks :many
-- Open self-lock tokens that no longer fit the settings: all of them when the switch is off, otherwise those of
-- another period, of a device that is no longer active, expiring before renew_before, or whose volumes differ from the
-- device's volumes with a confirmed header escrow (PDK-009; they are replaced). A device whose paddock-revoke does
-- not understand volumes keeps a token without them.
UPDATE revocation_request r SET status = 'cancelled', finished_at = @now::timestamptz
WHERE r.action = 'self_lock' AND r.status IN ('issued','delivered')
  AND (NOT @enabled::boolean OR r.period_days <> @period_days::int OR r.expires_at <= @renew_before::timestamptz
       OR NOT EXISTS (SELECT 1 FROM device d WHERE d.id = r.device_id AND d.state = 'active')
       OR r.volumes <> CASE
         WHEN coalesce((SELECT (s.health -> 'revoke_capabilities') ? 'volumes' FROM device_status s
                        WHERE s.device_id = r.device_id), false)
         THEN ARRAY(SELECT DISTINCT e.volume FROM escrow_secret e
                    WHERE e.device_id = r.device_id AND e.kind = 'luks_header' AND e.status = 'stored'
                      AND e.volume IS NOT NULL ORDER BY 1)
         ELSE '{}'::uuid[] END)
RETURNING r.id, r.device_id;

-- name: ListDevicesWithoutSelfLock :many
-- Active devices without an open self-lock token.
SELECT d.id, d.organization_id, d.hostname FROM device d
WHERE d.state = 'active' AND NOT EXISTS (
  SELECT 1 FROM revocation_request r
  WHERE r.device_id = d.id AND r.action = 'self_lock' AND r.status IN ('issued','delivered'))
ORDER BY d.id
LIMIT 500;

-- name: MarkPresumedSelfLocked :many
-- Devices silent since before silent_since: presumed to have locked themselves (once until their next contact).
UPDATE device_status SET presumed_self_locked_at = @now::timestamptz
WHERE presumed_self_locked_at IS NULL AND last_contact_at < @silent_since::timestamptz
RETURNING device_id;

-- name: ClearPresumedSelfLocked :execrows
UPDATE device_status SET presumed_self_locked_at = NULL
WHERE presumed_self_locked_at IS NOT NULL AND (last_contact_at >= @silent_since::timestamptz OR NOT @enabled::boolean);
