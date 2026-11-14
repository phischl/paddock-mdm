-- Uninstall (plan M8d decisions 36–38, 41).

-- name: SetDeviceUninstall :one
UPDATE device SET uninstall_requested_at = @requested_at, uninstall_mode = @mode, uninstall_command_id = @command_id,
  uninstalled_at = NULL, uninstall_reason = NULL
WHERE id = @id
RETURNING *;

-- name: ClearDeviceUninstall :one
UPDATE device SET uninstall_requested_at = NULL, uninstall_mode = NULL, uninstall_command_id = NULL, uninstalled_at = NULL,
  uninstall_reason = NULL
WHERE id = @id
RETURNING *;

-- name: GetDeviceUninstall :one
-- The uninstall of a device with its command; local_admin and tpm are the outcome the device reported, and
-- refused_reason the reason of a device that refused the command (PDK-403; bounded like device-reported audit params).
SELECT d.uninstall_mode::text AS mode, d.uninstall_requested_at::timestamptz AS requested_at, d.uninstall_reason AS reason,
       d.uninstall_command_id::uuid AS command_id, coalesce(c.status, '')::text AS command_status,
       d.uninstalled_at, coalesce(c.result ->> 'local_admin', '')::text AS local_admin,
       coalesce(c.result ->> 'tpm', '')::text AS tpm, c.delivered_at AS command_delivered_at,
       c.finished_at AS command_finished_at,
       CASE WHEN c.status = 'failed' THEN left(coalesce(c.result ->> 'reason', ''), 256) ELSE '' END::text AS refused_reason
FROM device d LEFT JOIN device_command c ON c.id = d.uninstall_command_id
WHERE d.id = @id AND d.uninstall_requested_at IS NOT NULL;

-- name: CancelDeviceCommand :execrows
-- Only a command the device has not received can be cancelled (pending), or one that ended without a removal.
UPDATE device_command SET status = 'cancelled', finished_at = @finished_at::timestamptz
WHERE id = @id AND status IN ('pending','failed','expired');

-- name: WithdrawDeviceCommand :execrows
-- A command whose result the caller claimed as cancelled first (devicecache ClaimResult): pending, or delivered when
-- the uninstall report is overdue or a Lock or Destroy takes precedence (review 2 findings A and D).
UPDATE device_command SET status = 'cancelled', finished_at = @finished_at::timestamptz
WHERE id = @id AND status IN ('pending','delivered');

-- name: DeviceHasOpenRevocation :one
-- An open Lock or Destroy; the standing self-lock token of the dead man's switch does not count.
SELECT EXISTS (
  SELECT 1 FROM revocation_request
  WHERE device_id = @device_id AND action IN ('lock','destroy') AND status IN ('requested','approved','issued','delivered')
)::boolean;

-- name: MarkDeviceUninstalled :execrows
-- The device's report of the removal (agent.uninstalled) for its open request whose command succeeded; the outcome
-- is kept with the command for the device page. An unsolicited report or one after a cancel marks nothing.
WITH marked AS (
  UPDATE device d SET uninstalled_at = @uninstalled_at::timestamptz
  FROM device_command c
  WHERE d.id = @device_id::uuid AND d.uninstalled_at IS NULL AND d.uninstall_requested_at IS NOT NULL
    AND d.uninstall_command_id = @command_id::uuid AND c.id = d.uninstall_command_id AND c.status = 'succeeded'
  RETURNING d.uninstall_command_id
)
UPDATE device_command c SET result = coalesce(c.result, '{}'::jsonb) || @outcome::jsonb
FROM marked m WHERE c.id = m.uninstall_command_id;

-- name: UninstallResultPending :one
-- The report matches the open request, but the worker has not recorded the command's result yet.
SELECT EXISTS (
  SELECT 1 FROM device d JOIN device_command c ON c.id = d.uninstall_command_id
  WHERE d.id = @device_id::uuid AND d.uninstall_command_id = @command_id::uuid AND d.uninstall_requested_at IS NOT NULL
    AND d.uninstalled_at IS NULL AND c.status IN ('pending','delivered') AND c.expires_at > now()
)::boolean;

-- name: EndFailedUninstall :execrows
-- The device could not start the removal of the request's command, or refused it for good (PDK-403): the request
-- ends.
UPDATE device SET uninstall_requested_at = NULL, uninstall_mode = NULL, uninstall_command_id = NULL, uninstall_reason = NULL
WHERE id = @id AND uninstall_command_id = @command_id::uuid AND uninstalled_at IS NULL;

-- name: SetDeviceRetiredReason :exec
UPDATE device SET retired_reason = @reason WHERE id = @id;

-- name: ListCancelledDeviceCommands :many
-- Commands cancelled since a time: the worker removes them from cmd:<device_id>.
SELECT id, device_id FROM device_command WHERE status = 'cancelled' AND finished_at >= @since::timestamptz;

-- Organization offboarding (plan M17 decisions 3 and 4, amendment e points 1, 4–6): the deletion request issues
-- uninstall leave to every active device as the system and marks it with its reason; cancelling the deletion withdraws
-- exactly the marked ones. Both work set-based with a constant number of statements. The locks are FOR NO KEY UPDATE:
-- they serialize with LockDevice and the other uninstall writers but not with the FOR KEY SHARE of foreign-key checks,
-- so the organization's devices keep reporting meanwhile.

-- name: LockActiveDevicesForOffboarding :many
SELECT id FROM device WHERE state = 'active' ORDER BY id FOR NO KEY UPDATE;

-- name: InsertOffboardingUninstalls :many
-- Every locked active device without an open uninstall and without an open Lock or Destroy (the condition of
-- DeviceHasOpenRevocation). Only the devices LockActiveDevicesForOffboarding locked, so a device that becomes active
-- in between is neither issued nor counted.
INSERT INTO device_command (id, organization_id, device_id, type, params, status, issued_at, expires_at)
SELECT uuidv7(), d.organization_id, d.id, 'uninstall', @params::jsonb, 'pending', @issued_at::timestamptz,
       @expires_at::timestamptz
FROM device d
WHERE d.id = ANY(@locked_ids::uuid[]) AND d.state = 'active'
  AND NOT (d.uninstall_requested_at IS NOT NULL AND d.uninstalled_at IS NULL)
  AND NOT EXISTS (
    SELECT 1 FROM revocation_request r
    WHERE r.device_id = d.id AND r.action IN ('lock','destroy') AND r.status IN ('requested','approved','issued','delivered')
  )
ORDER BY d.id
RETURNING id, device_id;

-- name: SetOffboardingUninstalls :execrows
UPDATE device d SET uninstall_requested_at = @requested_at::timestamptz, uninstall_mode = 'leave',
  uninstall_command_id = c.id, uninstalled_at = NULL, uninstall_reason = 'organization_offboarding'
FROM device_command c
WHERE c.id = ANY(@command_ids::uuid[]) AND c.device_id = d.id;

-- name: LockOffboardingUninstalls :many
SELECT d.id AS device_id, c.id AS command_id, c.status
FROM device d JOIN device_command c ON c.id = d.uninstall_command_id
WHERE d.uninstall_reason = 'organization_offboarding' AND d.uninstalled_at IS NULL
ORDER BY d.id
FOR NO KEY UPDATE OF d;

-- name: CancelOffboardingCommands :many
-- The withdrawn (result claimed as cancelled, so pending or delivered meanwhile), failed and expired commands; a
-- command that got its result meanwhile is not returned and its request stays.
UPDATE device_command SET status = 'cancelled', finished_at = @finished_at::timestamptz
WHERE id = ANY(@ids::uuid[]) AND status IN ('pending','delivered','failed','expired')
RETURNING id, device_id;

-- name: ClearOffboardingUninstalls :execrows
UPDATE device SET uninstall_requested_at = NULL, uninstall_mode = NULL, uninstall_command_id = NULL, uninstalled_at = NULL,
  uninstall_reason = NULL
WHERE id = ANY(@ids::uuid[]) AND uninstall_reason = 'organization_offboarding';
