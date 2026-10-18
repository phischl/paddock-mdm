-- Uninstall (plan M8d decisions 36–38, 41).

-- name: SetDeviceUninstall :one
UPDATE device SET uninstall_requested_at = @requested_at, uninstall_mode = @mode, uninstall_command_id = @command_id,
  uninstalled_at = NULL
WHERE id = @id
RETURNING *;

-- name: ClearDeviceUninstall :one
UPDATE device SET uninstall_requested_at = NULL, uninstall_mode = NULL, uninstall_command_id = NULL, uninstalled_at = NULL
WHERE id = @id
RETURNING *;

-- name: GetDeviceUninstall :one
-- The uninstall of a device with its command; local_admin and tpm are the outcome the device reported.
SELECT d.uninstall_mode::text AS mode, d.uninstall_requested_at::timestamptz AS requested_at,
       d.uninstall_command_id::uuid AS command_id, coalesce(c.status, '')::text AS command_status,
       d.uninstalled_at, coalesce(c.result ->> 'local_admin', '')::text AS local_admin,
       coalesce(c.result ->> 'tpm', '')::text AS tpm
FROM device d LEFT JOIN device_command c ON c.id = d.uninstall_command_id
WHERE d.id = @id AND d.uninstall_requested_at IS NOT NULL;

-- name: CancelDeviceCommand :execrows
-- Only a command the device has not received can be cancelled (pending), or one that ended without a removal.
UPDATE device_command SET status = 'cancelled', finished_at = @finished_at::timestamptz
WHERE id = @id AND status IN ('pending','failed','expired');

-- name: DeviceHasOpenRevocation :one
-- An open Lock or Destroy; the standing self-lock token of the dead man's switch does not count.
SELECT EXISTS (
  SELECT 1 FROM revocation_request
  WHERE device_id = @device_id AND action IN ('lock','destroy') AND status IN ('requested','approved','issued','delivered')
)::boolean;

-- name: MarkDeviceUninstalled :execrows
-- The device's report of the removal (agent.uninstalled); the outcome is kept with the command for the device page.
WITH marked AS (
  UPDATE device d SET uninstalled_at = @uninstalled_at::timestamptz
  WHERE d.id = @device_id::uuid AND d.uninstalled_at IS NULL
  RETURNING d.uninstall_command_id
)
UPDATE device_command c SET result = coalesce(c.result, '{}'::jsonb) || @outcome::jsonb
FROM marked m WHERE c.id = m.uninstall_command_id;

-- name: EndFailedUninstall :execrows
-- The device could not start the removal of the request's command: the request ends.
UPDATE device SET uninstall_requested_at = NULL, uninstall_mode = NULL, uninstall_command_id = NULL
WHERE id = @id AND uninstall_command_id = @command_id::uuid AND uninstalled_at IS NULL;

-- name: SetDeviceRetiredReason :exec
UPDATE device SET retired_reason = @reason WHERE id = @id;

-- name: ListCancelledDeviceCommands :many
-- Commands cancelled since a time: the worker removes them from cmd:<device_id>.
SELECT id, device_id FROM device_command WHERE status = 'cancelled' AND finished_at >= @since::timestamptz;
