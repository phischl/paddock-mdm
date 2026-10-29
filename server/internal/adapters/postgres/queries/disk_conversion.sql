-- In-place encryption (plan M8e decisions 6–10).

-- name: InsertDiskConversion :one
INSERT INTO device_disk_conversion (id, organization_id, device_id, command_id, requested_at, requested_by, reason, phase,
  phase_at)
VALUES (@id, @organization_id, @device_id, @command_id, @requested_at, @requested_by, @reason, 'requested', @requested_at)
RETURNING *;

-- name: GetLatestDiskConversion :one
-- The device's latest conversion with the status of its encrypt_disk command and of its abort command: the open one,
-- else the one whose phase changed last — an older conversion the device adopted (plan M8e §14.10 I2) is newer than
-- a request refused meanwhile (architect decision 2026-10-21, PDK-241 review 1). The attention view orders alike.
-- completed_at is when the device's latest completed conversion finished, whichever row is the latest (plan M8e
-- amendment 2026-10-21: the active rule of a completed conversion).
SELECT sqlc.embed(device_disk_conversion), c.status AS command_status, a.status AS abort_command_status,
  done.finished_at AS completed_at
FROM device_disk_conversion
JOIN device_command c ON c.id = device_disk_conversion.command_id
LEFT JOIN device_command a ON a.id = device_disk_conversion.abort_command_id
LEFT JOIN device_disk_conversion done ON done.id = (
  SELECT d.id FROM device_disk_conversion d WHERE d.device_id = device_disk_conversion.device_id AND d.phase = 'completed'
  ORDER BY d.phase_at DESC, d.id DESC LIMIT 1)
WHERE device_disk_conversion.device_id = @device_id
ORDER BY (device_disk_conversion.phase IN ('requested','prepared','encrypting')) DESC, device_disk_conversion.phase_at DESC,
  device_disk_conversion.id DESC
LIMIT 1;

-- name: LockDiskConversionPhase :one
-- The phase of a conversion under its row lock: a withdrawal re-reads it, so an event that moved it meanwhile wins.
SELECT phase FROM device_disk_conversion WHERE id = @id FOR UPDATE;

-- name: CancelDiskConversion :execrows
-- A conversion whose encrypt_disk command was withdrawn before delivery (cancel, Retire, Lock or Destroy).
UPDATE device_disk_conversion SET phase = 'cancelled', phase_at = @at::timestamptz, finished_at = @at::timestamptz
WHERE id = @id AND phase = 'requested';

-- name: CloseDiskConversion :execrows
-- A Retire closes a prepared conversion or one with an abort on its way (plan M8e §14.5 decision 38, amendment
-- 2026-10-28).
UPDATE device_disk_conversion SET phase = 'cancelled', phase_at = @at::timestamptz, finished_at = @at::timestamptz
WHERE id = @id AND phase IN ('requested','prepared');

-- name: SetDiskConversionAbort :execrows
UPDATE device_disk_conversion SET abort_command_id = @abort_command_id, abort_refused_reason = NULL
WHERE id = @id AND phase IN ('requested','prepared');

-- name: PrepareDiskConversion :execrows
-- disk.conversion_prepared of the device's conversion (decision 9).
UPDATE device_disk_conversion SET phase = 'prepared', layout = coalesce(sqlc.narg(layout), layout),
  luks_uuid = coalesce(sqlc.narg(luks_uuid), luks_uuid), data_bytes = coalesce(sqlc.narg(data_bytes), data_bytes),
  phase_at = now()
WHERE id = @id AND device_id = @device_id AND phase IN ('requested','prepared');

-- name: StartDiskConversion :execrows
-- disk.conversion_started: the device converted its disk, also for a conversion it had failed or cancelled (plan M8e
-- §14.10 I2); refused while another conversion of the device is open (device_disk_conversion_open_idx). The caller
-- holds the device's row lock, so no request opens a conversion meanwhile.
UPDATE device_disk_conversion c SET phase = 'encrypting', failure_stage = NULL, failure_reason = NULL,
  finished_at = NULL, phase_at = now()
WHERE c.id = @id AND c.device_id = @device_id AND c.phase IN ('requested','prepared','failed','cancelled')
  AND NOT EXISTS (SELECT 1 FROM device_disk_conversion o
                  WHERE o.device_id = c.device_id AND o.id <> c.id AND o.phase IN ('requested','prepared','encrypting'));

-- name: CompleteDiskConversion :execrows
-- disk.conversion_completed: the disk is encrypted whatever the row said, also after a resume failure or for a
-- cancelled conversion whose adoption was refused while another one was open (decision 9).
UPDATE device_disk_conversion SET phase = 'completed', finished_at = now(), phase_at = now(),
  data_bytes = coalesce(sqlc.narg(data_bytes), data_bytes)
WHERE id = @id AND device_id = @device_id AND phase IN ('requested','prepared','encrypting','failed','cancelled');

-- name: FailDiskConversion :execrows
-- disk.conversion_failed of an open conversion.
UPDATE device_disk_conversion SET phase = 'failed', failure_stage = sqlc.narg(failure_stage),
  failure_reason = sqlc.narg(failure_reason), finished_at = now(), phase_at = now()
WHERE id = @id AND device_id = @device_id AND phase IN ('requested','prepared','encrypting');

-- name: AbortDiskConversion :execrows
-- disk.conversion_aborted: the device abandoned the conversion before its restart.
UPDATE device_disk_conversion SET phase = 'cancelled', finished_at = now(), phase_at = now()
WHERE id = @id AND device_id = @device_id AND phase IN ('requested','prepared');

-- name: RefuseDiskConversionCommand :execrows
-- The device refused encrypt_disk ({accepted: false}): the conversion fails at stage preflight (decision 9).
UPDATE device_disk_conversion SET phase = 'failed', failure_stage = 'preflight', failure_reason = sqlc.narg(reason),
  finished_at = now(), phase_at = now()
WHERE command_id = @command_id AND device_id = @device_id AND phase = 'requested';

-- name: RefuseDiskConversionAbort :execrows
-- The device refused encrypt_disk_abort ({aborted: false, reason}); the phase stays.
UPDATE device_disk_conversion SET abort_refused_reason = sqlc.narg(reason)
WHERE abort_command_id = @abort_command_id AND device_id = @device_id;
