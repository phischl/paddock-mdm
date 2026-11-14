-- Maintenance windows of device groups (PDK-809, plan M13c decision 4).

-- name: GetMaintenanceWindow :one
SELECT * FROM device_group_maintenance_window WHERE device_group_id = @device_group_id;

-- name: UpsertMaintenanceWindow :one
INSERT INTO device_group_maintenance_window (organization_id, device_group_id, days, start_minute, duration_minutes,
  timezone, updated_by)
VALUES (@organization_id, @device_group_id, @days::int[], @start_minute, @duration_minutes, @timezone, sqlc.narg(updated_by))
ON CONFLICT (organization_id, device_group_id) DO UPDATE SET days = EXCLUDED.days, start_minute = EXCLUDED.start_minute,
  duration_minutes = EXCLUDED.duration_minutes, timezone = EXCLUDED.timezone, updated_by = EXCLUDED.updated_by,
  updated_at = now()
RETURNING *;

-- name: DeleteMaintenanceWindow :execrows
DELETE FROM device_group_maintenance_window WHERE device_group_id = @device_group_id;

-- name: ListAllMaintenanceWindows :many
-- Every window of the organization (compiler, declarative configuration), in a stable order.
SELECT * FROM device_group_maintenance_window ORDER BY device_group_id;
