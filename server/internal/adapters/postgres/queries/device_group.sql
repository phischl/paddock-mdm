-- name: InsertDeviceGroup :one
INSERT INTO device_group (id, organization_id, name, description)
VALUES (@id, @organization_id, @name, @description)
RETURNING *;

-- name: GetDeviceGroup :one
SELECT * FROM device_group WHERE id = @id;

-- name: ListDeviceGroups :many
SELECT * FROM device_group
WHERE (sqlc.narg(before)::uuid IS NULL OR id < sqlc.narg(before)::uuid)
ORDER BY id DESC
LIMIT @max_rows;

-- name: UpdateDeviceGroup :one
UPDATE device_group SET name = @name, description = @description, updated_at = now()
WHERE id = @id
RETURNING *;

-- name: DeleteDeviceGroup :execrows
DELETE FROM device_group WHERE id = @id;
