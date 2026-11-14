-- Device owners (plan M8d decisions 1–4).

-- name: ListDeviceOwners :many
SELECT sqlc.embed(app_user) FROM device_owner JOIN app_user ON app_user.id = device_owner.user_id
WHERE device_owner.device_id = @device_id
ORDER BY app_user.username;

-- name: InsertDeviceOwner :exec
INSERT INTO device_owner (organization_id, device_id, user_id, assigned_by)
VALUES (@organization_id, @device_id, @user_id, sqlc.narg(assigned_by));

-- name: DeleteDeviceOwner :exec
DELETE FROM device_owner WHERE device_id = @device_id AND user_id = @user_id;

-- name: ListDeviceOwnersWithUsernames :many
-- Every owner of the organization's devices with the user name (lower-case UPN), for the compiler (plan M13b
-- decision 8).
SELECT device_owner.device_id, device_owner.user_id, app_user.username
FROM device_owner JOIN app_user ON app_user.id = device_owner.user_id
ORDER BY device_owner.device_id, app_user.username;
