-- Organization offboarding (plan M17 decisions 7 and 15, ADR 0052 decisions 2 and 4).

-- Deletes at most max_rows rows of the context organization from the first registered table that still has rows;
-- 0 means nothing is left. Only paddock_worker may call it, inside InOrg of an organization in status deleting.
-- name: OffboardDeleteBatch :one
SELECT paddock_offboard_delete_batch(@max_rows::int)::bigint AS deleted;

-- Waits for every transaction that entered the organization before it was deleting, re-counts every registered table
-- (40001 when rows remain) and writes the tombstone in the same transaction (plan M17 amendment 2026-11-14 d). Only
-- paddock_worker may call it, inside InOrgOffboarding of an organization in status deleting.
-- name: OffboardFinalize :exec
SELECT paddock_offboard_finalize();

-- name: ListOffboardingTables :many
SELECT table_name, delete_order FROM offboarding_table ORDER BY delete_order;

-- Devices that had not reported their removal when their organization was deleted (platform role only).

-- name: InsertOffboardedDevice :exec
INSERT INTO offboarded_device (device_id, organization_id, keys, command_id, command_envelope)
VALUES (@device_id, @organization_id, @keys, @command_id, @command_envelope)
ON CONFLICT (device_id) DO NOTHING;

-- name: GetOffboardedDevice :one
SELECT * FROM offboarded_device WHERE device_id = @device_id;

-- name: ListOffboardedDevices :many
SELECT * FROM offboarded_device ORDER BY device_id;

-- name: DeleteOffboardedDevice :one
DELETE FROM offboarded_device WHERE device_id = @device_id RETURNING *;

-- name: PurgeOffboardedDevices :many
DELETE FROM offboarded_device WHERE offboarded_at < @before RETURNING device_id, organization_id;
