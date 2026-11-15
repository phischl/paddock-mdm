-- Organization offboarding (plan M17 decisions 7 and 15, ADR 0052 decisions 2 and 4).

-- Deletes at most max_rows rows of the context organization from the first registered table that still has rows;
-- 0 means nothing is left. Only paddock_worker may call it, inside InOrg of an organization in status deleting.
-- name: OffboardDeleteBatch :one
SELECT paddock_offboard_delete_batch(@max_rows::int)::bigint AS deleted;

-- True once every transaction that could have passed the gate before it saw the organization deleting has ended; false
-- while waiting (plan M17 amendment 2026-11-15 j and its addendum). The step tombstone calls it every round and calls
-- OffboardFinalize once it is true. Only paddock_worker may call it, inside InOrgOffboarding of an organization in
-- status deleting.
-- name: OffboardQuiesce :one
SELECT paddock_offboard_quiesce()::boolean AS ready;

-- Requires OffboardQuiesce to be true (else 55000), re-counts every registered table (40001 when rows remain) and
-- writes the tombstone in the same transaction (plan M17 amendments 2026-11-14 d, 2026-11-15 j). Only paddock_worker
-- may call it, inside InOrgOffboarding of an organization in status deleting.
-- name: OffboardFinalize :exec
SELECT paddock_offboard_finalize();

-- The number of the context organization's unpublished outbox rows (plan M17 decision 9, amendment c point 2); the
-- step outbox completes at 0. Only paddock_worker may call it, inside InOrgOffboarding of a deleting organization.
-- name: OffboardOutboxPending :one
SELECT paddock_offboard_outbox_pending()::bigint AS pending;

-- Revokes every API token of the context organization (decision 14) and returns how many were still live.
-- name: OffboardRevokeAPITokens :one
SELECT paddock_offboard_revoke_api_tokens()::bigint AS revoked;

-- The administrator accounts of the context organization, whose portal and MCP sessions the step sessions ends.
-- name: ListOffboardingAdminAccounts :many
SELECT id FROM admin_account ORDER BY id;

-- Every device of the context organization with its identity keys (key_id empty for a device without one), for the
-- step valkey (decision 13).
-- name: ListOffboardingDeviceKeys :many
SELECT d.id AS device_id, coalesce(k.key_id, '')::text AS key_id
FROM device d LEFT JOIN device_identity_key k ON k.device_id = d.id
ORDER BY d.id, k.key_id;

-- The Fleet hosts the context organization's devices reference, for the step fleet (decision 11).
-- name: ListOffboardingInventoryRefs :many
SELECT device_id, external_id FROM device_inventory_ref ORDER BY device_id;

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
