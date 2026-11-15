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

-- Locks the devices of the context organization that may still contact the server, disarms their dead man's switch and
-- gives each without a usable open uninstall a fresh one (plan M17 decision 15, amendments e, m and n, migration
-- 00135); returns how many uninstalls this call issued.
-- name: OffboardReissueUninstalls :one
SELECT paddock_offboard_reissue_uninstalls()::bigint;

-- The devices the step devices hands over to offboarded_device: no reported removal, approved at least once (a pending
-- device cannot verify a command), neither retired nor rejected.
-- name: ListOffboardingHandedDevices :many
SELECT id FROM device WHERE uninstalled_at IS NULL AND state NOT IN ('pending', 'retired', 'rejected') ORDER BY id;

-- The commands the handed-over devices keep: the uninstall, kept or fresh, and the hand-over's delete_self_lock (the only
-- disarm that lives longer than the type's 30 days).
-- name: ListOffboardingHandoverCommands :many
SELECT c.* FROM device_command c JOIN device d ON d.id = c.device_id
WHERE d.id = ANY(@device_ids::uuid[])
  AND (c.id = d.uninstall_command_id OR (c.type = 'delete_self_lock' AND c.status IN ('pending', 'delivered', 'succeeded')
    AND c.expires_at > now() + interval '31 days'))
ORDER BY c.device_id, c.id;

-- The cancelled uninstalls of the handed-over devices, among them the predecessors the hand-over replaced: the worker's
-- removal of cancelled commands from cmd: runs through the gate and no longer reaches a deleting organization.
-- name: ListOffboardingCancelledUninstalls :many
SELECT device_id, id FROM device_command
WHERE device_id = ANY(@device_ids::uuid[]) AND type = 'uninstall' AND status = 'cancelled'
ORDER BY device_id, id;

-- The active identity keys of the handed-over devices with their check-in counters.
-- name: ListOffboardingDeviceIdentities :many
SELECT k.device_id, k.key_id, k.public_key, coalesce(s.last_seq, 0)::bigint AS last_seq
FROM device_identity_key k LEFT JOIN device_status s ON s.device_id = k.device_id
WHERE k.device_id = ANY(@device_ids::uuid[]) AND k.status = 'active'
ORDER BY k.device_id, k.key_id;

-- name: ListOffboardingTables :many
SELECT table_name, delete_order FROM offboarding_table ORDER BY delete_order;

-- Devices that had not reported their removal when their organization was deleted (platform role only).

-- A device handed over again (a repeated step) keeps its row; only new rows count.
-- name: InsertOffboardedDevices :execrows
INSERT INTO offboarded_device (device_id, organization_id, keys, command_envelopes)
SELECT unnest(@device_ids::uuid[]), @organization_id::uuid, unnest(@keys::text[])::jsonb, unnest(@command_envelopes::text[])::jsonb
ON CONFLICT (device_id) DO NOTHING;

-- The offboarded devices of an organization, whose identity, command and sequence keys outlive it (plan M17 amendment l
-- point 3).
-- name: ListOffboardedDeviceIDs :many
SELECT device_id FROM offboarded_device WHERE organization_id = @organization_id ORDER BY device_id;

-- name: GetOffboardedDevice :one
SELECT * FROM offboarded_device WHERE device_id = @device_id;

-- name: ListOffboardedDevices :many
SELECT * FROM offboarded_device ORDER BY device_id;

-- name: DeleteOffboardedDevice :one
DELETE FROM offboarded_device WHERE device_id = @device_id RETURNING *;

-- name: ListExpiredOffboardedDevices :many
SELECT * FROM offboarded_device WHERE offboarded_at < @before ORDER BY offboarded_at, device_id LIMIT @max_rows;

-- name: DeleteOffboardedDevices :execrows
DELETE FROM offboarded_device WHERE device_id = ANY(@device_ids::uuid[]);

-- The devices of ids that still have a record: the cache sync deletes the keys it rewrote for any other (a device
-- that reported its removal meanwhile).
-- name: ListPresentOffboardedDevices :many
SELECT device_id FROM offboarded_device WHERE device_id = ANY(@device_ids::uuid[]) ORDER BY device_id;

-- The devices of the context organization still pending approval, for the deletion banner (plan M17 amendment m point 1).
-- name: CountPendingDevices :one
SELECT count(*)::bigint FROM device WHERE state = 'pending';
