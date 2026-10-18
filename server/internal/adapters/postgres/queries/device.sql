-- name: InsertDevice :one
INSERT INTO device (id, organization_id, hostname, state, hardware_uuid, machine_id, os_release, enrollment_token_id)
VALUES (@id, @organization_id, @hostname, @state, sqlc.narg(hardware_uuid), sqlc.narg(machine_id), @os_release,
        sqlc.narg(enrollment_token_id))
RETURNING *;

-- name: GetDevice :one
SELECT * FROM device WHERE id = @id;

-- name: LockDevice :one
SELECT * FROM device WHERE id = @id FOR UPDATE;

-- List queries (ADR 0018): see device_group.sql. Sort and search columns are unambiguous across the join.

-- name: ListDevices :many
SELECT sqlc.embed(device), device_status.last_contact_at, device_status.applied_bundle_version,
       device_status.agent_version, coalesce(device_status.health -> 'disk' ->> 'state', '')::text AS disk_state, -- '' = none
       paddock_device_contact(device.state, device_status.last_contact_at, device_status.presumed_lost_at, open_alert.kind, now())::text AS contact,
       -- The owners as UserRef objects for the list column (plan M8d decision 3).
       (SELECT coalesce(jsonb_agg(jsonb_build_object('id', u.id, 'username', u.username, 'display_name', u.display_name)
                                  ORDER BY u.username), '[]'::jsonb)
        FROM device_owner o JOIN app_user u ON u.id = o.user_id WHERE o.device_id = device.id)::jsonb AS owners,
       -- Hardware facts (plan M8d decision 8): NULL while no inventory row exists.
       inv.hardware_vendor, inv.hardware_model, inv.hardware_serial, inv.cpu_brand, inv.cpu_cores, inv.memory_bytes,
       inv.disk_total_bytes
FROM device LEFT JOIN device_status ON device_status.device_id = device.id
LEFT JOIN device_alert open_alert ON open_alert.device_id = device.id AND open_alert.cleared_at IS NULL
LEFT JOIN device_inventory_ref inv ON inv.device_id = device.id
WHERE (sqlc.narg(q_pattern)::text IS NULL
       OR hostname ILIKE sqlc.narg(q_pattern)::text ESCAPE '\'
       OR hardware_uuid ILIKE sqlc.narg(q_pattern)::text ESCAPE '\'
       OR inv.hardware_serial ILIKE sqlc.narg(q_pattern)::text ESCAPE '\'
       OR EXISTS (SELECT 1 FROM device_owner o JOIN app_user u ON u.id = o.user_id WHERE o.device_id = device.id
                  AND (u.username ILIKE sqlc.narg(q_pattern)::text ESCAPE '\' OR u.display_name ILIKE sqlc.narg(q_pattern)::text ESCAPE '\')))
  AND (sqlc.narg(states)::text[] IS NULL OR state = ANY(sqlc.narg(states)::text[]))
  AND (sqlc.narg(disk_states)::text[] IS NULL OR device_status.health -> 'disk' ->> 'state' = ANY(sqlc.narg(disk_states)::text[]))
  AND (sqlc.narg(contacts)::text[] IS NULL
       OR paddock_device_contact(device.state, device_status.last_contact_at, device_status.presumed_lost_at, open_alert.kind, now()) = ANY(sqlc.narg(contacts)::text[]))
  -- security_updates=overdue (plan M7c amendment 2026-10-10): contacted, but no successful security run within the window.
  AND (sqlc.narg(security_overdue_window)::interval IS NULL OR (device_status.last_contact_at IS NOT NULL AND (
         device_status.login_state -> 'updates_security' IS NULL
         OR device_status.login_state -> 'updates_security' -> 'params' ->> 'result' IS DISTINCT FROM 'ok'
         OR (device_status.login_state -> 'updates_security' ->> 'occurred_at')::timestamptz < now() - sqlc.narg(security_overdue_window)::interval)))
  AND (sqlc.narg(device_group_id)::uuid IS NULL OR EXISTS (
        SELECT 1 FROM device_group_member m
        WHERE m.device_id = device.id AND m.device_group_id = sqlc.narg(device_group_id)::uuid))
  AND (sqlc.narg(owner_id)::uuid IS NULL OR EXISTS (
        SELECT 1 FROM device_owner o WHERE o.device_id = device.id AND o.user_id = sqlc.narg(owner_id)::uuid))
ORDER BY
  CASE WHEN @sort::text = 'hostname' THEN hostname END ASC,
  CASE WHEN @sort::text = '-hostname' THEN hostname END DESC,
  CASE WHEN @sort::text = 'last_contact_at' THEN last_contact_at END ASC,
  CASE WHEN @sort::text = '-last_contact_at' THEN last_contact_at END DESC,
  CASE WHEN @sort::text = 'enrolled_at' THEN enrolled_at END ASC,
  CASE WHEN @sort::text = '-enrolled_at' THEN enrolled_at END DESC,
  CASE WHEN @sort::text = 'state' THEN state END ASC,
  CASE WHEN @sort::text = '-state' THEN state END DESC,
  device.id
LIMIT @max_rows OFFSET @skip_rows;

-- name: CountDevices :one
SELECT count(*) FROM (
  SELECT 1 FROM device LEFT JOIN device_status ON device_status.device_id = device.id
  LEFT JOIN device_alert open_alert ON open_alert.device_id = device.id AND open_alert.cleared_at IS NULL
  LEFT JOIN device_inventory_ref inv ON inv.device_id = device.id
  WHERE (sqlc.narg(q_pattern)::text IS NULL
         OR hostname ILIKE sqlc.narg(q_pattern)::text ESCAPE '\'
         OR hardware_uuid ILIKE sqlc.narg(q_pattern)::text ESCAPE '\'
         OR inv.hardware_serial ILIKE sqlc.narg(q_pattern)::text ESCAPE '\'
         OR EXISTS (SELECT 1 FROM device_owner o JOIN app_user u ON u.id = o.user_id WHERE o.device_id = device.id
                    AND (u.username ILIKE sqlc.narg(q_pattern)::text ESCAPE '\' OR u.display_name ILIKE sqlc.narg(q_pattern)::text ESCAPE '\')))
    AND (sqlc.narg(states)::text[] IS NULL OR state = ANY(sqlc.narg(states)::text[]))
    AND (sqlc.narg(disk_states)::text[] IS NULL OR device_status.health -> 'disk' ->> 'state' = ANY(sqlc.narg(disk_states)::text[]))
    AND (sqlc.narg(contacts)::text[] IS NULL
         OR paddock_device_contact(device.state, device_status.last_contact_at, device_status.presumed_lost_at, open_alert.kind, now()) = ANY(sqlc.narg(contacts)::text[]))
    AND (sqlc.narg(security_overdue_window)::interval IS NULL OR (device_status.last_contact_at IS NOT NULL AND (
           device_status.login_state -> 'updates_security' IS NULL
           OR device_status.login_state -> 'updates_security' -> 'params' ->> 'result' IS DISTINCT FROM 'ok'
           OR (device_status.login_state -> 'updates_security' ->> 'occurred_at')::timestamptz < now() - sqlc.narg(security_overdue_window)::interval)))
    AND (sqlc.narg(device_group_id)::uuid IS NULL OR EXISTS (
          SELECT 1 FROM device_group_member m
          WHERE m.device_id = device.id AND m.device_group_id = sqlc.narg(device_group_id)::uuid))
    AND (sqlc.narg(owner_id)::uuid IS NULL OR EXISTS (
          SELECT 1 FROM device_owner o WHERE o.device_id = device.id AND o.user_id = sqlc.narg(owner_id)::uuid))
  LIMIT @count_limit
) matching;

-- name: DeviceContact :one
SELECT paddock_device_contact(device.state, device_status.last_contact_at, device_status.presumed_lost_at, open_alert.kind, now())::text AS contact
FROM device LEFT JOIN device_status ON device_status.device_id = device.id
LEFT JOIN device_alert open_alert ON open_alert.device_id = device.id AND open_alert.cleared_at IS NULL
WHERE device.id = @id;

-- name: ListDeviceHostnames :many
-- The devices of the caller's organization among ids (RLS bounds it): the audit list resolves hostnames with it.
SELECT id, hostname FROM device WHERE id = ANY(@ids::uuid[]);

-- name: SetDeviceState :one
UPDATE device SET state = @state, state_changed_at = now()
WHERE id = @id AND state = @from_state
RETURNING *;

-- name: InsertDeviceIdentityKey :exec
INSERT INTO device_identity_key (key_id, organization_id, device_id, public_key, key_protection, status)
VALUES (@key_id, @organization_id, @device_id, @public_key, @key_protection, 'active');

-- name: GetDeviceIdentityKey :one
SELECT * FROM device_identity_key WHERE key_id = @key_id;

-- name: ListDeviceIdentityKeys :many
SELECT * FROM device_identity_key WHERE device_id = @device_id ORDER BY created_at, key_id;

-- name: RevokeDeviceIdentityKeys :exec
UPDATE device_identity_key SET status = 'revoked' WHERE device_id = @device_id AND status = 'active';

-- name: ListDeviceGroupsOfDevice :many
SELECT g.id, g.name FROM device_group_member m JOIN device_group g ON g.id = m.device_group_id
WHERE m.device_id = @device_id
ORDER BY g.name, g.id;

-- name: ListDeviceGroupIDsOfDevice :many
SELECT device_group_id FROM device_group_member WHERE device_id = @device_id ORDER BY device_group_id;

-- name: InsertDeviceGroupMember :exec
INSERT INTO device_group_member (organization_id, device_group_id, device_id)
VALUES (@organization_id, @device_group_id, @device_id)
ON CONFLICT DO NOTHING;

-- name: DeleteDeviceGroupMember :exec
DELETE FROM device_group_member WHERE device_group_id = @device_group_id AND device_id = @device_id;

-- name: GetDeviceStatus :one
SELECT * FROM device_status WHERE device_id = @device_id;

-- name: GetLatestBundle :one
SELECT * FROM bundle WHERE device_id = @device_id ORDER BY version DESC LIMIT 1;

-- Worker cache sync: identity keys with the state of their device; pending devices are not cached (plan M2a
-- decision 10).
-- name: ListCachedDeviceKeys :many
SELECT k.key_id, k.public_key, k.status AS key_status, d.id AS device_id, d.state
FROM device_identity_key k JOIN device d ON d.id = k.device_id
WHERE d.state <> 'pending' AND (sqlc.narg(device_id)::uuid IS NULL OR d.id = sqlc.narg(device_id)::uuid)
ORDER BY k.key_id;

-- Update now (plan M8d decisions 26 and 29).

-- name: SetAgentUpdateRequest :exec
UPDATE device SET agent_update_requested_version = @version, agent_update_requested_at = now() WHERE id = @id;

-- name: ClearAgentUpdateRequest :execrows
-- The device reported the outcome of the requested version.
UPDATE device SET agent_update_requested_version = NULL, agent_update_requested_at = NULL
WHERE id = @device_id AND agent_update_requested_version = @version;

-- name: ExpireAgentUpdateRequests :execrows
UPDATE device SET agent_update_requested_version = NULL, agent_update_requested_at = NULL
WHERE agent_update_requested_at < @before::timestamptz;

-- name: ListAgentUpdateRequests :many
SELECT id, agent_update_requested_version, agent_update_requested_at FROM device
WHERE agent_update_requested_at IS NOT NULL ORDER BY id;
