-- Login assignment, suspension and session reports (plan M3a decisions 9–11).

-- name: ListDeviceLoginAssignments :many
SELECT * FROM device_login_assignment WHERE device_id = @device_id ORDER BY subject_type, subject_id;

-- name: ListAllDeviceLoginAssignments :many
SELECT * FROM device_login_assignment ORDER BY device_id, subject_type, subject_id;

-- name: InsertDeviceLoginAssignment :exec
INSERT INTO device_login_assignment (organization_id, device_id, subject_type, subject_id)
VALUES (@organization_id, @device_id, @subject_type, @subject_id);

-- name: DeleteDeviceLoginAssignments :exec
DELETE FROM device_login_assignment WHERE device_id = @device_id;

-- A deleted user or group leaves every login assignment (the subject has no foreign key, plan M3a decision 9).
-- name: DeleteLoginAssignmentsOfSubject :many
DELETE FROM device_login_assignment WHERE subject_id = @subject_id RETURNING device_id;

-- name: SetDeviceLoginsSuspended :one
UPDATE device SET logins_suspended = @logins_suspended WHERE id = @id RETURNING *;

-- Worker: a session.login event of the agent (no audit event per login).
-- name: UpsertDeviceUserSeen :exec
INSERT INTO device_user_seen (organization_id, device_id, username, last_seen_at)
VALUES (@organization_id, @device_id, @username, @last_seen_at)
ON CONFLICT (device_id, username) DO UPDATE SET last_seen_at = greatest(device_user_seen.last_seen_at, EXCLUDED.last_seen_at);

-- name: ListDeviceUsersSeenSince :many
SELECT device_id, username FROM device_user_seen WHERE last_seen_at >= @since ORDER BY device_id, username;

-- name: HasExpiredDeviceUserSeen :one
SELECT EXISTS (SELECT 1 FROM device_user_seen WHERE last_seen_at < @cutoff::timestamptz);

-- name: SetRetentionLockTimeout :exec
-- Bounds the row-lock wait of one retention batch, so a blocked DELETE cannot hold a pass past the outbox reaper's
-- threshold (plan M10 amendment 2026-10-30); the transaction-local setting ends with the batch.
SELECT set_config('lock_timeout', @timeout::text, true);

-- name: DeleteExpiredDeviceUserSeen :execrows
-- One batch of rows older than the cutoff (plan M10 decision 13); the retention round runs each batch in its own
-- transaction until one deletes fewer than 1 000 rows (plan M10 amendment 2026-10-30).
DELETE FROM device_user_seen WHERE ctid IN (
  SELECT ctid FROM device_user_seen WHERE last_seen_at < @cutoff::timestamptz LIMIT 1000
);

-- Device groups of every device, for the effective profiles of the organization.
-- name: ListAllDeviceGroupMembers :many
SELECT device_id, device_group_id FROM device_group_member ORDER BY device_id, device_group_id;
