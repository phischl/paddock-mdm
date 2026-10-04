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

-- Device groups of every device, for the effective profiles of the organization.
-- name: ListAllDeviceGroupMembers :many
SELECT device_id, device_group_id FROM device_group_member ORDER BY device_id, device_group_id;
