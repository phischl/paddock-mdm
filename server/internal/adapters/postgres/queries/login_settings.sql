-- Login settings (plan M3a decision 8): one row per organization, created with the defaults by a trigger.

-- name: GetLoginSettings :one
SELECT * FROM organization_login_settings;

-- name: UpdateLoginSettings :one
UPDATE organization_login_settings
SET hello_enabled = @hello_enabled, hello_pin_min_length = @hello_pin_min_length,
    user_lock_session_action = @user_lock_session_action, break_glass_accounts = @break_glass_accounts,
    sudoers_d_allowlist = @sudoers_d_allowlist, sudo_lecture_text = @sudo_lecture_text,
    local_admin_username = @local_admin_username, local_admin_rotation_days = @local_admin_rotation_days,
    rotate_after_reveal_hours = sqlc.narg(rotate_after_reveal_hours), notice_text = @notice_text,
    boot_pin_min_length = @boot_pin_min_length, login_history_enabled = @login_history_enabled,
    login_history_days = @login_history_days, disk_unlock_mode = @disk_unlock_mode, updated_at = now(),
    login_history_enabled_at = CASE
      WHEN NOT @login_history_enabled::boolean THEN NULL
      WHEN organization_login_settings.login_history_enabled THEN organization_login_settings.login_history_enabled_at
      ELSE now() END
RETURNING *;

-- name: LockLoginHistory :exec
-- Serializes a change of the login history setting with the worker's inserts (LockLoginHistoryShared): a switch-off
-- waits for running inserts, and its deletion sees them (PDK-223 review 1 finding 3).
SELECT pg_advisory_xact_lock(hashtextextended('login_history:' || current_setting('paddock.org_id'), 0));

-- name: LockLoginHistoryShared :exec
-- Taken by the worker before it reads the setting and inserts a login; concurrent inserts do not block each other.
SELECT pg_advisory_xact_lock_shared(hashtextextended('login_history:' || current_setting('paddock.org_id'), 0));
