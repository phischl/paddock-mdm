-- Login settings (plan M3a decision 8): one row per organization, created with the defaults by a trigger.

-- name: GetLoginSettings :one
SELECT * FROM organization_login_settings;

-- name: UpdateLoginSettings :one
UPDATE organization_login_settings
SET hello_enabled = @hello_enabled, hello_pin_min_length = @hello_pin_min_length,
    user_lock_session_action = @user_lock_session_action, break_glass_accounts = @break_glass_accounts,
    sudoers_d_allowlist = @sudoers_d_allowlist, sudo_lecture_text = @sudo_lecture_text,
    local_admin_username = @local_admin_username, local_admin_rotation_days = @local_admin_rotation_days,
    rotate_after_reveal_hours = sqlc.narg(rotate_after_reveal_hours), notice_text = @notice_text, updated_at = now()
RETURNING *;
