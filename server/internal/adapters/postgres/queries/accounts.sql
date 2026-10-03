-- name: UpsertPlatformAdmin :one
INSERT INTO platform_admin (id, authentik_sub, username, display_name, last_login_at)
VALUES (@id, @authentik_sub, @username, @display_name, now())
ON CONFLICT (authentik_sub) DO UPDATE
SET username = EXCLUDED.username, display_name = EXCLUDED.display_name, last_login_at = now()
RETURNING *;

-- name: GetPlatformAdmin :one
SELECT * FROM platform_admin WHERE id = @id;

-- name: UpdatePlatformAdminLocale :one
UPDATE platform_admin SET locale = @locale WHERE id = @id RETURNING *;

-- name: UpsertAdminAccount :one
INSERT INTO admin_account (id, organization_id, authentik_sub, username, display_name, role, last_login_at)
VALUES (@id, @organization_id, @authentik_sub, @username, @display_name, @role, now())
ON CONFLICT (authentik_sub) DO UPDATE
SET username = EXCLUDED.username, display_name = EXCLUDED.display_name, role = EXCLUDED.role, last_login_at = now()
RETURNING *;

-- name: GetAdminAccount :one
SELECT * FROM admin_account WHERE id = @id;

-- name: GetAdminAccountBySubject :one
SELECT * FROM admin_account WHERE authentik_sub = @authentik_sub;

-- name: UpdateAdminAccountLocale :one
UPDATE admin_account SET locale = @locale WHERE id = @id RETURNING *;
