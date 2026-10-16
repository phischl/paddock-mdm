-- name: UpsertPlatformAdmin :one
INSERT INTO platform_admin (id, authentik_sub, username, display_name, last_login_at)
VALUES (@id, @authentik_sub, @username, @display_name, now())
ON CONFLICT (authentik_sub) DO UPDATE
SET username = EXCLUDED.username, display_name = EXCLUDED.display_name, last_login_at = now()
RETURNING *;

-- name: GetPlatformAdmin :one
SELECT * FROM platform_admin WHERE id = @id;

-- name: UpdatePlatformAdminSettings :one
UPDATE platform_admin
SET locale = coalesce(sqlc.narg(locale), locale), theme = coalesce(sqlc.narg(theme), theme)
WHERE id = @id RETURNING *;

-- name: UpsertAdminAccount :one
INSERT INTO admin_account (id, organization_id, authentik_sub, username, display_name, role, last_login_at)
VALUES (@id, @organization_id, @authentik_sub, @username, @display_name, @role, now())
ON CONFLICT (authentik_sub) DO UPDATE
SET username = EXCLUDED.username, display_name = EXCLUDED.display_name, role = EXCLUDED.role, last_login_at = now(),
    disabled_at = NULL
RETURNING *;

-- name: GetAdminAccount :one
SELECT * FROM admin_account WHERE id = @id;

-- name: GetAdminAccountBySubject :one
SELECT * FROM admin_account WHERE authentik_sub = @authentik_sub;

-- name: UpdateAdminAccountSettings :one
UPDATE admin_account
SET locale = coalesce(sqlc.narg(locale), locale), theme = coalesce(sqlc.narg(theme), theme)
WHERE id = @id RETURNING *;

-- name: GetPlatformAdminBySubject :one
SELECT * FROM platform_admin WHERE authentik_sub = @authentik_sub;

-- name: SetAdminAccountRole :exec
-- The role the identity provider grants now (plan M8s decisions 20 and 22).
UPDATE admin_account SET role = @role WHERE id = @id;

-- name: DisableAdminAccount :exec
-- The account has no role in its organization any more or was deactivated (plan M8s decisions 20 and 22).
UPDATE admin_account SET disabled_at = now() WHERE id = @id AND disabled_at IS NULL;

-- name: ListAdminAccounts :many
-- The accounts of the organization that are not disabled, for the worker round admin-accounts (plan M8s decision 22).
SELECT * FROM admin_account WHERE disabled_at IS NULL ORDER BY id;

-- name: ListPlatformAdmins :many
-- Every platform administrator that ever signed in, for the worker round admin-accounts (PDK-185).
SELECT * FROM platform_admin ORDER BY id;
