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

-- name: LockPlatformAdmin :one
-- The worker's revocation waits for a running login of the platform administrator, whose upsert holds the row.
SELECT id FROM platform_admin WHERE id = @id FOR UPDATE;

-- name: GetAdminAccountState :one
-- Read on every MCP request (plan M14 §3.3 item 14): a disabled account or a changed role ends its sessions.
SELECT role, (disabled_at IS NOT NULL)::boolean AS disabled, (mcp_write_enabled_at IS NOT NULL)::boolean AS mcp_write_enabled
FROM admin_account WHERE id = @id;

-- name: GetPlatformAdminState :one
-- Read on every MCP request of a platform administrator (plan M14 §3.3 item 14).
SELECT (mcp_write_enabled_at IS NOT NULL)::boolean AS mcp_write_enabled FROM platform_admin WHERE id = @id;

-- name: SetAdminAccountMcpWrite :one
-- The caller's own MCP write opt-in (plan M14 §3.4 item 18): enabled sets the time once, disabled clears it.
UPDATE admin_account
SET mcp_write_enabled_at = CASE WHEN @enabled::boolean THEN coalesce(mcp_write_enabled_at, now()) END
WHERE id = @id RETURNING *;

-- name: SetPlatformAdminMcpWrite :one
-- The caller's own MCP write opt-in of a platform administrator (plan M14 §3.4 item 18).
UPDATE platform_admin
SET mcp_write_enabled_at = CASE WHEN @enabled::boolean THEN coalesce(mcp_write_enabled_at, now()) END
WHERE id = @id RETURNING *;

-- name: ListOrgAccounts :many
-- The organization's accounts that are not disabled, for the assignee picker of findings (plan M9 decision 34).
SELECT id, username, display_name, role FROM admin_account
WHERE disabled_at IS NULL
  AND (sqlc.narg(q_pattern)::text IS NULL
       OR username ILIKE sqlc.narg(q_pattern)::text ESCAPE '\'
       OR display_name ILIKE sqlc.narg(q_pattern)::text ESCAPE '\')
  AND (sqlc.narg(roles)::text[] IS NULL OR role = ANY(sqlc.narg(roles)::text[]))
ORDER BY
  CASE WHEN @sort::text = 'username' THEN username END ASC,
  CASE WHEN @sort::text = '-username' THEN username END DESC,
  CASE WHEN @sort::text = 'display_name' THEN display_name END ASC,
  CASE WHEN @sort::text = '-display_name' THEN display_name END DESC,
  CASE WHEN @sort::text = 'role' THEN role END ASC,
  CASE WHEN @sort::text = '-role' THEN role END DESC,
  id
LIMIT @max_rows OFFSET @skip_rows;

-- name: CountOrgAccounts :one
SELECT count(*) FROM (
  SELECT 1 FROM admin_account
  WHERE disabled_at IS NULL
    AND (sqlc.narg(q_pattern)::text IS NULL
         OR username ILIKE sqlc.narg(q_pattern)::text ESCAPE '\'
         OR display_name ILIKE sqlc.narg(q_pattern)::text ESCAPE '\')
    AND (sqlc.narg(roles)::text[] IS NULL OR role = ANY(sqlc.narg(roles)::text[]))
  LIMIT @count_limit
) matching;

-- name: GetAssignableAccount :one
-- An account a finding can be assigned to: of the organization, not disabled, administrator or operator (plan M9
-- decision 33).
SELECT id, username, display_name FROM admin_account
WHERE id = @id AND disabled_at IS NULL AND role IN ('org_admin', 'org_operator');
