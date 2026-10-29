-- name: GetOrgMcpSettings :one
-- The MCP policy of the organization in paddock.org_id (plan M14 §3.4 item 17); no row means the MCP is off.
SELECT * FROM organization_mcp_settings;

-- name: UpsertOrgMcpSettings :one
INSERT INTO organization_mcp_settings (organization_id, enabled, write_enabled, mode, allowed_operations, updated_at, updated_by)
VALUES (@organization_id, @enabled, @write_enabled, @mode, @allowed_operations, now(), sqlc.narg(updated_by))
ON CONFLICT (organization_id) DO UPDATE
SET enabled = excluded.enabled, write_enabled = excluded.write_enabled, mode = excluded.mode,
    allowed_operations = excluded.allowed_operations, updated_at = excluded.updated_at, updated_by = excluded.updated_by
RETURNING *;

-- name: GetPlatformMcpSettings :one
-- The MCP policy of the platform (plan M14 §3.4 item 17); no row means the MCP is off.
SELECT * FROM platform_mcp_settings WHERE singleton;

-- name: UpsertPlatformMcpSettings :one
INSERT INTO platform_mcp_settings (singleton, enabled, write_enabled, mode, allowed_operations, updated_at, updated_by)
VALUES (true, @enabled, @write_enabled, @mode, @allowed_operations, now(), sqlc.narg(updated_by))
ON CONFLICT (singleton) DO UPDATE
SET enabled = excluded.enabled, write_enabled = excluded.write_enabled, mode = excluded.mode,
    allowed_operations = excluded.allowed_operations, updated_at = excluded.updated_at, updated_by = excluded.updated_by
RETURNING *;
