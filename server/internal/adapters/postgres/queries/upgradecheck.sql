-- The upgrade check (plan M16 decision 4). Every query reads tables that exist in the previous release too, and names
-- its columns, so a newer binary can check an older database before it is migrated (a SELECT * would carry the newer
-- schema's column list); the read access to goose_db_version (migration 00102) and the M15 tables are probed.

-- name: UpgradeCheckSchemaVersionReadable :one
SELECT coalesce(has_table_privilege(to_regclass('goose_db_version'), 'SELECT'), false)::boolean AS readable;

-- name: UpgradeCheckSchemaVersion :one
SELECT coalesce(max(version_id), 0)::bigint AS version FROM goose_db_version WHERE is_applied;

-- name: UpgradeCheckRelationExists :one
SELECT (to_regclass(@relation::text) IS NOT NULL)::boolean AS present;

-- name: UpgradeCheckOrganizationIDs :many
SELECT id FROM organization ORDER BY id;

-- The organization's active devices by reported agent version (NULL: never checked in).
-- name: UpgradeCheckAgentVersions :many
SELECT s.agent_version, count(*)::bigint AS devices
FROM device d LEFT JOIN device_status s ON s.device_id = d.id
WHERE d.state = 'active'
GROUP BY s.agent_version;

-- name: UpgradeCheckDevicesWithAgentVersions :many
SELECT d.id, d.hostname, s.agent_version::text AS agent_version
FROM device d JOIN device_status s ON s.device_id = d.id
WHERE d.state = 'active' AND s.agent_version = ANY(@versions::text[])
ORDER BY d.hostname, d.id
LIMIT @max_rows;

-- name: UpgradeCheckHaltedConfigRollouts :one
SELECT count(*)::bigint AS n FROM config_rollout WHERE status = 'halted';

-- name: UpgradeCheckRunningAgentRollouts :many
SELECT version FROM agent_rollout WHERE status = 'running' ORDER BY version;

-- name: UpgradeCheckAutoUnsealState :one
SELECT state FROM openbao_auto_unseal WHERE id = 1;

-- name: UpgradeCheckPlatformAdminIDs :many
SELECT id FROM platform_admin ORDER BY id;
