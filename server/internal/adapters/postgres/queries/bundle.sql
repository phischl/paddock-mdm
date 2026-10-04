-- Compiler (plan M2a decision 13).

-- name: ListActiveDeviceIDs :many
SELECT id FROM device WHERE state = 'active' ORDER BY id;

-- name: ListActiveGroupMemberIDs :many
SELECT d.id FROM device d JOIN device_group_member m ON m.device_id = d.id
WHERE m.device_group_id = @device_group_id AND d.state = 'active'
ORDER BY d.id;

-- name: ListCompileTargets :many
SELECT d.id, d.state, d.bundle_seq, d.logins_suspended, coalesce(s.schema_versions, '{}')::int[] AS schema_versions
FROM device d LEFT JOIN device_status s ON s.device_id = d.id
WHERE d.id = ANY(@ids::uuid[]) ORDER BY d.id;

-- Active devices whose latest bundle has another schema than their agent's newest supported one (v2 when the agent
-- reports 2, else v1); devices without a bundle are compiled at enrollment.
-- name: ListDevicesWithOutdatedSchema :many
SELECT d.id FROM device d
LEFT JOIN device_status s ON s.device_id = d.id
JOIN LATERAL (SELECT b.schema_version FROM bundle b WHERE b.device_id = d.id ORDER BY b.version DESC LIMIT 1) lb ON true
WHERE d.state = 'active'
  AND lb.schema_version <> CASE WHEN 2 = ANY(coalesce(s.schema_versions, '{}')) THEN 2 ELSE 1 END
ORDER BY d.id;

-- Optimistic: a concurrent compile of the same device makes this update no row.
-- name: SetDeviceBundleSeq :execrows
UPDATE device SET bundle_seq = @new_seq WHERE id = @id AND bundle_seq = @old_seq;

-- name: InsertBundle :exec
INSERT INTO bundle (device_id, version, organization_id, content_sha256, envelope_sha256, object_key, schema_version)
VALUES (@device_id, @version, @organization_id, @content_sha256, @envelope_sha256, @object_key, @schema_version);

-- name: ListLatestBundles :many
SELECT DISTINCT ON (device_id) * FROM bundle ORDER BY device_id, version DESC;
