-- Compiler (plan M2a decision 13).

-- name: ListActiveDeviceIDs :many
SELECT id FROM device WHERE state = 'active' ORDER BY id;

-- name: ListActiveGroupMemberIDs :many
SELECT d.id FROM device d JOIN device_group_member m ON m.device_id = d.id
WHERE m.device_group_id = @device_group_id AND d.state = 'active'
ORDER BY d.id;

-- name: ListCompileTargets :many
SELECT id, state, bundle_seq FROM device WHERE id = ANY(@ids::uuid[]) ORDER BY id;

-- Optimistic: a concurrent compile of the same device makes this update no row.
-- name: SetDeviceBundleSeq :execrows
UPDATE device SET bundle_seq = @new_seq WHERE id = @id AND bundle_seq = @old_seq;

-- name: InsertBundle :exec
INSERT INTO bundle (device_id, version, organization_id, content_sha256, envelope_sha256, object_key)
VALUES (@device_id, @version, @organization_id, @content_sha256, @envelope_sha256, @object_key);

-- name: ListLatestBundles :many
SELECT DISTINCT ON (device_id) * FROM bundle ORDER BY device_id, version DESC;
