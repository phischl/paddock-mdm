-- name: LockDeviceBundleSeq :one
-- The compiler replaces a device's warnings only while the device still has the bundle its compile saw (PDK-918). The
-- lock conflicts with SetDeviceBundleSeq, so no other compile publishes a bundle for the device in between.
SELECT bundle_seq FROM device WHERE id = @id FOR NO KEY UPDATE;

-- name: DeleteCompileWarnings :exec
-- The compiler replaces the warnings of the devices it compiled (PDK-918).
DELETE FROM compile_warning WHERE device_id = @device_id;

-- name: InsertCompileWarning :exec
INSERT INTO compile_warning (organization_id, device_id, assignment_id, catalog_entry_id, code, params)
VALUES (@organization_id, @device_id, sqlc.narg(assignment_id), sqlc.narg(catalog_entry_id), @code, @params);

-- name: ListCompileWarnings :many
SELECT w.id, w.device_id, d.hostname, w.assignment_id, w.catalog_entry_id, w.code, w.params, w.created_at
FROM compile_warning w JOIN device d ON d.id = w.device_id
WHERE (sqlc.narg(q_pattern)::text IS NULL
       OR d.hostname ILIKE sqlc.narg(q_pattern)::text ESCAPE '\'
       OR w.code ILIKE sqlc.narg(q_pattern)::text ESCAPE '\')
  AND (sqlc.narg(device_id)::uuid IS NULL OR w.device_id = sqlc.narg(device_id)::uuid)
  AND (sqlc.narg(assignment_id)::uuid IS NULL OR w.assignment_id = sqlc.narg(assignment_id)::uuid)
  AND (sqlc.narg(catalog_entry_id)::uuid IS NULL OR w.catalog_entry_id = sqlc.narg(catalog_entry_id)::uuid)
  AND (sqlc.narg(code)::text IS NULL OR w.code = sqlc.narg(code)::text)
ORDER BY
  CASE WHEN @sort::text = 'created_at' THEN w.created_at END ASC,
  CASE WHEN @sort::text = '-created_at' THEN w.created_at END DESC,
  CASE WHEN @sort::text = 'hostname' THEN d.hostname END ASC,
  CASE WHEN @sort::text = '-hostname' THEN d.hostname END DESC,
  CASE WHEN @sort::text = 'code' THEN w.code END ASC,
  CASE WHEN @sort::text = '-code' THEN w.code END DESC,
  w.id
LIMIT @max_rows OFFSET @skip_rows;

-- name: CountCompileWarnings :one
SELECT count(*) FROM (
  SELECT 1 FROM compile_warning w JOIN device d ON d.id = w.device_id
  WHERE (sqlc.narg(q_pattern)::text IS NULL
         OR d.hostname ILIKE sqlc.narg(q_pattern)::text ESCAPE '\'
         OR w.code ILIKE sqlc.narg(q_pattern)::text ESCAPE '\')
    AND (sqlc.narg(device_id)::uuid IS NULL OR w.device_id = sqlc.narg(device_id)::uuid)
    AND (sqlc.narg(assignment_id)::uuid IS NULL OR w.assignment_id = sqlc.narg(assignment_id)::uuid)
    AND (sqlc.narg(catalog_entry_id)::uuid IS NULL OR w.catalog_entry_id = sqlc.narg(catalog_entry_id)::uuid)
    AND (sqlc.narg(code)::text IS NULL OR w.code = sqlc.narg(code)::text)
  LIMIT @count_limit
) matching;
