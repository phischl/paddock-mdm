-- Permission profiles and their assignments (plan M3a decisions 12–14).

-- name: InsertPermissionProfile :one
INSERT INTO permission_profile (id, organization_id, name, class, commands, require_password, timestamp_timeout_min, lecture,
  root_grant_confirmed_at, root_grant_confirmed_by)
VALUES (@id, @organization_id, @name, @class, @commands, @require_password, @timestamp_timeout_min, @lecture,
  sqlc.narg(root_grant_confirmed_at), sqlc.narg(root_grant_confirmed_by))
RETURNING *;

-- name: GetPermissionProfile :one
SELECT * FROM permission_profile WHERE id = @id;

-- Gated changes decide on the row they write, so a concurrent demotion is never overwritten by a stale read (plan M8s
-- decision 7j): FOR UPDATE for a change of the profile, FOR SHARE for a change that only depends on it.

-- name: GetPermissionProfileForUpdate :one
SELECT * FROM permission_profile WHERE id = @id FOR UPDATE;

-- name: GetPermissionProfileForShare :one
SELECT * FROM permission_profile WHERE id = @id FOR SHARE;

-- List queries (ADR 0018): see device_group.sql.

-- name: ListPermissionProfiles :many
SELECT * FROM permission_profile
WHERE (sqlc.narg(q_pattern)::text IS NULL OR name ILIKE sqlc.narg(q_pattern)::text ESCAPE '\')
  AND (sqlc.narg(classes)::text[] IS NULL OR class = ANY(sqlc.narg(classes)::text[]))
ORDER BY
  CASE WHEN @sort::text = 'name' THEN name END ASC,
  CASE WHEN @sort::text = '-name' THEN name END DESC,
  CASE WHEN @sort::text = 'class' THEN class END ASC,
  CASE WHEN @sort::text = '-class' THEN class END DESC,
  CASE WHEN @sort::text = 'created_at' THEN created_at END ASC,
  CASE WHEN @sort::text = '-created_at' THEN created_at END DESC,
  CASE WHEN @sort::text = 'updated_at' THEN updated_at END ASC,
  CASE WHEN @sort::text = '-updated_at' THEN updated_at END DESC,
  id
LIMIT @max_rows OFFSET @skip_rows;

-- name: CountPermissionProfiles :one
SELECT count(*) FROM (
  SELECT 1 FROM permission_profile
  WHERE (sqlc.narg(q_pattern)::text IS NULL OR name ILIKE sqlc.narg(q_pattern)::text ESCAPE '\')
    AND (sqlc.narg(classes)::text[] IS NULL OR class = ANY(sqlc.narg(classes)::text[]))
  LIMIT @count_limit
) matching;

-- name: ListAllPermissionProfiles :many
SELECT * FROM permission_profile ORDER BY id;

-- name: UpdatePermissionProfile :one
UPDATE permission_profile
SET name = @name, class = @class, commands = @commands, require_password = @require_password,
    timestamp_timeout_min = @timestamp_timeout_min, lecture = @lecture, updated_at = now(),
    root_grant_confirmed_at = CASE WHEN @set_root_grant::bool THEN sqlc.narg(root_grant_confirmed_at) ELSE root_grant_confirmed_at END,
    root_grant_confirmed_by = CASE WHEN @set_root_grant::bool THEN sqlc.narg(root_grant_confirmed_by) ELSE root_grant_confirmed_by END
WHERE id = @id
RETURNING *;

-- name: ConfirmPermissionProfileRootGrant :one
UPDATE permission_profile SET root_grant_confirmed_at = now(), root_grant_confirmed_by = sqlc.narg(confirmed_by)
WHERE id = @id
RETURNING *;

-- name: CountProfileAssignmentsByProfile :many
SELECT profile_id, count(*) AS assignments FROM profile_assignment GROUP BY profile_id;

-- name: DeletePermissionProfile :execrows
DELETE FROM permission_profile WHERE id = @id;

-- name: InsertProfileAssignment :one
INSERT INTO profile_assignment (id, organization_id, profile_id, subject_type, subject_id, device_group_id)
VALUES (@id, @organization_id, @profile_id, @subject_type, sqlc.narg(subject_id), sqlc.narg(device_group_id))
RETURNING *;

-- name: GetProfileAssignment :one
SELECT * FROM profile_assignment WHERE id = @id;

-- name: GetProfileAssignmentForUpdate :one
SELECT * FROM profile_assignment WHERE id = @id FOR UPDATE;

-- The search matches the profile's name.
-- name: ListProfileAssignments :many
SELECT * FROM profile_assignment
WHERE (sqlc.narg(q_pattern)::text IS NULL OR EXISTS (
        SELECT 1 FROM permission_profile p
        WHERE p.id = profile_assignment.profile_id AND p.name ILIKE sqlc.narg(q_pattern)::text ESCAPE '\'))
  AND (sqlc.narg(profile_id)::uuid IS NULL OR profile_id = sqlc.narg(profile_id)::uuid)
  AND (sqlc.narg(subject_types)::text[] IS NULL OR subject_type = ANY(sqlc.narg(subject_types)::text[]))
  AND (sqlc.narg(subject_id)::uuid IS NULL OR subject_id = sqlc.narg(subject_id)::uuid)
  AND (sqlc.narg(device_group_id)::uuid IS NULL OR device_group_id = sqlc.narg(device_group_id)::uuid)
ORDER BY
  CASE WHEN @sort::text = 'created_at' THEN created_at END ASC,
  CASE WHEN @sort::text = '-created_at' THEN created_at END DESC,
  CASE WHEN @sort::text = 'subject_type' THEN subject_type END ASC,
  CASE WHEN @sort::text = '-subject_type' THEN subject_type END DESC,
  id
LIMIT @max_rows OFFSET @skip_rows;

-- name: CountProfileAssignments :one
SELECT count(*) FROM (
  SELECT 1 FROM profile_assignment
  WHERE (sqlc.narg(q_pattern)::text IS NULL OR EXISTS (
          SELECT 1 FROM permission_profile p
          WHERE p.id = profile_assignment.profile_id AND p.name ILIKE sqlc.narg(q_pattern)::text ESCAPE '\'))
    AND (sqlc.narg(profile_id)::uuid IS NULL OR profile_id = sqlc.narg(profile_id)::uuid)
    AND (sqlc.narg(subject_types)::text[] IS NULL OR subject_type = ANY(sqlc.narg(subject_types)::text[]))
    AND (sqlc.narg(subject_id)::uuid IS NULL OR subject_id = sqlc.narg(subject_id)::uuid)
    AND (sqlc.narg(device_group_id)::uuid IS NULL OR device_group_id = sqlc.narg(device_group_id)::uuid)
  LIMIT @count_limit
) matching;

-- name: ListAllProfileAssignments :many
SELECT * FROM profile_assignment ORDER BY id;

-- name: UpdateProfileAssignmentScope :one
UPDATE profile_assignment SET device_group_id = sqlc.narg(device_group_id) WHERE id = @id RETURNING *;

-- name: DeleteProfileAssignment :execrows
DELETE FROM profile_assignment WHERE id = @id;

-- A deleted user or group takes its assignments (the subject has no foreign key, plan M3a decision 12).
-- name: DeleteProfileAssignmentsOfSubject :execrows
DELETE FROM profile_assignment WHERE subject_id = @subject_id;

-- name: CountProfileAssignmentsOfProfile :one
SELECT count(*) FROM profile_assignment WHERE profile_id = @profile_id;
