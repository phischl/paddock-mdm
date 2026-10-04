-- Users and user groups of an organization (plan M3a decisions 2–4).

-- name: InsertAppUser :one
INSERT INTO app_user (id, organization_id, authentik_pk, username, display_name, email, source)
VALUES (@id, @organization_id, @authentik_pk, @username, @display_name, @email, @source)
RETURNING *;

-- name: GetAppUser :one
SELECT * FROM app_user WHERE id = @id;

-- name: LockAppUser :one
SELECT * FROM app_user WHERE id = @id FOR UPDATE;

-- List queries (ADR 0018): see device_group.sql. group_id limits the list to the members of one group.

-- name: ListAppUsers :many
SELECT * FROM app_user
WHERE (sqlc.narg(q_pattern)::text IS NULL
       OR username ILIKE sqlc.narg(q_pattern)::text ESCAPE '\'
       OR display_name ILIKE sqlc.narg(q_pattern)::text ESCAPE '\'
       OR email ILIKE sqlc.narg(q_pattern)::text ESCAPE '\')
  AND (sqlc.narg(sources)::text[] IS NULL OR source = ANY(sqlc.narg(sources)::text[]))
  AND (sqlc.narg(locked)::boolean IS NULL OR locked = sqlc.narg(locked)::boolean)
  AND (sqlc.narg(group_id)::uuid IS NULL OR EXISTS (
        SELECT 1 FROM user_group_member m WHERE m.user_id = app_user.id AND m.group_id = sqlc.narg(group_id)::uuid))
ORDER BY
  CASE WHEN @sort::text = 'username' THEN username END ASC,
  CASE WHEN @sort::text = '-username' THEN username END DESC,
  CASE WHEN @sort::text = 'display_name' THEN display_name END ASC,
  CASE WHEN @sort::text = '-display_name' THEN display_name END DESC,
  CASE WHEN @sort::text = 'created_at' THEN created_at END ASC,
  CASE WHEN @sort::text = '-created_at' THEN created_at END DESC,
  id
LIMIT @max_rows OFFSET @skip_rows;

-- name: CountAppUsers :one
SELECT count(*) FROM (
  SELECT 1 FROM app_user
  WHERE (sqlc.narg(q_pattern)::text IS NULL
         OR username ILIKE sqlc.narg(q_pattern)::text ESCAPE '\'
         OR display_name ILIKE sqlc.narg(q_pattern)::text ESCAPE '\'
         OR email ILIKE sqlc.narg(q_pattern)::text ESCAPE '\')
    AND (sqlc.narg(sources)::text[] IS NULL OR source = ANY(sqlc.narg(sources)::text[]))
    AND (sqlc.narg(locked)::boolean IS NULL OR locked = sqlc.narg(locked)::boolean)
    AND (sqlc.narg(group_id)::uuid IS NULL OR EXISTS (
          SELECT 1 FROM user_group_member m WHERE m.user_id = app_user.id AND m.group_id = sqlc.narg(group_id)::uuid))
  LIMIT @count_limit
) matching;

-- name: ListAllAppUsers :many
SELECT * FROM app_user ORDER BY id;

-- name: SetAppUserAuthentikPK :exec
UPDATE app_user SET authentik_pk = @authentik_pk, updated_at = now() WHERE id = @id;

-- name: UpdateAppUser :one
UPDATE app_user SET display_name = @display_name, email = @email, updated_at = now()
WHERE id = @id
RETURNING *;

-- Worker synchronization of a synced user's upstream attributes.
-- name: UpdateSyncedAppUser :exec
UPDATE app_user SET username = @username, display_name = @display_name, email = @email, updated_at = now()
WHERE id = @id AND source = 'synced';

-- name: SetAppUserLocked :one
UPDATE app_user SET locked = @locked, locked_at = CASE WHEN @locked::boolean THEN coalesce(locked_at, now()) END,
  updated_at = now()
WHERE id = @id
RETURNING *;

-- name: DeleteAppUser :execrows
DELETE FROM app_user WHERE id = @id;

-- name: InsertUserGroup :one
INSERT INTO user_group (id, organization_id, slug, name, source, upstream_authentik_pk)
VALUES (@id, @organization_id, @slug, @name, @source, sqlc.narg(upstream_authentik_pk))
RETURNING *;

-- name: GetUserGroup :one
SELECT * FROM user_group WHERE id = @id;

-- name: ListUserGroups :many
SELECT * FROM user_group
WHERE (sqlc.narg(q_pattern)::text IS NULL
       OR slug ILIKE sqlc.narg(q_pattern)::text ESCAPE '\'
       OR name ILIKE sqlc.narg(q_pattern)::text ESCAPE '\')
  AND (sqlc.narg(sources)::text[] IS NULL OR source = ANY(sqlc.narg(sources)::text[]))
ORDER BY
  CASE WHEN @sort::text = 'name' THEN name END ASC,
  CASE WHEN @sort::text = '-name' THEN name END DESC,
  CASE WHEN @sort::text = 'slug' THEN slug END ASC,
  CASE WHEN @sort::text = '-slug' THEN slug END DESC,
  CASE WHEN @sort::text = 'created_at' THEN created_at END ASC,
  CASE WHEN @sort::text = '-created_at' THEN created_at END DESC,
  id
LIMIT @max_rows OFFSET @skip_rows;

-- name: CountUserGroups :one
SELECT count(*) FROM (
  SELECT 1 FROM user_group
  WHERE (sqlc.narg(q_pattern)::text IS NULL
         OR slug ILIKE sqlc.narg(q_pattern)::text ESCAPE '\'
         OR name ILIKE sqlc.narg(q_pattern)::text ESCAPE '\')
    AND (sqlc.narg(sources)::text[] IS NULL OR source = ANY(sqlc.narg(sources)::text[]))
  LIMIT @count_limit
) matching;

-- name: ListAllUserGroups :many
SELECT * FROM user_group ORDER BY id;

-- name: SetUserGroupAuthentikPK :exec
UPDATE user_group SET authentik_pk = @authentik_pk, updated_at = now() WHERE id = @id;

-- name: UpdateUserGroupName :one
UPDATE user_group SET name = @name, updated_at = now() WHERE id = @id RETURNING *;

-- name: DeleteUserGroup :execrows
DELETE FROM user_group WHERE id = @id;

-- name: InsertUserGroupMember :execrows
INSERT INTO user_group_member (organization_id, group_id, user_id)
VALUES (@organization_id, @group_id, @user_id)
ON CONFLICT DO NOTHING;

-- name: DeleteUserGroupMember :execrows
DELETE FROM user_group_member WHERE group_id = @group_id AND user_id = @user_id;

-- name: ListAllUserGroupMembers :many
SELECT group_id, user_id FROM user_group_member ORDER BY group_id, user_id;

-- name: ListUserGroupMemberIDs :many
SELECT user_id FROM user_group_member WHERE group_id = @group_id ORDER BY user_id;

-- name: ListGroupsOfUser :many
SELECT g.* FROM user_group g JOIN user_group_member m ON m.group_id = g.id
WHERE m.user_id = @user_id
ORDER BY g.name, g.id;
