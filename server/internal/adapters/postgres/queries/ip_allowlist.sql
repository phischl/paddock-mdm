-- IP allow list of the administrative surfaces (plan M7a decision 10). Platform scope (paddock_platform).

-- List queries (ADR 0018): see device_group.sql.

-- name: ListIPAllowlistEntries :many
SELECT * FROM ip_allowlist_entry
WHERE (sqlc.narg(q_pattern)::text IS NULL
       OR label ILIKE sqlc.narg(q_pattern)::text ESCAPE '\'
       OR cidr::text ILIKE sqlc.narg(q_pattern)::text ESCAPE '\')
ORDER BY
  CASE WHEN @sort::text = 'cidr' THEN cidr END ASC,
  CASE WHEN @sort::text = '-cidr' THEN cidr END DESC,
  CASE WHEN @sort::text = 'label' THEN label END ASC,
  CASE WHEN @sort::text = '-label' THEN label END DESC,
  CASE WHEN @sort::text = 'created_at' THEN created_at END ASC,
  CASE WHEN @sort::text = '-created_at' THEN created_at END DESC,
  id
LIMIT @max_rows OFFSET @skip_rows;

-- name: CountIPAllowlistEntries :one
SELECT count(*) FROM (
  SELECT 1 FROM ip_allowlist_entry
  WHERE (sqlc.narg(q_pattern)::text IS NULL
         OR label ILIKE sqlc.narg(q_pattern)::text ESCAPE '\'
         OR cidr::text ILIKE sqlc.narg(q_pattern)::text ESCAPE '\')
  LIMIT @count_limit
) matching;

-- name: GetIPAllowlistEntry :one
SELECT * FROM ip_allowlist_entry WHERE id = @id;

-- Every entry, for the enforcer's cache and the consequence check (plan M7a decisions 12 and 18).
-- name: AllIPAllowlistEntries :many
SELECT * FROM ip_allowlist_entry ORDER BY cidr;

-- The consequence check of a write must see a consistent set under concurrent writers (plan M7a decision 12).
-- name: LockIPAllowlistEntries :exec
LOCK TABLE ip_allowlist_entry IN SHARE ROW EXCLUSIVE MODE;

-- name: InsertIPAllowlistEntry :one
INSERT INTO ip_allowlist_entry (id, cidr, label, created_by) VALUES (@id, @cidr, @label, @created_by)
RETURNING *;

-- name: UpdateIPAllowlistEntry :one
UPDATE ip_allowlist_entry SET cidr = @cidr, label = @label, updated_at = now() WHERE id = @id
RETURNING *;

-- name: DeleteIPAllowlistEntry :execrows
DELETE FROM ip_allowlist_entry WHERE id = @id;

-- Break-glass (plan M7a decision 21): switches the feature off and reports what was removed.
-- name: DeleteAllIPAllowlistEntries :many
DELETE FROM ip_allowlist_entry RETURNING cidr;
