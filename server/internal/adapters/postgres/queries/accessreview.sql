-- Access review report (plan M12 decisions 25 and 26, PDK-754). Every list takes the cap plus one row at most; the
-- counts are exact because the report states totals.

-- name: ListAccessReviewAccounts :many
SELECT username, display_name, role, last_login_at, (disabled_at IS NOT NULL)::boolean AS disabled
FROM admin_account ORDER BY username, id LIMIT @max_rows;

-- name: CountAccessReviewAccounts :one
SELECT count(*) FROM admin_account;

-- name: ListAccessReviewTokens :many
-- Every token that existed at some time in [from, to): created before the end, neither revoked nor expired before
-- the start.
SELECT t.name, t.role, t.prefix, c.display_name AS created_by, t.created_at, t.expires_at, t.last_used_at,
       t.revoked_at, r.display_name AS revoked_by
FROM api_token t
JOIN admin_account c ON c.id = t.created_by
LEFT JOIN admin_account r ON r.id = t.revoked_by
WHERE t.created_at < @to_time AND LEAST(coalesce(t.revoked_at, t.expires_at), t.expires_at) >= @from_time::timestamptz
ORDER BY t.created_at, t.id
LIMIT @max_rows;

-- name: CountAccessReviewTokens :one
SELECT count(*) FROM api_token t
WHERE t.created_at < @to_time AND LEAST(coalesce(t.revoked_at, t.expires_at), t.expires_at) >= @from_time::timestamptz;

-- name: ListAccessReviewPlatformAdmins :many
SELECT username, display_name, last_login_at FROM platform_admin ORDER BY username, id LIMIT @max_rows;

-- name: CountAccessReviewPlatformAdmins :one
SELECT count(*) FROM platform_admin;

-- name: ListAccessReviewOrganizations :many
SELECT slug, name, created_at FROM organization
WHERE created_at >= @from_time AND created_at < @to_time
ORDER BY created_at, id LIMIT @max_rows;

-- name: CountAccessReviewOrganizations :one
SELECT count(*) FROM organization WHERE created_at >= @from_time AND created_at < @to_time;
