-- Software requests (plan M13c decisions 8 to 10): a user's request for an available entry that requires approval,
-- opened by the worker from the device's software.request, decided by an administrator, expired by the worker.

-- name: GetSoftwareCatalogEntryApproval :one
-- The approval of an entry of the organization (worker: the event path checks the entry a device names).
SELECT approval FROM software_catalog_entry WHERE id = @id;

-- name: GetUserIDByUsername :one
SELECT id FROM app_user WHERE username = @username;

-- name: LastSoftwareRequestDenial :one
-- When the user's latest request for the entry on the device was denied; no row without a denial.
SELECT decided_at::timestamptz FROM software_request
WHERE device_id = @device_id AND catalog_entry_id = @catalog_entry_id AND username = @username AND state = 'denied'
  AND decided_at IS NOT NULL
ORDER BY decided_at DESC LIMIT 1;

-- name: InsertSoftwareRequest :execrows
-- Opens a request; none while one of the device, entry and user is open (software_request_open_idx).
INSERT INTO software_request (id, organization_id, catalog_entry_id, device_id, user_id, username, state, requested_at,
  expires_at)
VALUES (@id, @organization_id, @catalog_entry_id, @device_id, sqlc.narg(user_id), @username, 'requested', @requested_at,
  @expires_at)
ON CONFLICT (device_id, catalog_entry_id, username) WHERE state = 'requested' DO NOTHING;

-- name: ListSoftwareRequestsToExpire :many
-- The requests to expire, oldest first: open or approved ones whose entry has no available assignment left (A10-17),
-- and open ones whose entry no longer requires approval (§3.8 L4) or whose validity ended at now.
SELECT id, catalog_entry_id, device_id, username, cause::text AS cause FROM (
  SELECT r.id, r.catalog_entry_id, r.device_id, r.username, r.requested_at,
    CASE WHEN NOT EXISTS (SELECT 1 FROM software_assignment a WHERE a.catalog_entry_id = r.catalog_entry_id
                            AND a.intent = 'available') THEN 'assignment_removed'
         WHEN r.state = 'approved' THEN NULL
         WHEN e.approval = 'none' THEN 'approval_removed'
         WHEN r.expires_at <= @now THEN 'validity_ended' END AS cause
  FROM software_request r JOIN software_catalog_entry e ON e.id = r.catalog_entry_id
  WHERE r.state IN ('requested', 'approved')
) due
WHERE cause IS NOT NULL
ORDER BY requested_at, id
LIMIT @max_rows;

-- name: ExpireSoftwareRequest :execrows
UPDATE software_request SET state = 'expired', decided_at = @decided_at
WHERE id = @id AND (state = 'requested' OR state = 'approved' AND @approved_too::boolean);

-- name: GetSoftwareRequest :one
SELECT r.id, r.organization_id, r.catalog_entry_id, e.name AS entry_name, e.approval AS entry_approval, r.device_id,
  d.hostname, r.user_id, r.username, r.state, r.requested_at, r.expires_at, r.decided_by, r.decided_at,
  r.decision_reason
FROM software_request r JOIN software_catalog_entry e ON e.id = r.catalog_entry_id JOIN device d ON d.id = r.device_id
WHERE r.id = @id;

-- name: GetSoftwareRequestForUpdate :one
-- The request locked for the rest of the transaction: a decision must not interleave with another or with the expiry.
SELECT id, state, catalog_entry_id, device_id, username FROM software_request WHERE id = @id FOR UPDATE;

-- name: DecideSoftwareRequest :execrows
UPDATE software_request SET state = @state, decided_by = @decided_by, decided_at = @decided_at,
  decision_reason = sqlc.narg(decision_reason)
WHERE id = @id AND state = 'requested';

-- name: ListSoftwareRequests :many
-- The rows are read through a subquery, so the sort columns are unambiguous (device has a state too).
SELECT id, organization_id, catalog_entry_id, entry_name, entry_approval, device_id, hostname, user_id, username, state,
  requested_at, expires_at, decided_by, decided_at, decision_reason
FROM (
  SELECT r.id, r.organization_id, r.catalog_entry_id, e.name AS entry_name, e.approval AS entry_approval, r.device_id,
    d.hostname, r.user_id, r.username, r.state, r.requested_at, r.expires_at, r.decided_by, r.decided_at,
    r.decision_reason
  FROM software_request r JOIN software_catalog_entry e ON e.id = r.catalog_entry_id JOIN device d ON d.id = r.device_id
  WHERE (sqlc.narg(q_pattern)::text IS NULL OR r.username ILIKE sqlc.narg(q_pattern)::text ESCAPE '\')
    AND (sqlc.narg(states)::text[] IS NULL OR r.state = ANY(sqlc.narg(states)::text[]))
    AND (sqlc.narg(catalog_entry_id)::uuid IS NULL OR r.catalog_entry_id = sqlc.narg(catalog_entry_id)::uuid)
    AND (sqlc.narg(device_id)::uuid IS NULL OR r.device_id = sqlc.narg(device_id)::uuid)
) req
ORDER BY
  CASE WHEN @sort::text = 'requested_at' THEN requested_at END ASC,
  CASE WHEN @sort::text = '-requested_at' THEN requested_at END DESC,
  CASE WHEN @sort::text = 'username' THEN username END ASC,
  CASE WHEN @sort::text = '-username' THEN username END DESC,
  CASE WHEN @sort::text = 'state' THEN state END ASC,
  CASE WHEN @sort::text = '-state' THEN state END DESC,
  CASE WHEN @sort::text = 'expires_at' THEN expires_at END ASC,
  CASE WHEN @sort::text = '-expires_at' THEN expires_at END DESC,
  id
LIMIT @max_rows OFFSET @skip_rows;

-- name: CountSoftwareRequests :one
SELECT count(*) FROM (
  SELECT 1 FROM software_request r
  WHERE (sqlc.narg(q_pattern)::text IS NULL OR r.username ILIKE sqlc.narg(q_pattern)::text ESCAPE '\')
    AND (sqlc.narg(states)::text[] IS NULL OR r.state = ANY(sqlc.narg(states)::text[]))
    AND (sqlc.narg(catalog_entry_id)::uuid IS NULL OR r.catalog_entry_id = sqlc.narg(catalog_entry_id)::uuid)
    AND (sqlc.narg(device_id)::uuid IS NULL OR r.device_id = sqlc.narg(device_id)::uuid)
  LIMIT @count_limit
) matching;

-- name: ListApprovedSoftwareRequests :many
-- The approved users per device and entry (compiler, plan M13c decision 9), sorted by user name.
SELECT device_id, catalog_entry_id, username FROM software_request WHERE state = 'approved'
ORDER BY device_id, catalog_entry_id, username;
