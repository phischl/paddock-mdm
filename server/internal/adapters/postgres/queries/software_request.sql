-- Software requests (plan M13c decisions 8 to 10): a user's request for an available entry that requires approval,
-- opened by the worker from the device's software.request, decided by an administrator, expired by the worker.

-- name: GetSoftwareCatalogEntryApproval :one
-- The approval and its epoch of an entry of the organization (worker: the event path checks the entry a device names).
SELECT approval, approval_epoch FROM software_catalog_entry WHERE id = @id;

-- name: SoftwareRequestOffered :one
-- Whether an available assignment of the entry offers it to the user on the device (architect decision A10-17), as the
-- compiler resolves targets: the whole organization or a device group of the device offers it to every user, a user or
-- user-group target to the device's owners it names. ListSoftwareRequestsToExpire repeats the predicate.
SELECT EXISTS (
  SELECT 1 FROM software_assignment a
  WHERE a.catalog_entry_id = @catalog_entry_id AND a.intent = 'available'
    AND ((a.device_group_id IS NULL AND a.user_id IS NULL AND a.user_group_id IS NULL)
      OR a.device_group_id IN (SELECT m.device_group_id FROM device_group_member m WHERE m.device_id = @device_id)
      OR a.user_id IN (SELECT o.user_id FROM device_owner o JOIN app_user u ON u.id = o.user_id
                       WHERE o.device_id = @device_id AND u.username = @username)
      OR a.user_group_id IN (SELECT g.group_id FROM user_group_member g JOIN device_owner o ON o.user_id = g.user_id
                             JOIN app_user u ON u.id = o.user_id WHERE o.device_id = @device_id AND u.username = @username))
)::boolean AS offered;

-- name: SoftwareRequestApprovalHolds :one
-- Whether the user holds an approval of the entry on the device within the entry's current approval epoch.
SELECT EXISTS (
  SELECT 1 FROM software_request r JOIN software_catalog_entry e ON e.id = r.catalog_entry_id
  WHERE r.device_id = @device_id AND r.catalog_entry_id = @catalog_entry_id AND r.username = @username
    AND r.state = 'approved' AND r.approval_epoch = e.approval_epoch
)::boolean AS holds;

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
  expires_at, approval_epoch, justification)
VALUES (@id, @organization_id, @catalog_entry_id, @device_id, sqlc.narg(user_id), @username, 'requested', @requested_at,
  @expires_at, @approval_epoch, @justification)
ON CONFLICT (device_id, catalog_entry_id, username) WHERE state = 'requested' DO NOTHING;

-- name: ListSoftwareRequestsToExpire :many
-- The requests to expire, oldest first, with the cause: open or approved ones no available assignment of the entry
-- offers to the device and user any longer (A10-17; the predicate of SoftwareRequestOffered), open or approved ones
-- whose entry no longer requires approval or changed its approval since (§3.8 L4: an approval never outlives a change to
-- none), and open ones whose validity ended at now.
SELECT id, catalog_entry_id, device_id, username, cause::text AS cause FROM (
  SELECT r.id, r.catalog_entry_id, r.device_id, r.username, r.requested_at,
    CASE WHEN NOT EXISTS (
           SELECT 1 FROM software_assignment a
           WHERE a.catalog_entry_id = r.catalog_entry_id AND a.intent = 'available'
             AND ((a.device_group_id IS NULL AND a.user_id IS NULL AND a.user_group_id IS NULL)
               OR a.device_group_id IN (SELECT m.device_group_id FROM device_group_member m WHERE m.device_id = r.device_id)
               OR a.user_id IN (SELECT o.user_id FROM device_owner o JOIN app_user u ON u.id = o.user_id
                                WHERE o.device_id = r.device_id AND u.username = r.username)
               OR a.user_group_id IN (SELECT g.group_id FROM user_group_member g JOIN device_owner o ON o.user_id = g.user_id
                                      JOIN app_user u ON u.id = o.user_id
                                      WHERE o.device_id = r.device_id AND u.username = r.username))
         ) THEN 'assignment_removed'
         WHEN e.approval = 'none' OR r.approval_epoch <> e.approval_epoch THEN 'approval_removed'
         WHEN r.state = 'approved' THEN NULL
         WHEN r.expires_at <= @now THEN 'validity_ended' END AS cause
  FROM software_request r JOIN software_catalog_entry e ON e.id = r.catalog_entry_id
  WHERE r.state IN ('requested', 'approved')
) due
WHERE cause IS NOT NULL
ORDER BY requested_at, id
LIMIT @max_rows;

-- name: ExpireSoftwareRequest :execrows
-- Expires the request only while the cause the list named still holds, so a request covered again in between stays.
UPDATE software_request r SET state = 'expired', decided_at = @decided_at
FROM software_catalog_entry e
WHERE r.id = @id AND e.id = r.catalog_entry_id AND r.state IN ('requested', 'approved')
  AND (CASE WHEN NOT EXISTS (
           SELECT 1 FROM software_assignment a
           WHERE a.catalog_entry_id = r.catalog_entry_id AND a.intent = 'available'
             AND ((a.device_group_id IS NULL AND a.user_id IS NULL AND a.user_group_id IS NULL)
               OR a.device_group_id IN (SELECT m.device_group_id FROM device_group_member m WHERE m.device_id = r.device_id)
               OR a.user_id IN (SELECT o.user_id FROM device_owner o JOIN app_user u ON u.id = o.user_id
                                WHERE o.device_id = r.device_id AND u.username = r.username)
               OR a.user_group_id IN (SELECT g.group_id FROM user_group_member g JOIN device_owner o ON o.user_id = g.user_id
                                      JOIN app_user u ON u.id = o.user_id
                                      WHERE o.device_id = r.device_id AND u.username = r.username))
         ) THEN 'assignment_removed'
         WHEN e.approval = 'none' OR r.approval_epoch <> e.approval_epoch THEN 'approval_removed'
         WHEN r.state = 'approved' THEN NULL
         WHEN r.expires_at <= @now THEN 'validity_ended' END) = @cause::text;

-- name: GetSoftwareRequest :one
SELECT r.id, r.organization_id, r.catalog_entry_id, e.name AS entry_name, e.approval AS entry_approval, r.device_id,
  d.hostname, r.user_id, r.username, r.state, r.requested_at, r.expires_at, r.decided_by, r.decided_at,
  r.decision_reason, r.justification
FROM software_request r JOIN software_catalog_entry e ON e.id = r.catalog_entry_id JOIN device d ON d.id = r.device_id
WHERE r.id = @id;

-- name: GetSoftwareRequestForUpdate :one
-- The request locked for the rest of the transaction: a decision must not interleave with another or with the expiry.
-- current says whether it was opened under the entry's current approval epoch.
SELECT r.id, r.state, r.catalog_entry_id, r.device_id, r.username, r.expires_at,
  (r.approval_epoch = e.approval_epoch)::boolean AS current
FROM software_request r JOIN software_catalog_entry e ON e.id = r.catalog_entry_id
WHERE r.id = @id FOR UPDATE OF r;

-- name: DecideSoftwareRequest :execrows
UPDATE software_request SET state = @state, decided_by = @decided_by, decided_at = @decided_at,
  decision_reason = sqlc.narg(decision_reason)
WHERE id = @id AND state = 'requested';

-- name: WithdrawSoftwareRequest :execrows
-- Closes the open request of the device, entry and user a device reported withdrawn (PDK-811b); the partial unique
-- index allows one at most. A request opened after the report was received is a newer one and stays.
UPDATE software_request SET state = 'withdrawn', decided_at = @decided_at
WHERE device_id = @device_id AND catalog_entry_id = @catalog_entry_id AND username = @username AND state = 'requested'
  AND requested_at <= @decided_at;

-- name: ListSoftwareRequests :many
-- The rows are read through a subquery, so the sort columns are unambiguous (device has a state too).
SELECT id, organization_id, catalog_entry_id, entry_name, entry_approval, device_id, hostname, user_id, username, state,
  requested_at, expires_at, decided_by, decided_at, decision_reason, justification
FROM (
  SELECT r.id, r.organization_id, r.catalog_entry_id, e.name AS entry_name, e.approval AS entry_approval, r.device_id,
    d.hostname, r.user_id, r.username, r.state, r.requested_at, r.expires_at, r.decided_by, r.decided_at,
    r.decision_reason, r.justification
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
-- The approved users per device and entry (compiler, plan M13c decision 9), sorted by user name: only approvals of an
-- entry that requires approval, decided within its current approval epoch, so one never comes back after a change to
-- none, even before the worker expired it.
SELECT r.device_id, r.catalog_entry_id, r.username
FROM software_request r JOIN software_catalog_entry e ON e.id = r.catalog_entry_id
WHERE r.state = 'approved' AND e.approval = 'required' AND r.approval_epoch = e.approval_epoch
ORDER BY r.device_id, r.catalog_entry_id, r.username;

-- name: ListSoftwareRequestDenials :many
-- The denials the device's next bundle names (compiler, architect decision A10-27): per device, entry and user the
-- latest denial decided after lock_start, the start of the re-request lock (software.RerequestAfterDenial), the window
-- in which the worker opens no new request (LastSoftwareRequestDenial). Like that lock, it ignores the approval epoch.
SELECT DISTINCT ON (r.device_id, r.catalog_entry_id, r.username) r.device_id, r.catalog_entry_id, r.username,
  coalesce(r.decision_reason, '')::text AS reason
FROM software_request r
WHERE r.state = 'denied' AND r.decided_at > sqlc.arg(lock_start)::timestamptz
ORDER BY r.device_id, r.catalog_entry_id, r.username, r.decided_at DESC;

-- name: ListDevicesWithEndedDenialLock :many
-- The active devices with a denial whose re-request lock ended at or before now and after the render time of the
-- device's last compile (denial_lock_checked_at): that compile may have rendered the denial into the bundle, and the
-- device refuses a new request while the bundle names it (compiler reconcile, architect decision A10-27). The render
-- time, not the bundle's publish time, decides: a render before the lock end that commits after it still names the
-- denial. Only locks that ended within the last week are read, so the round does not scan every denial ever made; the
-- reconcile runs every minute, so a lock is caught long before that.
SELECT DISTINCT d.id FROM device d
JOIN software_request r ON r.device_id = d.id
WHERE d.state = 'active' AND r.state = 'denied' AND r.decided_at <= sqlc.arg(lock_start)::timestamptz
  AND r.decided_at > sqlc.arg(lock_start)::timestamptz - interval '7 days'
  AND r.decided_at + (sqlc.arg(now)::timestamptz - sqlc.arg(lock_start)::timestamptz)
    > coalesce(d.denial_lock_checked_at, '-infinity'::timestamptz)
ORDER BY d.id;

-- name: MarkDenialLockChecked :execrows
-- Records the render time of a compile for a device while its bundle_seq is still the one that compile left: the
-- bundle it committed, or the unchanged (or blocked) one it kept. Every denial lock that ended before checked_at is
-- then reflected in that bundle. A concurrent compile that changed bundle_seq records its own render time instead, so
-- a later render time never lands on a bundle rendered earlier.
UPDATE device SET denial_lock_checked_at = sqlc.arg(checked_at)::timestamptz
WHERE id = sqlc.arg(id)::uuid AND bundle_seq = sqlc.arg(bundle_seq)::bigint;
