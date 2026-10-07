-- Revocation requests and approvals (plan M4c decisions 5, 7–10). The raw step-up ID token is read only by the
-- issuer (ListRevocationApprovalTokens); every other query leaves it out.

-- name: InsertRevocationRequest :one
INSERT INTO revocation_request (id, organization_id, device_id, action, status, requested_by, requested_at, reason,
                                approved_at, period_days)
VALUES (@id, @organization_id, @device_id, @action, @status, sqlc.narg(requested_by), @requested_at, @reason,
        sqlc.narg(approved_at), sqlc.narg(period_days))
RETURNING *;

-- name: InsertRevocationApproval :exec
INSERT INTO revocation_approval (request_id, organization_id, role, admin_id, subject, stepup_jti, stepup_id_token,
                                 approved_at)
VALUES (@request_id, @organization_id, @role, @admin_id, @subject, @stepup_jti, @stepup_id_token, @approved_at);

-- name: GetRevocationRequest :one
SELECT * FROM revocation_request WHERE id = @id;

-- name: GetRevocationRequestForUpdate :one
SELECT * FROM revocation_request WHERE id = @id FOR UPDATE;

-- name: StepUpUsedForRevocation :one
-- Whether a step-up token was used for an approval already: one token per approval (plan M4c decision 8).
SELECT EXISTS (SELECT 1 FROM revocation_approval WHERE stepup_jti = @stepup_jti);

-- name: ListRevocationApprovals :many
SELECT a.request_id, a.role, a.admin_id, a.subject, a.approved_at, coalesce(ac.username, '')::text AS username
FROM revocation_approval a LEFT JOIN admin_account ac ON ac.id = a.admin_id
WHERE a.request_id = ANY(@request_ids::uuid[])
ORDER BY a.request_id, a.approved_at;

-- name: ListRevocationApprovalTokens :many
-- The issuer's view: the raw step-up ID token of every approval of a request.
SELECT role, admin_id, subject, stepup_jti, coalesce(stepup_id_token, '')::text AS stepup_id_token, approved_at
FROM revocation_approval WHERE request_id = @request_id ORDER BY approved_at;

-- name: ApproveRevocationRequest :one
-- A Destroy's second approval, or a Lock's own: approved, handed to the issuer.
UPDATE revocation_request SET status = 'approved', approved_at = @approved_at::timestamptz
WHERE id = @id AND status = 'requested'
RETURNING *;

-- name: CloseRevocationRequest :one
-- Reject or cancel a request before issuance.
UPDATE revocation_request SET status = @status, finished_at = @finished_at::timestamptz,
  rejection = sqlc.narg(rejection)
WHERE id = @id AND status IN ('requested','approved')
RETURNING *;

-- name: ActiveRevocationFreeze :one
-- The latest end of a freeze of the administrator that is still running at now (no rows if none).
SELECT frozen_until FROM revocation_freeze
WHERE admin_id = @admin_id AND frozen_until > @now::timestamptz
ORDER BY frozen_until DESC LIMIT 1;

-- name: InsertRevocationFreeze :exec
INSERT INTO revocation_freeze (organization_id, admin_id, request_id, frozen_at, frozen_until)
VALUES (@organization_id, @admin_id, @request_id, @frozen_at, @frozen_until)
ON CONFLICT DO NOTHING;

-- name: CountIssuedRevocationsByAdmin :one
-- Issued Lock and Destroy requests of an administrator since a moment (ADR 0014 sliding windows).
SELECT count(*) FROM revocation_request
WHERE requested_by = @admin_id AND action IN ('lock','destroy') AND issued_at > @since::timestamptz;

-- name: CountIssuedRevocations :one
-- Issued Lock and Destroy requests of the organization since a moment.
SELECT count(*) FROM revocation_request
WHERE action IN ('lock','destroy') AND issued_at > @since::timestamptz;

-- name: InsertSelfLock :one
-- A self-lock token of the dead man's switch: no approvals, no limits (plan M4c decision 15).
INSERT INTO revocation_request (id, organization_id, device_id, action, status, requested_at, approved_at, issued_at,
                                expires_at, envelope, period_days)
VALUES (@id, @organization_id, @device_id, 'self_lock', 'issued', @issued_at, @issued_at, @issued_at, @expires_at,
        @envelope, @period_days)
RETURNING *;

-- name: IssueRevocationRequest :one
UPDATE revocation_request SET status = 'issued', issued_at = @issued_at::timestamptz,
  expires_at = @expires_at::timestamptz, envelope = @envelope
WHERE id = @id AND status = 'approved'
RETURNING *;

-- name: ListApprovedRevocationRequests :many
-- Approved requests the issuer has not handled yet (a lost message, a failed attempt).
SELECT id FROM revocation_request WHERE status = 'approved' ORDER BY approved_at, id LIMIT 100;

-- name: ListOpenRevocationTokens :many
-- Issued, unexpired tokens: the issuer makes sure each is in cmd:<device_id>.
SELECT id, device_id, expires_at::timestamptz AS expires_at, envelope FROM revocation_request
WHERE status IN ('issued','delivered') AND expires_at > @now::timestamptz
ORDER BY issued_at, id;

-- name: ClearRevocationStepUpTokens :execrows
-- Raw step-up tokens are deleted 30 days after their request reached a final state (plan M4c decision 5).
UPDATE revocation_approval a SET stepup_id_token = NULL
FROM revocation_request r
WHERE r.id = a.request_id AND a.stepup_id_token IS NOT NULL AND r.finished_at < @before::timestamptz;

-- name: DeviceEscrowDestroyed :one
-- Whether a Destroy of the device was issued: its escrow is gone for good.
SELECT EXISTS (SELECT 1 FROM revocation_request
               WHERE device_id = @device_id AND action = 'destroy' AND status IN ('issued','delivered','confirmed','expired'));

-- name: DeleteDeviceLUKSEscrows :many
-- Crypto-shredding of a Destroy (plan M4c decision 9): every recovery key and header generation of the device.
DELETE FROM escrow_secret WHERE device_id = @device_id AND kind IN ('luks_recovery_key','luks_header')
RETURNING kind;

-- name: MarkRevocationsDelivered :execrows
UPDATE revocation_request SET status = 'delivered', delivered_at = @delivered_at::timestamptz
WHERE device_id = @device_id AND id = ANY(@ids::uuid[]) AND status = 'issued';

-- name: FinishRevocation :one
-- The device's confirmation: the first result counts.
UPDATE revocation_request SET status = @status, result = @result, confirmed_at = @confirmed_at::timestamptz,
  finished_at = @confirmed_at::timestamptz, delivered_at = coalesce(delivered_at, @confirmed_at::timestamptz)
WHERE id = @id AND device_id = @device_id AND status IN ('issued','delivered')
RETURNING *;

-- name: ExpireRevocations :many
UPDATE revocation_request SET status = 'expired', finished_at = @now::timestamptz
WHERE status IN ('issued','delivered') AND expires_at <= @now::timestamptz
RETURNING id, device_id;

-- name: GetRevocationRequestRow :one
SELECT sqlc.embed(revocation_request), device.hostname, coalesce(ac.username, '')::text AS requested_by_username
FROM revocation_request JOIN device ON device.id = revocation_request.device_id
LEFT JOIN admin_account ac ON ac.id = revocation_request.requested_by
WHERE revocation_request.id = @id;

-- List queries (ADR 0018): see device_group.sql.

-- name: ListRevocationRequests :many
SELECT sqlc.embed(revocation_request), device.hostname, coalesce(ac.username, '')::text AS requested_by_username
FROM revocation_request JOIN device ON device.id = revocation_request.device_id
LEFT JOIN admin_account ac ON ac.id = revocation_request.requested_by
WHERE (sqlc.narg(q_pattern)::text IS NULL
       OR device.hostname ILIKE sqlc.narg(q_pattern)::text ESCAPE '\'
       OR revocation_request.reason ILIKE sqlc.narg(q_pattern)::text ESCAPE '\')
  AND (sqlc.narg(statuses)::text[] IS NULL OR revocation_request.status = ANY(sqlc.narg(statuses)::text[]))
  AND (sqlc.narg(actions)::text[] IS NULL OR revocation_request.action = ANY(sqlc.narg(actions)::text[]))
  AND (sqlc.narg(device_id)::uuid IS NULL OR revocation_request.device_id = sqlc.narg(device_id)::uuid)
ORDER BY
  CASE WHEN @sort::text = 'requested_at' THEN requested_at END ASC,
  CASE WHEN @sort::text = '-requested_at' THEN requested_at END DESC,
  CASE WHEN @sort::text = 'status' THEN status END ASC,
  CASE WHEN @sort::text = '-status' THEN status END DESC,
  CASE WHEN @sort::text = 'action' THEN action END ASC,
  CASE WHEN @sort::text = '-action' THEN action END DESC,
  CASE WHEN @sort::text = 'hostname' THEN hostname END ASC,
  CASE WHEN @sort::text = '-hostname' THEN hostname END DESC,
  revocation_request.id
LIMIT @max_rows OFFSET @skip_rows;

-- name: CountRevocationRequests :one
SELECT count(*) FROM (
  SELECT 1 FROM revocation_request JOIN device ON device.id = revocation_request.device_id
  WHERE (sqlc.narg(q_pattern)::text IS NULL
         OR device.hostname ILIKE sqlc.narg(q_pattern)::text ESCAPE '\'
         OR revocation_request.reason ILIKE sqlc.narg(q_pattern)::text ESCAPE '\')
    AND (sqlc.narg(statuses)::text[] IS NULL OR revocation_request.status = ANY(sqlc.narg(statuses)::text[]))
    AND (sqlc.narg(actions)::text[] IS NULL OR revocation_request.action = ANY(sqlc.narg(actions)::text[]))
    AND (sqlc.narg(device_id)::uuid IS NULL OR revocation_request.device_id = sqlc.narg(device_id)::uuid)
  LIMIT @count_limit
) matching;
