-- The notifier's delivery state (plan M9 decisions 21–23), role paddock_notifier: an organization's rows under its
-- context, the platform destinations under the nil organization. Every result column of
-- notification_destination_state is written here and nowhere else (migration 00085).

-- name: ListNotifierDestinations :many
SELECT d.id, d.organization_id, d.type, d.name, d.filter_mode, d.codes, d.pseudonymize_users, d.include_params,
       d.url_ciphertext, d.secret_ciphertext, d.heartbeat_interval_s, d.recipients, d.email_min_interval_s,
       s.cursor_commit_seq, s.start_at_latest, s.forward_seq, s.status, s.pending_delivery_id,
       s.consecutive_failures, s.first_failure_at, s.stalled_since, s.last_success_at, s.next_attempt_at,
       s.last_heartbeat_at, p.forward_from AS pending_forward_from
FROM notification_destination d
JOIN notification_destination_state s ON s.destination_id = d.id AND s.organization_id = d.organization_id
LEFT JOIN notification_delivery p ON p.id = s.pending_delivery_id AND p.organization_id = s.organization_id
WHERE d.enabled
ORDER BY d.id;

-- name: StartNotifierCursorAtLatest :one
-- Resolves a skip request: the cursor jumps to the scope's latest commit sequence (never back, the trigger refuses a
-- decrease anyway) and a pending batch, whose events lie at or below it, is dropped. Only while the flag is set, so a
-- request that arrived after the read is resolved in the next round.
UPDATE notification_destination_state SET
  cursor_commit_seq = greatest(cursor_commit_seq, @latest::bigint), start_at_latest = false,
  pending_delivery_id = NULL, next_attempt_at = NULL
WHERE destination_id = @destination_id AND start_at_latest
RETURNING cursor_commit_seq;

-- name: SkipNotifierDelivery :exec
-- A pending batch dropped by a skip request: neither delivered nor failed.
UPDATE notification_delivery SET last_error = 'skipped' WHERE id = @id AND delivered_at IS NULL;

-- name: NextNotifierTestDelivery :one
SELECT id, requested_by FROM notification_delivery
WHERE destination_id = @destination_id AND kind = 'test' AND delivered_at IS NULL AND last_error IS NULL
ORDER BY created_at, id
LIMIT 1;

-- name: FinishNotifierTestDelivery :exec
UPDATE notification_delivery SET
  attempts = attempts + 1, delivered_at = sqlc.narg(delivered_at)::timestamptz, last_error = sqlc.narg(last_error)::text
WHERE id = @id;

-- name: SetNotifierTestResult :exec
UPDATE notification_destination_state SET
  last_test_at = @at, last_test_ok = @ok, last_test_error = sqlc.narg(test_error)::text
WHERE destination_id = @destination_id;

-- name: GetNotifierDelivery :one
SELECT id, kind, forward_from, forward_to, event_count, attempts FROM notification_delivery WHERE id = @id;

-- name: ListNotifierDeliveryEvents :many
SELECT forward_seq, event_id, commit_seq FROM notification_delivery_event
WHERE delivery_id = @delivery_id
ORDER BY forward_seq;

-- name: InsertNotifierDelivery :exec
INSERT INTO notification_delivery (id, destination_id, organization_id, kind, forward_from, forward_to, event_count)
VALUES (@id, @destination_id, @organization_id, @kind, sqlc.narg(forward_from), sqlc.narg(forward_to), @event_count);

-- name: InsertNotifierDeliveryEvents :exec
INSERT INTO notification_delivery_event (destination_id, organization_id, forward_seq, event_id, commit_seq, delivery_id)
SELECT @destination_id::uuid, @organization_id::uuid, unnest(@forward_seqs::bigint[]), unnest(@event_ids::uuid[]),
       unnest(@commit_seqs::bigint[]), @delivery_id::uuid;

-- name: SetNotifierPending :exec
-- The batch's forward sequence numbers are taken when it is created, so they never change on a retry.
UPDATE notification_destination_state SET forward_seq = @forward_seq, pending_delivery_id = @delivery_id
WHERE destination_id = @destination_id;

-- name: AdvanceNotifierCursor :exec
UPDATE notification_destination_state SET cursor_commit_seq = @cursor_commit_seq WHERE destination_id = @destination_id;

-- name: NotifierDeliverySucceeded :execrows
-- Guarded: a delivery is marked delivered once, so its notification.delivered is recorded once.
UPDATE notification_delivery SET attempts = attempts + 1, delivered_at = @at, last_error = NULL
WHERE id = @id AND delivered_at IS NULL;

-- name: NotifierDestinationSucceeded :execrows
-- A delivered batch moves the cursor to the last event it covered; a heartbeat (cursor_commit_seq NULL) does not. Only
-- while the state still has the pending batch the engine delivered (none for a heartbeat): a skip request resolved
-- meanwhile wins.
UPDATE notification_destination_state SET
  cursor_commit_seq = coalesce(sqlc.narg(cursor_commit_seq)::bigint, cursor_commit_seq),
  pending_delivery_id = CASE WHEN sqlc.narg(cursor_commit_seq)::bigint IS NULL THEN pending_delivery_id END,
  consecutive_failures = 0, first_failure_at = NULL, last_error = NULL, next_attempt_at = NULL,
  last_attempt_at = @at,
  last_success_at = CASE WHEN sqlc.narg(cursor_commit_seq)::bigint IS NULL THEN last_success_at ELSE @at END,
  last_heartbeat_at = CASE WHEN sqlc.narg(cursor_commit_seq)::bigint IS NULL THEN @at ELSE last_heartbeat_at END
WHERE destination_id = @destination_id AND pending_delivery_id IS NOT DISTINCT FROM sqlc.narg(expected_pending)::uuid;

-- name: NotifierDestinationResumed :execrows
UPDATE notification_destination_state SET status = 'active', stalled_since = NULL
WHERE destination_id = @destination_id AND status = 'stalled';

-- name: NotifierDeliveryFailed :exec
UPDATE notification_delivery SET attempts = attempts + 1, last_error = @last_error WHERE id = @id AND delivered_at IS NULL;

-- name: NotifierDestinationFailed :execrows
-- Guarded like NotifierDestinationSucceeded, so a stall is recorded once and never for a batch that was dropped.
UPDATE notification_destination_state SET
  consecutive_failures = @consecutive_failures, first_failure_at = @first_failure_at, last_error = @last_error,
  last_attempt_at = @at, next_attempt_at = @next_attempt_at, status = @status,
  stalled_since = sqlc.narg(stalled_since)::timestamptz
WHERE destination_id = @destination_id AND pending_delivery_id IS NOT DISTINCT FROM sqlc.narg(expected_pending)::uuid
  AND status = @previous_status;

-- name: GetNotifierPseudonymKey :one
SELECT key_ciphertext FROM notification_pseudonym_key;

-- name: ListNotifierPseudonymLookups :many
SELECT id, pseudonym FROM notification_pseudonym_lookup WHERE resolved_at IS NULL ORDER BY created_at;

-- name: ListNotifierUsernames :many
-- Every name a pseudonym of the organization can stand for (plan M9 decision 18).
SELECT username FROM admin_account
UNION
SELECT username FROM app_user;

-- name: ResolveNotifierPseudonymLookup :exec
UPDATE notification_pseudonym_lookup SET resolved_username = @resolved_username, resolved_at = @at
WHERE id = @id AND resolved_at IS NULL;

-- name: DeleteExpiredNotifierPseudonymLookups :exec
-- Lookups live 10 minutes (plan M9 decision 18), resolved or not.
DELETE FROM notification_pseudonym_lookup WHERE created_at < @before;
