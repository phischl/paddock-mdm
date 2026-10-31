-- Notification destinations (plan M9 decisions 14–18). The same queries serve the organization scope (paddock_api)
-- and the platform scope (paddock_platform, nil organization): row level security selects the rows. The api never
-- writes a state column (migration 00085): it inserts the state row with its key and requests a cursor skip through
-- the SECURITY DEFINER functions.

-- name: InsertNotificationDestination :exec
INSERT INTO notification_destination (
  id, organization_id, type, name, enabled, filter_mode, codes, pseudonymize_users, include_params, url_ciphertext,
  url_display, secret_ciphertext, heartbeat_interval_s, recipients, email_min_interval_s, created_by
) VALUES (
  @id, @organization_id, @type, @name, @enabled, @filter_mode, @codes, @pseudonymize_users, @include_params,
  sqlc.narg(url_ciphertext), sqlc.narg(url_display), sqlc.narg(secret_ciphertext), @heartbeat_interval_s, @recipients,
  @email_min_interval_s, @created_by
);

-- name: InsertNotificationDestinationState :exec
INSERT INTO notification_destination_state (destination_id, organization_id) VALUES (@destination_id, @organization_id);

-- name: GetNotificationDestination :one
SELECT d.id, d.organization_id, d.type, d.name, d.enabled, d.filter_mode, d.codes, d.pseudonymize_users,
       d.include_params, d.url_display, d.heartbeat_interval_s, d.recipients, d.email_min_interval_s, d.created_by,
       d.created_at, d.updated_at,
       s.status, s.cursor_commit_seq, s.forward_seq, s.last_success_at, s.last_attempt_at, s.next_attempt_at,
       s.stalled_since, s.first_failure_at, s.last_error, s.last_test_at, s.last_test_ok, s.last_test_error
FROM notification_destination d
LEFT JOIN notification_destination_state s ON s.destination_id = d.id AND s.organization_id = d.organization_id
WHERE d.id = @id;

-- name: LockNotificationDestination :one
-- The row an update, rotation or deletion changes, locked against a concurrent change of the same destination.
SELECT id, type, name, enabled FROM notification_destination WHERE id = @id FOR UPDATE;

-- List queries (ADR 0018): see device_group.sql.

-- name: ListNotificationDestinations :many
SELECT d.id, d.organization_id, d.type, d.name, d.enabled, d.filter_mode, d.codes, d.pseudonymize_users,
       d.include_params, d.url_display, d.heartbeat_interval_s, d.recipients, d.email_min_interval_s, d.created_by,
       d.created_at, d.updated_at,
       s.status, s.cursor_commit_seq, s.forward_seq, s.last_success_at, s.last_attempt_at, s.next_attempt_at,
       s.stalled_since, s.first_failure_at, s.last_error, s.last_test_at, s.last_test_ok, s.last_test_error
FROM notification_destination d
LEFT JOIN notification_destination_state s ON s.destination_id = d.id AND s.organization_id = d.organization_id
WHERE (sqlc.narg(q_pattern)::text IS NULL OR d.name ILIKE sqlc.narg(q_pattern)::text ESCAPE '\')
  AND (sqlc.narg(types)::text[] IS NULL OR d.type = ANY(sqlc.narg(types)::text[]))
  AND (sqlc.narg(enabled)::boolean IS NULL OR d.enabled = sqlc.narg(enabled)::boolean)
ORDER BY
  CASE WHEN @sort::text = 'name' THEN name END ASC,
  CASE WHEN @sort::text = '-name' THEN name END DESC,
  CASE WHEN @sort::text = 'type' THEN type END ASC,
  CASE WHEN @sort::text = '-type' THEN type END DESC,
  CASE WHEN @sort::text = 'created_at' THEN created_at END ASC,
  CASE WHEN @sort::text = '-created_at' THEN created_at END DESC,
  d.id
LIMIT @max_rows OFFSET @skip_rows;

-- name: CountNotificationDestinations :one
SELECT count(*) FROM (
  SELECT 1 FROM notification_destination d
  WHERE (sqlc.narg(q_pattern)::text IS NULL OR d.name ILIKE sqlc.narg(q_pattern)::text ESCAPE '\')
    AND (sqlc.narg(types)::text[] IS NULL OR d.type = ANY(sqlc.narg(types)::text[]))
    AND (sqlc.narg(enabled)::boolean IS NULL OR d.enabled = sqlc.narg(enabled)::boolean)
  LIMIT @count_limit
) matching;

-- name: UpdateNotificationDestination :exec
-- A NULL url_ciphertext keeps the stored URL and its display (an update without url).
UPDATE notification_destination SET
  name = @name, enabled = @enabled, filter_mode = @filter_mode, codes = @codes,
  pseudonymize_users = @pseudonymize_users, include_params = @include_params,
  url_ciphertext = coalesce(sqlc.narg(url_ciphertext), url_ciphertext),
  url_display = coalesce(sqlc.narg(url_display), url_display),
  heartbeat_interval_s = @heartbeat_interval_s, recipients = @recipients,
  email_min_interval_s = @email_min_interval_s, updated_at = now()
WHERE id = @id;

-- name: UpdateNotificationDestinationSecret :exec
UPDATE notification_destination SET secret_ciphertext = @secret_ciphertext, updated_at = now() WHERE id = @id;

-- name: DeleteNotificationDestination :execrows
DELETE FROM notification_destination WHERE id = @id;

-- name: StartNotificationDestinationAtLatest :one
-- Organization scope: false for a destination that is not the organization's.
SELECT coalesce(paddock_destination_start_at_latest(@destination_id), false)::boolean AS started;

-- name: StartPlatformNotificationDestinationAtLatest :one
-- Platform scope: false for a destination that is not the platform's.
SELECT coalesce(paddock_platform_destination_start_at_latest(@destination_id), false)::boolean AS started;

-- name: InsertNotificationTestDelivery :exec
INSERT INTO notification_delivery (id, destination_id, organization_id, kind, requested_by)
VALUES (@id, @destination_id, @organization_id, 'test', @requested_by);

-- name: NotificationPseudonymKeyExists :one
SELECT EXISTS (SELECT 1 FROM notification_pseudonym_key) AS present;

-- name: InsertNotificationPseudonymKey :exec
-- A concurrent creation keeps the first key: the api cannot replace a key, and every pseudonym stays stable.
INSERT INTO notification_pseudonym_key (organization_id, key_ciphertext) VALUES (@organization_id, @key_ciphertext)
ON CONFLICT (organization_id) DO NOTHING;

-- name: InsertNotificationPseudonymLookup :exec
INSERT INTO notification_pseudonym_lookup (id, organization_id, pseudonym, requested_by)
VALUES (@id, @organization_id, @pseudonym, @requested_by);

-- name: GetNotificationPseudonymLookup :one
SELECT id, pseudonym, resolved_username, resolved_at FROM notification_pseudonym_lookup WHERE id = @id;

-- name: TakeResolvedNotificationPseudonymLookup :one
-- Reads and deletes a resolved lookup in one statement: of concurrent reads exactly one receives the user name.
DELETE FROM notification_pseudonym_lookup WHERE id = @id AND resolved_at IS NOT NULL
RETURNING pseudonym, resolved_username;

-- name: PendingNotificationTestExists :one
-- A test delivery of the destination the notifier has not attempted yet.
SELECT EXISTS (
  SELECT 1 FROM notification_delivery
  WHERE destination_id = @destination_id AND kind = 'test' AND delivered_at IS NULL AND last_error IS NULL
) AS pending;

-- name: PendingNotificationPseudonymLookupExists :one
-- An unresolved pseudonym lookup of the organization (lookups belong to the organization, not to a destination)
-- younger than the 10 minutes after which the notifier deletes lookups.
SELECT EXISTS (
  SELECT 1 FROM notification_pseudonym_lookup WHERE resolved_at IS NULL AND created_at > now() - interval '10 minutes'
) AS pending;

-- name: LockNotificationPseudonymLookups :exec
-- Serializes the pending check and the insert of lookup requests of one organization.
SELECT pg_advisory_xact_lock(hashtextextended('paddock.notification_pseudonym_lookup:' || CAST(@organization_id::uuid AS text), 0));
