-- Diagnostics bundles (ADR 0048, plan M12 decisions 3–7).

-- name: InsertDeviceDiagnostics :one
INSERT INTO device_diagnostics (id, organization_id, device_id, requested_by, requested_at, reason, state)
VALUES (@id, @organization_id, @device_id, @requested_by, @requested_at, @reason, 'requested')
RETURNING *;

-- name: GetDeviceDiagnostics :one
SELECT * FROM device_diagnostics WHERE id = @id;

-- name: DeviceHasPendingDiagnostics :one
-- At most one collection per device waits for the device (plan M12 decision 4); the caller holds the device's lock.
SELECT EXISTS (SELECT 1 FROM device_diagnostics WHERE device_id = @device_id AND state = 'requested');

-- name: AnnounceDeviceDiagnostics :execrows
-- The device's announcement of the sealed object (POST /v1/diagnostics); only the first one counts, and only while
-- the bundle has not been verified or ended.
UPDATE device_diagnostics SET object_key = @object_key, size = @size, sha256 = @sha256, nonce = @nonce,
  wrapped_dek = @wrapped_dek, key_version = sqlc.narg(key_version)
WHERE id = @id AND device_id = @device_id AND state IN ('requested','uploaded') AND object_key IS NULL;

-- name: MarkDeviceDiagnosticsUploaded :execrows
-- The command result {uploaded: true}.
UPDATE device_diagnostics SET state = 'uploaded', uploaded_at = @uploaded_at::timestamptz, files = @files,
  truncated_entries = @truncated_entries::text[], notified_sessions = @notified_sessions
WHERE id = @id AND device_id = @device_id AND state = 'requested';

-- name: FailRequestedDeviceDiagnostics :execrows
-- The command result {uploaded: false, reason}, or a failed result without a reason. The key material goes at once;
-- expires_at is when the retention round deletes whatever object a presigned PUT still left (ListEndedDeviceDiagnostics).
UPDATE device_diagnostics SET state = 'failed', failed_reason = @failed_reason, expires_at = @objects_until::timestamptz,
  object_key = NULL, nonce = NULL, wrapped_dek = NULL
WHERE id = @id AND device_id = @device_id AND state = 'requested';

-- name: ExpireRequestedDeviceDiagnostics :execrows
-- The collect_status commands that expired without a result; key material and objects go as with a failed bundle.
UPDATE device_diagnostics SET state = 'expired', expires_at = @objects_until::timestamptz, object_key = NULL,
  nonce = NULL, wrapped_dek = NULL
WHERE id = ANY(@ids::uuid[]) AND state = 'requested';

-- name: ListUploadedDeviceDiagnostics :many
-- The bundles the worker verifies: reported uploaded at or before @before.
SELECT * FROM device_diagnostics WHERE state = 'uploaded' AND uploaded_at <= @before::timestamptz
ORDER BY uploaded_at, id;

-- name: StoreDeviceDiagnostics :execrows
UPDATE device_diagnostics SET state = 'stored', stored_at = @stored_at::timestamptz, expires_at = @expires_at::timestamptz
WHERE id = @id AND state = 'uploaded';

-- name: FailUploadedDeviceDiagnostics :execrows
-- The object is missing or does not match; key material and objects go as with a failed request.
UPDATE device_diagnostics SET state = 'failed', failed_reason = @failed_reason, expires_at = @objects_until::timestamptz,
  object_key = NULL, nonce = NULL, wrapped_dek = NULL
WHERE id = @id AND state = 'uploaded';

-- name: RearmEndedDeviceDiagnostics :execrows
-- An announcement that arrived after its bundle ended without being stored: the object it may still put is deleted at
-- @objects_until at the latest.
UPDATE device_diagnostics SET expires_at = GREATEST(COALESCE(expires_at, @objects_until::timestamptz), @objects_until::timestamptz)
WHERE id = @id AND device_id = @device_id AND state IN ('failed','expired') AND stored_at IS NULL;

-- name: ListExpiredDeviceDiagnostics :many
-- One batch of bundles whose objects are due for deletion: stored bundles whose retention ended (plan M12 decision 7),
-- failed or expired bundles never stored, and purged bundles, whose upload window ended (their objects are found by the
-- derived key: a late or mismatching upload is not referenced by the row).
SELECT id, organization_id, device_id, state FROM device_diagnostics
WHERE state IN ('stored','failed','expired','purged') AND expires_at <= @now::timestamptz
  AND (state IN ('stored','purged') OR stored_at IS NULL)
ORDER BY expires_at, id
LIMIT @max_rows;

-- name: ExpireStoredDeviceDiagnostics :execrows
-- A stored bundle whose object the retention round deleted: the key material and the object key go, the metadata
-- (who, when, hash, downloads) stays.
UPDATE device_diagnostics SET state = 'expired', object_key = NULL, nonce = NULL, wrapped_dek = NULL
WHERE id = @id AND state = 'stored';

-- name: ClearEndedDeviceDiagnostics :execrows
-- A failed, expired or purged bundle whose object the retention round deleted; an announcement that re-armed it since (a
-- later expires_at) keeps it due.
UPDATE device_diagnostics SET expires_at = NULL, object_key = NULL, nonce = NULL, wrapped_dek = NULL
WHERE id = @id AND (state = 'purged' OR (state IN ('failed','expired') AND stored_at IS NULL))
  AND expires_at <= @now::timestamptz;

-- name: HasExpiredDeviceDiagnosticsRows :one
-- Whether the retention round has ended bundles older than the audit index keeps their events
-- (DeleteExpiredDeviceDiagnosticsRows).
SELECT EXISTS (
  SELECT 1 FROM device_diagnostics WHERE state IN ('failed','expired','purged') AND requested_at < @cutoff::timestamptz
    AND NOT (expires_at IS NOT NULL AND (stored_at IS NULL OR state = 'purged'))
);

-- name: DeleteExpiredDeviceDiagnosticsRows :execrows
-- One batch of ended bundles requested before the cutoff whose objects are gone already.
DELETE FROM device_diagnostics WHERE id IN (
  SELECT id FROM device_diagnostics WHERE state IN ('failed','expired','purged') AND requested_at < @cutoff::timestamptz
    AND NOT (expires_at IS NOT NULL AND (stored_at IS NULL OR state = 'purged'))
  ORDER BY requested_at LIMIT 1000);

-- name: GetDeviceDiagnosticsWithHost :one
SELECT sqlc.embed(dd), d.hostname FROM device_diagnostics dd JOIN device d ON d.id = dd.device_id WHERE dd.id = @id;

-- name: LockDeviceDiagnosticsWithHost :one
-- A download or purge holds the bundle's row, so a purge or the retention round waits instead of ending the bundle
-- while the escrow-reader unwraps its key (that would be refused as step_up_required instead of invalid_state).
SELECT sqlc.embed(dd), d.hostname FROM device_diagnostics dd JOIN device d ON d.id = dd.device_id WHERE dd.id = @id
FOR UPDATE OF dd;

-- name: ListDeviceDiagnostics :many
-- The bundles of one device (plan M12 decision 13); q searches the requester and the reason.
SELECT sqlc.embed(dd), d.hostname FROM device_diagnostics dd JOIN device d ON d.id = dd.device_id
WHERE dd.device_id = @device_id
  AND (sqlc.narg(q_pattern)::text IS NULL OR dd.requested_by ILIKE sqlc.narg(q_pattern)::text ESCAPE '\'
    OR dd.reason ILIKE sqlc.narg(q_pattern)::text ESCAPE '\')
  AND (sqlc.narg(states)::text[] IS NULL OR dd.state = ANY(sqlc.narg(states)::text[]))
ORDER BY
  CASE WHEN @sort::text = 'requested_at' THEN dd.requested_at END ASC,
  CASE WHEN @sort::text = '-requested_at' THEN dd.requested_at END DESC,
  CASE WHEN @sort::text = 'state' THEN dd.state END ASC,
  CASE WHEN @sort::text = '-state' THEN dd.state END DESC,
  dd.id
LIMIT @max_rows OFFSET @skip_rows;

-- name: CountDeviceDiagnostics :one
SELECT count(*) FROM (
  SELECT 1 FROM device_diagnostics
  WHERE device_id = @device_id
    AND (sqlc.narg(q_pattern)::text IS NULL OR requested_by ILIKE sqlc.narg(q_pattern)::text ESCAPE '\'
      OR reason ILIKE sqlc.narg(q_pattern)::text ESCAPE '\')
    AND (sqlc.narg(states)::text[] IS NULL OR state = ANY(sqlc.narg(states)::text[]))
  LIMIT @count_limit
) c;

-- name: ListAllDeviceDiagnostics :many
-- Every bundle of the organization (plan M12 decision 13); q searches the hostname and the requester.
SELECT sqlc.embed(dd), d.hostname FROM device_diagnostics dd JOIN device d ON d.id = dd.device_id
WHERE (sqlc.narg(q_pattern)::text IS NULL OR d.hostname ILIKE sqlc.narg(q_pattern)::text ESCAPE '\'
    OR dd.requested_by ILIKE sqlc.narg(q_pattern)::text ESCAPE '\')
  AND (sqlc.narg(states)::text[] IS NULL OR dd.state = ANY(sqlc.narg(states)::text[]))
ORDER BY
  CASE WHEN @sort::text = 'requested_at' THEN dd.requested_at END ASC,
  CASE WHEN @sort::text = '-requested_at' THEN dd.requested_at END DESC,
  CASE WHEN @sort::text = 'hostname' THEN d.hostname END ASC,
  CASE WHEN @sort::text = '-hostname' THEN d.hostname END DESC,
  CASE WHEN @sort::text = 'state' THEN dd.state END ASC,
  CASE WHEN @sort::text = '-state' THEN dd.state END DESC,
  dd.id
LIMIT @max_rows OFFSET @skip_rows;

-- name: CountAllDeviceDiagnostics :one
SELECT count(*) FROM (
  SELECT 1 FROM device_diagnostics dd JOIN device d ON d.id = dd.device_id
  WHERE (sqlc.narg(q_pattern)::text IS NULL OR d.hostname ILIKE sqlc.narg(q_pattern)::text ESCAPE '\'
      OR dd.requested_by ILIKE sqlc.narg(q_pattern)::text ESCAPE '\')
    AND (sqlc.narg(states)::text[] IS NULL OR dd.state = ANY(sqlc.narg(states)::text[]))
  LIMIT @count_limit
) c;

-- name: CountDeviceDiagnosticsDownload :execrows
-- A download served (plan M12 decision 4); only a stored bundle is served.
UPDATE device_diagnostics SET download_count = download_count + 1, last_downloaded_at = @downloaded_at::timestamptz
WHERE id = @id AND state = 'stored';

-- name: PurgeDeviceDiagnostics :execrows
-- An administrator's purge (ADR 0048 decision 5): the key material and the object key go at once, the metadata stays;
-- the caller deletes every version of the object in the same transaction. A device may still PUT with a presigned URL
-- issued before the purge, so the retention round deletes the object again at @objects_until.
UPDATE device_diagnostics SET state = 'purged', purged_at = @purged_at::timestamptz, expires_at = @objects_until::timestamptz,
  object_key = NULL, nonce = NULL, wrapped_dek = NULL
WHERE id = @id AND state = 'stored';
