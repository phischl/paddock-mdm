-- name: InsertAuditExport :one
-- The reader role inserts the request of its own organization (RLS WITH CHECK, plan M10 decision 29); the audit
-- writer moves it on from pending.
INSERT INTO audit_export (id, organization_id, status, from_day, to_day, purpose, requested_by, correlation_id)
VALUES (@id, @organization_id, 'pending', @from_day, @to_day, @purpose, @requested_by, @correlation_id)
RETURNING *;

-- name: GetAuditExport :one
SELECT * FROM audit_export WHERE id = @id;

-- name: GetAuditExportLocked :one
-- The row lock waits out a transaction still updating the export, so the status read is final. xmin names the
-- transaction whose write is visible, so a writer whose COMMIT outcome was lost can tell whether that was its own.
SELECT sqlc.embed(audit_export), audit_export.xmin::text AS xmin FROM audit_export WHERE id = @id FOR UPDATE;

-- name: ListAuditExports :many
SELECT * FROM audit_export
WHERE (sqlc.narg(statuses)::text[] IS NULL OR status = ANY(sqlc.narg(statuses)::text[]))
  AND (sqlc.narg(q_pattern)::text IS NULL OR purpose ILIKE sqlc.narg(q_pattern)::text ESCAPE '\'
       OR requested_by->>'display' ILIKE sqlc.narg(q_pattern)::text ESCAPE '\')
ORDER BY
  CASE WHEN @sort::text = 'requested_at' THEN requested_at END ASC,
  CASE WHEN @sort::text = '-requested_at' THEN requested_at END DESC,
  CASE WHEN @sort::text = 'status' THEN status END ASC,
  CASE WHEN @sort::text = '-status' THEN status END DESC,
  CASE WHEN @sort::text = 'from_day' THEN from_day END ASC,
  CASE WHEN @sort::text = '-from_day' THEN from_day END DESC,
  CASE WHEN @sort::text = 'to_day' THEN to_day END ASC,
  CASE WHEN @sort::text = '-to_day' THEN to_day END DESC,
  id
LIMIT @max_rows OFFSET @skip_rows;

-- name: CountAuditExports :one
SELECT count(*) FROM (
  SELECT 1 FROM audit_export
  WHERE (sqlc.narg(statuses)::text[] IS NULL OR status = ANY(sqlc.narg(statuses)::text[]))
    AND (sqlc.narg(q_pattern)::text IS NULL OR purpose ILIKE sqlc.narg(q_pattern)::text ESCAPE '\'
         OR requested_by->>'display' ILIKE sqlc.narg(q_pattern)::text ESCAPE '\')
  LIMIT @count_limit
) matching;

-- name: CountOpenAuditExports :one
SELECT count(*) FROM audit_export WHERE status IN ('pending', 'running');

-- name: LockAuditExportRequests :exec
-- Serializes the export requests of the transaction's organization so the count of open exports and the insert are
-- atomic (PDK-142 review); released at the end of the transaction. pg_advisory_xact_lock needs no grant.
SELECT pg_advisory_xact_lock(hashtextextended('audit_export:' || current_setting('paddock.org_id'), 0));

-- name: ClaimPendingAuditExport :one
-- One replica claims the oldest pending export; SKIP LOCKED lets every other replica claim the next one instead of
-- waiting (plan M10 decision 31). pending → running keeps the export open, so it needs no request lock.
UPDATE audit_export SET status = 'running', started_at = now()
WHERE id = (SELECT id FROM audit_export WHERE status = 'pending' ORDER BY requested_at LIMIT 1 FOR UPDATE SKIP LOCKED)
RETURNING *;

-- name: UpdateAuditExportReady :execrows
-- Only a running export becomes ready: an export the stuck check failed in the meantime stays failed.
UPDATE audit_export SET status = 'ready', ready_at = @ready_at, expires_at = @expires_at, event_count = @event_count,
  object_count = @object_count, size = @size, package_sha256 = @package_sha256, verify_ok = @verify_ok,
  verify_problems = @verify_problems, signature = @signature, key_version = @key_version
WHERE id = @id AND status = 'running';

-- name: UpdateAuditExportFailed :many
-- xmin of the new row version is this transaction's id; see GetAuditExportLocked.
UPDATE audit_export SET status = 'failed', error = @error WHERE id = @id AND status = 'running' RETURNING xmin::text;

-- name: UpdateAuditExportExpired :many
-- xmin of the new row version is this transaction's id; see GetAuditExportLocked.
UPDATE audit_export SET status = 'expired' WHERE id = @id AND status = 'ready' AND expires_at < @now RETURNING xmin::text;

-- name: ListExpiredAuditExports :many
SELECT * FROM audit_export WHERE status = 'ready' AND expires_at < @now ORDER BY expires_at LIMIT 100;

-- name: ListStuckAuditExports :many
SELECT * FROM audit_export WHERE status = 'running' AND started_at < @started_before ORDER BY started_at LIMIT 100;

-- name: InsertAuditExportChunk :execrows
-- Only a running export takes chunks. The share lock makes a concurrent failure wait for this insert, so its chunk
-- delete sees the row, or makes this insert see the failed status once the failure committed.
INSERT INTO audit_export_chunk (export_id, organization_id, seq, data)
SELECT @export_id::uuid, @organization_id::uuid, @seq::int4, @data::bytea
WHERE EXISTS (SELECT 1 FROM audit_export WHERE id = @export_id::uuid AND status = 'running' FOR SHARE);

-- name: DeleteAuditExportChunks :execrows
DELETE FROM audit_export_chunk WHERE export_id = @export_id;

-- name: DeleteEndedAuditExportChunks :execrows
-- The status is read in the same statement, so the chunks of an export that became ready are never deleted.
DELETE FROM audit_export_chunk c USING audit_export e
WHERE c.export_id = e.id AND e.status IN ('failed', 'expired')
  AND (sqlc.narg(export_id)::uuid IS NULL OR e.id = sqlc.narg(export_id)::uuid);

-- name: OldestPendingAuditExportAge :one
SELECT COALESCE(EXTRACT(EPOCH FROM now() - min(requested_at)), 0)::float8 AS age_seconds
FROM audit_export WHERE status = 'pending';

-- name: GetAuditExportChunk :one
-- One chunk per call keeps at most one 8 MiB row in memory while the package streams.
SELECT data FROM audit_export_chunk WHERE export_id = @export_id AND seq = @seq;

-- name: EnsureAuditSigningKey :exec
-- Insert-only: a published key is never changed, so the first public key seen for a version stays the one auditors
-- compare against (plan M10 decision 36).
INSERT INTO audit_signing_key (key_version, public_key) VALUES (@key_version, @public_key)
ON CONFLICT (key_version) DO NOTHING;

-- name: GetAuditSigningKey :one
SELECT public_key FROM audit_signing_key WHERE key_version = @key_version;

-- name: ListAuditSigningKeys :many
SELECT * FROM audit_signing_key ORDER BY key_version;
