-- Apply status of devices (plan M11 decisions 12–14, PDK-151). The worker writes it from the device's events, in the
-- event's transaction; the admin API reads it.

-- Serializes the apply-status writes of one device across workers (PDK-151 review 1): without it, an older report
-- whose transaction runs alongside a newer one inserts the resources the newer one deleted. Released at the end of the
-- transaction.
-- name: LockDeviceConfigStatus :exec
SELECT pg_advisory_xact_lock(hashtextextended('config_status:' || CAST(@device_id::uuid AS text), 0));

-- A newer applied report owns the resource rows of the device: an older event must neither insert nor delete any.
-- name: HasNewerAppliedBundleReport :one
SELECT EXISTS (
  SELECT 1 FROM device_bundle_report WHERE device_id = @device_id AND outcome = 'applied' AND occurred_at > @occurred_at
);

-- The mode of the device's last applied report up to occurred_at: a bundle.rejected event carries none, and the device
-- keeps running the bundle it applied before.
-- name: GetLatestAppliedBundleMode :one
SELECT mode FROM device_bundle_report WHERE device_id = @device_id AND outcome = 'applied' AND occurred_at <= @occurred_at
ORDER BY occurred_at DESC, version DESC LIMIT 1;

-- A report with a newer occurred_at wins; one that is not newer changes nothing (events may arrive out of order). A
-- rejection never replaces the applied report of the same version: HasNewerAppliedBundleReport would lose it, and a
-- late older report would bring back what that version removed (PDK-151 review 2 finding L1).
-- name: UpsertDeviceBundleReport :exec
INSERT INTO device_bundle_report (device_id, organization_id, version, outcome, mode, changed, error_count, reason, occurred_at)
VALUES (@device_id, @organization_id, @version, @outcome, @mode, @changed, @error_count, sqlc.narg(reason), @occurred_at)
ON CONFLICT (device_id, version) DO UPDATE SET
  outcome = EXCLUDED.outcome, mode = EXCLUDED.mode, changed = EXCLUDED.changed, error_count = EXCLUDED.error_count,
  reason = EXCLUDED.reason, occurred_at = EXCLUDED.occurred_at, recorded_at = now()
WHERE EXCLUDED.occurred_at > device_bundle_report.occurred_at
  AND NOT (device_bundle_report.outcome = 'applied' AND EXCLUDED.outcome = 'rejected');

-- rows is a JSON array of {id, status, message, changes}; a row with a newer occurred_at is never replaced.
-- name: UpsertDeviceResourceStatuses :exec
INSERT INTO device_resource_status (device_id, organization_id, resource_id, status, message, changes, bundle_version, occurred_at)
SELECT @device_id, @organization_id, r.id, r.status, r.message, r.changes, @bundle_version, @occurred_at
FROM jsonb_to_recordset(@rows::jsonb) AS r(id text, status text, message text, changes text[])
ON CONFLICT (device_id, resource_id) DO UPDATE SET
  status = EXCLUDED.status, message = EXCLUDED.message, changes = EXCLUDED.changes,
  bundle_version = EXCLUDED.bundle_version, occurred_at = EXCLUDED.occurred_at
WHERE EXCLUDED.occurred_at >= device_resource_status.occurred_at;

-- Resources that left the bundle; rows a newer report wrote stay.
-- name: DeleteDeviceResourceStatusNotIn :exec
DELETE FROM device_resource_status
WHERE device_id = @device_id AND resource_id <> ALL(@resource_ids::text[]) AND occurred_at <= @occurred_at;

-- The report of an agent without per-resource outcomes names only failures: other rows stay.
-- name: DeleteFailedDeviceResourceStatusNotIn :exec
DELETE FROM device_resource_status
WHERE device_id = @device_id AND status = 'failed' AND resource_id <> ALL(@resource_ids::text[]) AND occurred_at <= @occurred_at;

-- name: CountDeviceResourceStatus :one
SELECT count(*) FILTER (WHERE status = 'applied')::int AS applied,
       count(*) FILTER (WHERE status = 'failed')::int AS failed,
       count(*) FILTER (WHERE status = 'pending')::int AS pending,
       count(*) FILTER (WHERE status = 'drift_corrected')::int AS drift_corrected
FROM device_resource_status WHERE device_id = @device_id;

-- List queries of the admin API (ADR 0018); see device_group.sql.

-- name: ListDeviceResourceStatus :many
SELECT resource_id, status, message, changes, bundle_version, occurred_at FROM device_resource_status
WHERE device_id = @device_id
  AND (sqlc.narg(q_pattern)::text IS NULL OR resource_id ILIKE sqlc.narg(q_pattern)::text ESCAPE '\')
  AND (sqlc.narg(statuses)::text[] IS NULL OR status = ANY(sqlc.narg(statuses)::text[]))
ORDER BY
  CASE WHEN @sort::text = 'resource_id' THEN resource_id END ASC,
  CASE WHEN @sort::text = '-resource_id' THEN resource_id END DESC,
  CASE WHEN @sort::text = 'status' THEN status END ASC,
  CASE WHEN @sort::text = '-status' THEN status END DESC,
  CASE WHEN @sort::text = 'occurred_at' THEN occurred_at END ASC,
  CASE WHEN @sort::text = '-occurred_at' THEN occurred_at END DESC,
  resource_id
LIMIT @max_rows OFFSET @skip_rows;

-- name: CountDeviceResourceStatusList :one
SELECT count(*) FROM (
  SELECT 1 FROM device_resource_status
  WHERE device_id = @device_id
    AND (sqlc.narg(q_pattern)::text IS NULL OR resource_id ILIKE sqlc.narg(q_pattern)::text ESCAPE '\')
    AND (sqlc.narg(statuses)::text[] IS NULL OR status = ANY(sqlc.narg(statuses)::text[]))
  LIMIT @count_limit
) matching;

-- Every bundle version of the device with the device's report of it; outcome none selects versions without a report.
-- name: ListDeviceBundles :many
SELECT b.version, b.created_at, b.schema_version, r.outcome AS report_outcome, r.mode AS report_mode, r.changed AS report_changed,
       r.error_count AS report_error_count, r.reason AS report_reason, r.occurred_at AS report_occurred_at
FROM bundle b LEFT JOIN device_bundle_report r ON r.device_id = b.device_id AND r.version = b.version
WHERE b.device_id = @device_id
  AND (sqlc.narg(q_pattern)::text IS NULL OR b.version::text ILIKE sqlc.narg(q_pattern)::text ESCAPE '\')
  AND (sqlc.narg(outcomes)::text[] IS NULL OR coalesce(r.outcome, 'none') = ANY(sqlc.narg(outcomes)::text[]))
ORDER BY
  CASE WHEN @sort::text = 'version' THEN b.version END ASC,
  CASE WHEN @sort::text = '-version' THEN b.version END DESC,
  CASE WHEN @sort::text = 'created_at' THEN b.created_at END ASC,
  CASE WHEN @sort::text = '-created_at' THEN b.created_at END DESC,
  b.version
LIMIT @max_rows OFFSET @skip_rows;

-- name: CountDeviceBundles :one
SELECT count(*) FROM (
  SELECT 1 FROM bundle b LEFT JOIN device_bundle_report r ON r.device_id = b.device_id AND r.version = b.version
  WHERE b.device_id = @device_id
    AND (sqlc.narg(q_pattern)::text IS NULL OR b.version::text ILIKE sqlc.narg(q_pattern)::text ESCAPE '\')
    AND (sqlc.narg(outcomes)::text[] IS NULL OR coalesce(r.outcome, 'none') = ANY(sqlc.narg(outcomes)::text[]))
  LIMIT @count_limit
) matching;

-- One row per resource ID with the number of active devices per status; a resource of retired devices only is absent.
-- name: ListConfigStatus :many
SELECT resource_id, applied, failed, pending, drift_corrected, last_failure_at FROM (
  SELECT s.resource_id,
         count(*) FILTER (WHERE s.status = 'applied')::int AS applied,
         count(*) FILTER (WHERE s.status = 'failed')::int AS failed,
         count(*) FILTER (WHERE s.status = 'pending')::int AS pending,
         count(*) FILTER (WHERE s.status = 'drift_corrected')::int AS drift_corrected,
         max(s.occurred_at) FILTER (WHERE s.status = 'failed') AS last_failure_at
  FROM device_resource_status s JOIN device d ON d.id = s.device_id AND d.state = 'active'
  WHERE (sqlc.narg(q_pattern)::text IS NULL OR s.resource_id ILIKE sqlc.narg(q_pattern)::text ESCAPE '\')
  GROUP BY s.resource_id
  HAVING sqlc.narg(statuses)::text[] IS NULL OR count(*) FILTER (WHERE s.status = ANY(sqlc.narg(statuses)::text[])) > 0
) resources
ORDER BY
  CASE WHEN @sort::text = 'resource_id' THEN resource_id END ASC,
  CASE WHEN @sort::text = '-resource_id' THEN resource_id END DESC,
  CASE WHEN @sort::text = 'failed' THEN failed END ASC,
  CASE WHEN @sort::text = '-failed' THEN failed END DESC,
  CASE WHEN @sort::text = 'pending' THEN pending END ASC,
  CASE WHEN @sort::text = '-pending' THEN pending END DESC,
  CASE WHEN @sort::text = 'applied' THEN applied END ASC,
  CASE WHEN @sort::text = '-applied' THEN applied END DESC,
  resource_id
LIMIT @max_rows OFFSET @skip_rows;

-- name: CountConfigStatus :one
SELECT count(*) FROM (
  SELECT 1
  FROM device_resource_status s JOIN device d ON d.id = s.device_id AND d.state = 'active'
  WHERE (sqlc.narg(q_pattern)::text IS NULL OR s.resource_id ILIKE sqlc.narg(q_pattern)::text ESCAPE '\')
  GROUP BY s.resource_id
  HAVING sqlc.narg(statuses)::text[] IS NULL OR count(*) FILTER (WHERE s.status = ANY(sqlc.narg(statuses)::text[])) > 0
  LIMIT @count_limit
) matching;
