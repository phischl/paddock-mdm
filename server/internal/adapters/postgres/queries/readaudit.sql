-- Coalescing keys of read-access audit events (ADR 0032 §4, plan M10 decisions 18–21).

-- name: ClaimReadAuditWindow :one
-- Claims the window of one actor, code and target; no row comes back when the window was claimed before, so the read
-- records no event (ActionRunner.RecordReadOnce). target_id is the device of an inventory view, the CVE of a
-- vulnerability device-list view (PDK-606) and the filter hash of an audit search (plan M10 amendment 2026-10-30,
-- PDK-139 round 2).
INSERT INTO read_audit_window (organization_id, actor_id, code, target_id, window_start)
VALUES (@organization_id, @actor_id, @code, @target_id, @window_start)
ON CONFLICT DO NOTHING
RETURNING true;

-- name: HasExpiredReadAuditWindows :one
SELECT EXISTS (SELECT 1 FROM read_audit_window WHERE window_start < @cutoff::timestamptz);

-- name: DeleteExpiredReadAuditWindows :execrows
-- One batch of windows that started before the cutoff (plan M10 decision 21); the retention round runs each batch in
-- its own transaction until one deletes fewer than 1 000 rows (plan M10 amendment 2026-10-30).
DELETE FROM read_audit_window WHERE ctid IN (
  SELECT ctid FROM read_audit_window WHERE window_start < @cutoff::timestamptz LIMIT 1000
);
