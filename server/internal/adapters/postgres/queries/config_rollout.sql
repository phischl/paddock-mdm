-- Staged configuration rollouts (plan M11 decisions 25-31). At most one rollout of an organization is open (running or
-- halted); config_rollout_one_open_idx enforces it.

-- name: InsertConfigRollout :one
INSERT INTO config_rollout (id, organization_id, change_set_id, waves, min_wave_minutes, failure_threshold_percent,
  failure_threshold_min, canary_device_group_id, status, started_by, staged_assignments, wave_success_threshold_percent,
  stall_warning_hours)
VALUES (@id, @organization_id, @change_set_id, @waves, @min_wave_minutes, @failure_threshold_percent,
  @failure_threshold_min, sqlc.narg(canary_device_group_id), 'running', @started_by, sqlc.narg(staged_assignments),
  @wave_success_threshold_percent, @stall_warning_hours)
RETURNING *;

-- name: GetOpenConfigRollout :one
-- The open rollout, its wave and the plan of its change set, whose keys are staged.
SELECT r.id, r.change_set_id, r.status, r.waves, r.current_wave_index, r.canary_device_group_id, c.plan
FROM config_rollout r JOIN change_set c ON c.id = r.change_set_id
WHERE r.status IN ('running', 'halted');

-- name: GetOpenConfigRolloutOverlay :one
-- What the compiler needs of the open rollout: its wave, its canary group, the rows of its staged software assignments
-- and the plan and before-states of its change set.
SELECT r.id, r.status, r.waves, r.current_wave_index, r.canary_device_group_id, r.staged_assignments, c.plan, c.before
FROM config_rollout r JOIN change_set c ON c.id = r.change_set_id
WHERE r.status IN ('running', 'halted');

-- name: EndConfigRolloutReverted :execrows
UPDATE config_rollout SET status = 'reverted', ended_at = now(), ended_reason = @ended_reason, updated_at = now()
WHERE id = @id AND status IN ('running', 'halted');

-- Evaluation and wave actions (plan M11 decisions 32-34, PDK-158).

-- name: GetConfigRollout :one
SELECT * FROM config_rollout WHERE id = @id;

-- name: LockConfigRollout :one
-- A rollout under its row lock, so that the worker's round and the administrator's actions see each other's change.
SELECT * FROM config_rollout WHERE id = @id FOR UPDATE;

-- name: HaltConfigRollout :one
UPDATE config_rollout SET status = 'halted', halted_reason = @halted_reason, updated_at = now()
WHERE id = @id RETURNING *;

-- name: ResumeConfigRollout :one
-- Failures reported before the resume no longer count, and the wave gets its full observation period again (plan M11
-- decision 32, amendment R6.14 (d)): its first apply and applied devices are cleared, so the next worker round dates the
-- first apply anew (architect decision A10-18). The time it was halted is no stall (A10-16).
UPDATE config_rollout SET status = 'running', halted_reason = NULL, evaluation_since = now(), wave_started_at = now(),
  wave_first_applied_at = NULL, wave_applied = 0, wave_outstanding = 0, wave_progress_at = now(), stall_warned_at = NULL,
  updated_at = now()
WHERE id = @id RETURNING *;

-- name: AdvanceConfigRollout :one
-- The next wave starts without an apply of its own (A10-16).
UPDATE config_rollout SET current_wave_index = current_wave_index + 1, wave_started_at = now(), wave_first_applied_at = NULL,
  wave_applied = 0, wave_outstanding = 0, wave_progress_at = now(), stall_warned_at = NULL, updated_at = now()
WHERE id = @id RETURNING *;

-- name: RecordConfigRolloutWaveProgress :execrows
-- The worker's bookkeeping of the wave it evaluated (A10-16, A10-19 §3): the applied devices that joined in the wave, the
-- devices it waits for (waiting for a window or awaiting a retry), the time the first applied device was seen and the
-- time the wave last made progress (more applied, or fewer outstanding), which ends a stall warning. Only while the
-- rollout is still running in the wave the worker read, so it never dates a wave an administrator moved on since.
UPDATE config_rollout SET wave_applied = @wave_applied, wave_outstanding = @wave_outstanding,
  wave_first_applied_at = CASE WHEN wave_first_applied_at IS NULL AND @wave_applied::int > 0 THEN @now::timestamptz
                               ELSE wave_first_applied_at END,
  wave_progress_at = CASE WHEN @wave_applied::int > wave_applied OR @wave_outstanding::int < wave_outstanding
                          THEN @now::timestamptz ELSE wave_progress_at END,
  stall_warned_at = CASE WHEN @wave_applied::int > wave_applied OR @wave_outstanding::int < wave_outstanding
                         THEN NULL ELSE stall_warned_at END
WHERE id = @id AND status = 'running' AND current_wave_index = @current_wave_index AND wave_started_at = @wave_started_at;

-- name: MarkConfigRolloutStalled :one
-- The stall warning of the current wave was given (A10-16).
UPDATE config_rollout SET stall_warned_at = @now::timestamptz WHERE id = @id RETURNING *;

-- name: CompleteConfigRollout :one
UPDATE config_rollout SET status = 'completed', ended_at = now(), ended_reason = @ended_reason, updated_at = now()
WHERE id = @id RETURNING *;

-- name: GetOpenConfigRolloutSummary :one
-- The open rollout without counts for the overview (plan M11 amendment R6.16): counting it is the rollout API's work.
SELECT id, status, waves, current_wave_index, started_at
FROM config_rollout
WHERE status IN ('running', 'halted');

-- name: ListRunningConfigRollouts :many
-- The rollouts the worker evaluates, with the plan of their change set, whose keys are staged.
SELECT sqlc.embed(r), c.plan
FROM config_rollout r JOIN change_set c ON c.id = r.change_set_id
WHERE r.status = 'running'
ORDER BY r.id;

-- name: CountConfigRolloutsByStatus :many
SELECT status, count(*) AS n FROM config_rollout GROUP BY status ORDER BY status;

-- name: GetConfigRolloutPlan :one
SELECT c.plan FROM config_rollout r JOIN change_set c ON c.id = r.change_set_id WHERE r.id = @id;

-- List queries of the admin API (ADR 0018); see device_group.sql.

-- name: ListConfigRollouts :many
-- With the plan of the change set, whose staged resources the counts need.
SELECT sqlc.embed(r), c.plan FROM config_rollout r JOIN change_set c ON c.id = r.change_set_id
WHERE (sqlc.narg(q_pattern)::text IS NULL OR started_by ILIKE sqlc.narg(q_pattern)::text ESCAPE '\')
  AND (sqlc.narg(statuses)::text[] IS NULL OR status = ANY(sqlc.narg(statuses)::text[]))
ORDER BY
  CASE WHEN @sort::text = 'started_at' THEN started_at END ASC,
  CASE WHEN @sort::text = '-started_at' THEN started_at END DESC,
  CASE WHEN @sort::text = 'status' THEN status END ASC,
  CASE WHEN @sort::text = '-status' THEN status END DESC,
  r.id
LIMIT @max_rows OFFSET @skip_rows;

-- name: CountConfigRollouts :one
SELECT count(*) FROM (
  SELECT 1 FROM config_rollout
  WHERE (sqlc.narg(q_pattern)::text IS NULL OR started_by ILIKE sqlc.narg(q_pattern)::text ESCAPE '\')
    AND (sqlc.narg(statuses)::text[] IS NULL OR status = ANY(sqlc.narg(statuses)::text[]))
  LIMIT @count_limit
) matching;

-- name: ListConfigRolloutReports :many
-- The newest report of every device on a bundle that carries one of the rollouts, with the resources that failed in
-- that version: what the counts of a rollout and its device list read (plan M11 amendment R6.14). recorded_at is when
-- the server received the report. The newest report is picked first, so the failed resources are read once per device.
-- A catalog entry the device reported failed since the rollout's evaluation_since is listed as software:<entry id>
-- (plan M13c decision 3): the software resource reports per entry through the heartbeat, not per bundle version, and
-- the counts keep only the IDs the rollout stages; discarded_resource_ids are the entries still failed since before
-- evaluation_since, a failure the last resume discarded, which the wave rules read as not yet retried (A10-18).
-- waiting_resource_ids are the entries whose policy operations wait for the device's maintenance window (PDK-809): the
-- current state, not bounded by evaluation_since, because a device that has not yet run the change must not count as
-- applied however old the report is.
WITH latest AS (
  SELECT DISTINCT ON (b.config_rollout_id, r.device_id) b.config_rollout_id AS rollout_id, r.device_id, r.version,
    r.outcome, r.mode, r.occurred_at, r.recorded_at
  FROM device_bundle_report r JOIN bundle b ON b.device_id = r.device_id AND b.version = r.version
  WHERE b.config_rollout_id = ANY(@rollout_ids::uuid[])
  ORDER BY b.config_rollout_id, r.device_id, r.version DESC
)
SELECT l.rollout_id::uuid AS rollout_id, l.device_id, l.version, l.outcome, l.mode, l.occurred_at, l.recorded_at,
  ARRAY(SELECT s.resource_id FROM device_resource_status s
        WHERE s.device_id = l.device_id AND s.bundle_version = l.version AND s.status = 'failed'
        UNION
        SELECT 'software:' || ss.catalog_entry_id::text FROM device_software_status ss JOIN config_rollout cr ON cr.id = l.rollout_id
        WHERE ss.device_id = l.device_id AND ss.state = 'failed' AND ss.reported_at >= cr.evaluation_since
        ORDER BY 1)::text[] AS failed_resource_ids,
  ARRAY(SELECT 'software:' || ss.catalog_entry_id::text FROM device_software_status ss JOIN config_rollout cr ON cr.id = l.rollout_id
        WHERE ss.device_id = l.device_id AND ss.state = 'failed' AND ss.reported_at < cr.evaluation_since
        ORDER BY 1)::text[] AS discarded_resource_ids,
  ARRAY(SELECT 'software:' || ss.catalog_entry_id::text FROM device_software_status ss
        WHERE ss.device_id = l.device_id AND ss.state = 'pending' AND ss.reason = 'outside_window'
        ORDER BY 1)::text[] AS waiting_resource_ids
FROM latest l;

-- name: ListConfigRolloutDevices :many
-- The active devices with their newest bundle, ordered by hostname: the rollout's device list sorts the rest in memory,
-- because whether a device is in the wave depends on its bucket in the rollout. A device without a bundle has version 0.
SELECT d.id, d.hostname, d.config_mode,
  COALESCE(nb.version, 0)::bigint AS bundle_version,
  COALESCE(nb.config_rollout_id, '00000000-0000-0000-0000-000000000000'::uuid)::uuid AS bundle_rollout_id
FROM device d
LEFT JOIN LATERAL (SELECT b.version, b.config_rollout_id FROM bundle b WHERE b.device_id = d.id ORDER BY b.version DESC LIMIT 1) nb ON true
WHERE d.state = 'active'
  AND (sqlc.narg(q_pattern)::text IS NULL OR d.hostname ILIKE sqlc.narg(q_pattern)::text ESCAPE '\')
ORDER BY d.hostname, d.id;
