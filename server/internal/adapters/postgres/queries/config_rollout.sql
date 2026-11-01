-- Staged configuration rollouts (plan M11 decisions 25-31). At most one rollout of an organization is open (running or
-- halted); config_rollout_one_open_idx enforces it.

-- name: InsertConfigRollout :one
INSERT INTO config_rollout (id, organization_id, change_set_id, waves, min_wave_minutes, failure_threshold_percent,
  failure_threshold_min, canary_device_group_id, status, started_by)
VALUES (@id, @organization_id, @change_set_id, @waves, @min_wave_minutes, @failure_threshold_percent,
  @failure_threshold_min, sqlc.narg(canary_device_group_id), 'running', @started_by)
RETURNING *;

-- name: GetOpenConfigRollout :one
-- The open rollout, its wave and the plan of its change set, whose keys are staged.
SELECT r.id, r.change_set_id, r.status, r.waves, r.current_wave_index, r.canary_device_group_id, c.plan
FROM config_rollout r JOIN change_set c ON c.id = r.change_set_id
WHERE r.status IN ('running', 'halted');

-- name: GetOpenConfigRolloutOverlay :one
-- What the compiler needs of the open rollout: its wave, its canary group and the plan and before-states of its change
-- set.
SELECT r.id, r.status, r.waves, r.current_wave_index, r.canary_device_group_id, c.plan, c.before
FROM config_rollout r JOIN change_set c ON c.id = r.change_set_id
WHERE r.status IN ('running', 'halted');

-- name: EndConfigRolloutReverted :execrows
UPDATE config_rollout SET status = 'reverted', ended_at = now(), ended_reason = @ended_reason, updated_at = now()
WHERE id = @id AND status IN ('running', 'halted');
