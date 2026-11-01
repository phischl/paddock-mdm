-- Staged configuration rollouts (plan M11 decisions 23 and 24). Without a settings row the defaults apply.

-- name: GetRolloutSettings :one
SELECT * FROM organization_rollout_settings;

-- name: UpsertRolloutSettings :one
INSERT INTO organization_rollout_settings (organization_id, enabled, waves, min_wave_minutes, failure_threshold_percent,
  failure_threshold_min, canary_device_group_id, updated_at, updated_by)
VALUES (@organization_id, @enabled, @waves, @min_wave_minutes, @failure_threshold_percent, @failure_threshold_min,
  sqlc.narg(canary_device_group_id), now(), sqlc.narg(updated_by))
ON CONFLICT (organization_id) DO UPDATE
SET enabled = excluded.enabled, waves = excluded.waves, min_wave_minutes = excluded.min_wave_minutes,
    failure_threshold_percent = excluded.failure_threshold_percent, failure_threshold_min = excluded.failure_threshold_min,
    canary_device_group_id = excluded.canary_device_group_id, updated_at = excluded.updated_at, updated_by = excluded.updated_by
RETURNING *;
