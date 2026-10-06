-- Agent releases, artifacts and rollouts (plan M2b §3.3). Platform scope (paddock_platform), except the update
-- reports, which the worker writes per organization.

-- name: InsertAgentRelease :one
INSERT INTO agent_release (version, created_by) VALUES (@version, @created_by)
RETURNING *;

-- name: GetAgentRelease :one
SELECT * FROM agent_release WHERE version = @version;

-- name: PublishAgentRelease :one
UPDATE agent_release SET status = 'published', published_at = now()
WHERE version = @version
RETURNING *;

-- List queries (ADR 0018): see device_group.sql.

-- name: ListAgentReleases :many
SELECT agent_release.*,
       coalesce((SELECT ro.status FROM agent_rollout ro WHERE ro.version = agent_release.version), '')::text AS rollout_status, -- '' = none
       (SELECT count(*) FROM agent_artifact a WHERE a.version = agent_release.version)::int AS artifact_count
FROM agent_release
WHERE (sqlc.narg(q_pattern)::text IS NULL OR version ILIKE sqlc.narg(q_pattern)::text ESCAPE '\')
  AND (sqlc.narg(statuses)::text[] IS NULL OR status = ANY(sqlc.narg(statuses)::text[]))
ORDER BY
  CASE WHEN @sort::text = 'version' THEN version END ASC,
  CASE WHEN @sort::text = '-version' THEN version END DESC,
  CASE WHEN @sort::text = 'created_at' THEN created_at END ASC,
  CASE WHEN @sort::text = '-created_at' THEN created_at END DESC,
  CASE WHEN @sort::text = 'status' THEN status END ASC,
  CASE WHEN @sort::text = '-status' THEN status END DESC,
  version
LIMIT @max_rows OFFSET @skip_rows;

-- name: CountAgentReleases :one
SELECT count(*) FROM (
  SELECT 1 FROM agent_release
  WHERE (sqlc.narg(q_pattern)::text IS NULL OR version ILIKE sqlc.narg(q_pattern)::text ESCAPE '\')
    AND (sqlc.narg(statuses)::text[] IS NULL OR status = ANY(sqlc.narg(statuses)::text[]))
  LIMIT @count_limit
) matching;

-- name: UpsertAgentArtifact :one
INSERT INTO agent_artifact (version, arch, sha256, size, minisig, object_key)
VALUES (@version, @arch, @sha256, @size, @minisig, @object_key)
ON CONFLICT (version, arch) DO UPDATE
  SET sha256 = EXCLUDED.sha256, size = EXCLUDED.size, minisig = EXCLUDED.minisig, object_key = EXCLUDED.object_key,
      created_at = now()
RETURNING *;

-- name: ListAgentArtifacts :many
SELECT * FROM agent_artifact WHERE version = @version ORDER BY arch;

-- name: InsertAgentRollout :one
INSERT INTO agent_rollout (version, waves, min_wave_minutes, failure_threshold_percent, failure_threshold_min, status,
                           started_by)
VALUES (@version, @waves::int[], @min_wave_minutes, @failure_threshold_percent, @failure_threshold_min, 'running',
        @started_by)
RETURNING *;

-- name: GetAgentRollout :one
SELECT * FROM agent_rollout WHERE version = @version;

-- name: SetAgentRolloutStatus :one
UPDATE agent_rollout SET status = @status, halted_reason = sqlc.narg(halted_reason), updated_at = now()
WHERE version = @version
RETURNING *;

-- Resume restarts the failure count (plan M2.1 decision 1).
-- name: ResumeAgentRollout :one
UPDATE agent_rollout SET status = @status, halted_reason = NULL, evaluation_since = now(), updated_at = now()
WHERE version = @version
RETURNING *;

-- name: CompleteAgentRollout :one
UPDATE agent_rollout SET status = 'completed', completed_at = now(), updated_at = now()
WHERE version = @version
RETURNING *;

-- name: AdvanceAgentRollout :one
UPDATE agent_rollout SET current_wave_index = current_wave_index + 1, wave_started_at = now(), updated_at = now()
WHERE version = @version
RETURNING *;

-- name: ListRunningAgentRollouts :many
SELECT * FROM agent_rollout WHERE status = 'running' ORDER BY version;

-- The rollout that decides what devices are offered: the running one, otherwise the most recently started one (a
-- halted latest rollout offers nothing, so halting never falls back to an older release).
-- name: CurrentAgentRollout :one
SELECT * FROM agent_rollout
ORDER BY (status = 'running') DESC, started_at DESC
LIMIT 1;

-- name: AgentRolloutStats :one
SELECT eligible::bigint, updated::bigint, failed::bigint FROM paddock_agent_rollout_stats(@version, @percent::int);

-- Counts of a running rollout with the failures since since (plan M2.1 decision 1).
-- name: RolloutEvaluationStats :one
SELECT eligible::bigint, failed::bigint FROM paddock_agent_rollout_evaluation_stats(@version, @percent::int, @since::timestamptz);

-- Counts of the current release over the sliding window starting at since (plan M2.1 decision 1).
-- name: CurrentReleaseStats :one
SELECT offered::bigint, failed::bigint FROM paddock_agent_current_release_stats(@version, @since::timestamptz);

-- name: InsertAgentUpdateReport :exec
INSERT INTO agent_update_report (device_id, organization_id, version, outcome)
VALUES (@device_id, @organization_id, @version, @outcome)
ON CONFLICT DO NOTHING;

-- Debian packages of a release (plan M4b decision 1).

-- name: UpsertAgentPackage :one
INSERT INTO agent_package (version, name, arch, sha256, size, minisig, object_key)
VALUES (@version, @name, @arch, @sha256, @size, @minisig, @object_key)
ON CONFLICT (version, name, arch) DO UPDATE
  SET sha256 = EXCLUDED.sha256, size = EXCLUDED.size, minisig = EXCLUDED.minisig, object_key = EXCLUDED.object_key,
      created_at = now()
RETURNING *;

-- name: ListAgentPackages :many
SELECT * FROM agent_package WHERE version = @version ORDER BY name, arch;

-- The packages of the release new devices install (plan M4b decision 2); paddock-supervisor first.
-- name: InstallPackages :many
SELECT version::text, name::text, sha256::text, object_key::text FROM paddock_install_packages(@arch::text);
