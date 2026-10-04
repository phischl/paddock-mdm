-- Rollout evaluation starts again on resume (plan M2.1 decision 1 as amended). Forward-only: there is no Down
-- migration.
-- evaluation_since is the start of the failure count of a rollout: its start, and every resume, so a resumed rollout
-- is not halted again by the failures that halted it.
-- +goose Up

ALTER TABLE agent_rollout ADD COLUMN evaluation_since timestamptz;
UPDATE agent_rollout SET evaluation_since = started_at;
ALTER TABLE agent_rollout ALTER COLUMN evaluation_since SET NOT NULL, ALTER COLUMN evaluation_since SET DEFAULT now();

-- Counts for the evaluation of a running rollout: active devices in the waves up to pct (all organizations), and
-- devices that reported a failure for version since since. Nothing but counts leaves the function.
CREATE FUNCTION paddock_agent_rollout_evaluation_stats(release text, pct int, since timestamptz)
  RETURNS TABLE (eligible bigint, failed bigint)
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS
  $$ SELECT
       (SELECT count(*) FROM device WHERE state = 'active' AND paddock_rollout_bucket(id) < pct),
       (SELECT count(DISTINCT device_id) FROM agent_update_report
          WHERE version = release AND outcome IN ('update_failed','rolled_back') AND reported_at >= since) $$;
REVOKE ALL ON FUNCTION paddock_agent_rollout_evaluation_stats(text, int, timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION paddock_agent_rollout_evaluation_stats(text, int, timestamptz) TO paddock_platform;

-- +goose Down
