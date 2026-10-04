-- Auto-stop for the current release (plan M2.1 decision 1, architecture §11.2 as amended). Forward-only: there is no
-- Down migration.
-- completed_at marks a rollout that finished its last wave, so resuming it after an auto-stop restores the
-- current-release offer instead of running it again.
-- +goose Up

ALTER TABLE agent_rollout ADD COLUMN completed_at timestamptz;
UPDATE agent_rollout SET completed_at = updated_at WHERE status = 'completed';

-- Counts for the current-release evaluation over the window starting at since: active devices that contacted the
-- server in the window (they were offered the release unless they already ran it), and devices that reported a
-- failure for version in the window. Nothing but counts leaves the function.
CREATE FUNCTION paddock_agent_current_release_stats(release text, since timestamptz)
  RETURNS TABLE (offered bigint, failed bigint)
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS
  $$ SELECT
       (SELECT count(*) FROM device JOIN device_status ON device_status.device_id = device.id
          WHERE device.state = 'active' AND device_status.last_contact_at >= since),
       (SELECT count(DISTINCT device_id) FROM agent_update_report
          WHERE version = release AND outcome IN ('update_failed','rolled_back') AND reported_at >= since) $$;
REVOKE ALL ON FUNCTION paddock_agent_current_release_stats(text, timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION paddock_agent_current_release_stats(text, timestamptz) TO paddock_platform;

-- +goose Down
