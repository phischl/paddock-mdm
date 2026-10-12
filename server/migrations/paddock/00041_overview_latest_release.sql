-- The overview names the latest published agent release and the running rollout (plan M7c decision 26, amendment
-- 2026-10-12). Releases and rollouts are platform data; these functions let the api read exactly these values in
-- organization scope, as paddock_current_agent_version does. Forward-only: there is no Down migration.
-- +goose Up

-- The newest published release by SemVer precedence; the later publication, then the higher text wins a tie (two
-- versions that differ only in build metadata).
CREATE FUNCTION paddock_latest_published_agent_version() RETURNS text
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, pg_temp AS
  $$ SELECT version FROM agent_release WHERE status = 'published'
     ORDER BY version_key DESC, published_at DESC NULLS LAST, version DESC LIMIT 1 $$;
REVOKE ALL ON FUNCTION paddock_latest_published_agent_version() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION paddock_latest_published_agent_version() TO paddock_api;

-- The rollout with status running (at most one, agent_rollout_one_running_idx): its release, the 1-based wave, the
-- number of waves and the percentage of the current wave. No row while none runs.
CREATE FUNCTION paddock_running_agent_rollout() RETURNS TABLE (version text, wave int, waves int, percent int)
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, pg_temp AS
  $$ SELECT ro.version, ro.current_wave_index + 1, cardinality(ro.waves), ro.waves[ro.current_wave_index + 1]
     FROM agent_rollout ro WHERE ro.status = 'running' $$;
REVOKE ALL ON FUNCTION paddock_running_agent_rollout() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION paddock_running_agent_rollout() TO paddock_api;

-- +goose Down
