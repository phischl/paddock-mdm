-- Supervisor package updates (ADR 0037 decision 3, plan M8d decision 30, PDK-227): the compiler renders the
-- paddock-supervisor packages of the current release — the release of the most recently completed rollout — into v2
-- bundles. The compiler role reads release data only through functions like paddock_fleetd_package (migration
-- 00023); no row while no rollout completed or the latest one was halted afterwards. Forward-only: there is no Down
-- migration.
-- +goose Up
CREATE FUNCTION paddock_supervisor_packages()
  RETURNS TABLE (version text, arch text, package_version text, sha256 text, object_key text)
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, pg_temp AS
  $$ WITH current AS (
       SELECT ro.version FROM agent_rollout ro
       ORDER BY (ro.status = 'running') DESC, ro.started_at DESC
       LIMIT 1)
     SELECT p.version, p.arch, coalesce(p.package_version, p.version), p.sha256, p.object_key
     FROM agent_package p JOIN current c USING (version)
     JOIN agent_rollout ro ON ro.version = c.version
     WHERE p.name = 'paddock-supervisor' AND ro.status = 'completed'
     ORDER BY p.arch $$;
REVOKE ALL ON FUNCTION paddock_supervisor_packages() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION paddock_supervisor_packages() TO paddock_compiler;

-- +goose Down
