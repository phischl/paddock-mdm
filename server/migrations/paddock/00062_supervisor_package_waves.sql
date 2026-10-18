-- Supervisor packages follow the rollout waves (ADR 0037 amendment 2026-10-18, PDK-326, design contract 6): the
-- compiler renders the paddock-supervisor packages of the current rollout while it is running or completed, with the
-- rollout's status and waves, so that a device's bundle carries the package only once the device's wave bucket was
-- reached — the same gate as the agent offer. A halted rollout renders nothing. A failed supervisor upgrade is
-- reported as agent_update_report outcome supervisor_failed and counts toward the rollout's failure threshold like a
-- failed agent update. Forward-only: there is no Down migration.
-- +goose Up
DROP FUNCTION paddock_supervisor_packages();

-- +goose StatementBegin
CREATE FUNCTION paddock_supervisor_packages()
  RETURNS TABLE (version text, arch text, package_version text, sha256 text, object_key text, status text,
                 waves int[], current_wave_index int)
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, pg_temp AS
  $$ WITH current AS (
       SELECT ro.version, ro.status, ro.waves, ro.current_wave_index FROM agent_rollout ro
       ORDER BY (ro.status = 'running') DESC, ro.started_at DESC
       LIMIT 1)
     SELECT p.version, p.arch, coalesce(p.package_version, p.version), p.sha256, p.object_key, c.status, c.waves,
            c.current_wave_index
     FROM agent_package p JOIN current c USING (version)
     WHERE p.name = 'paddock-supervisor' AND c.status IN ('running', 'completed')
     ORDER BY p.arch $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION paddock_supervisor_packages() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION paddock_supervisor_packages() TO paddock_compiler;

ALTER TABLE agent_update_report DROP CONSTRAINT agent_update_report_outcome_check,
  ADD CONSTRAINT agent_update_report_outcome_check
  CHECK (outcome IN ('updated','update_failed','rolled_back','rollback_failed','supervisor_failed'));

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION paddock_agent_rollout_stats(release text, pct int)
  RETURNS TABLE (eligible bigint, updated bigint, failed bigint)
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, pg_temp AS
  $$ SELECT
       (SELECT count(*) FROM device WHERE state = 'active' AND paddock_rollout_bucket(id) < pct),
       (SELECT count(DISTINCT device_id) FROM agent_update_report WHERE version = release AND outcome = 'updated'),
       (SELECT count(DISTINCT device_id) FROM agent_update_report
          WHERE version = release AND outcome IN ('update_failed','rolled_back','rollback_failed','supervisor_failed')) $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION paddock_agent_current_release_stats(release text, since timestamptz)
  RETURNS TABLE (offered bigint, failed bigint)
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, pg_temp AS
  $$ SELECT
       (SELECT count(*) FROM device JOIN device_status ON device_status.device_id = device.id
          WHERE device.state = 'active' AND device_status.last_contact_at >= since),
       (SELECT count(DISTINCT device_id) FROM agent_update_report
          WHERE version = release AND outcome IN ('update_failed','rolled_back','rollback_failed','supervisor_failed')
            AND reported_at >= since) $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION paddock_agent_rollout_evaluation_stats(release text, pct int, since timestamptz)
  RETURNS TABLE (eligible bigint, failed bigint)
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, pg_temp AS
  $$ SELECT
       (SELECT count(*) FROM device WHERE state = 'active' AND paddock_rollout_bucket(id) < pct),
       (SELECT count(DISTINCT device_id) FROM agent_update_report
          WHERE version = release AND outcome IN ('update_failed','rolled_back','rollback_failed','supervisor_failed')
            AND reported_at >= since) $$;
-- +goose StatementEnd

-- +goose Down
