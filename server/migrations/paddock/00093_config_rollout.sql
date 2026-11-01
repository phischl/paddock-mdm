-- Staged configuration rollouts (plan M11 decisions 25-31, ADR 0033; the plan names this file 00048, amendment R1).
-- Forward-only: there is no Down migration. A staged change set starts one rollout; devices outside its current wave
-- keep the before-state of the staged keys (compiler overlay), devices inside get the change and their bundle rows name
-- the rollout. At most one rollout per organization is open (running or halted). The api starts and ends rollouts, the
-- compiler reads them, the worker evaluates them (PDK-158). Retention (ADR 0032 §1): configuration history like
-- change_set, no purge.
-- +goose Up

CREATE TABLE config_rollout (
  id uuid PRIMARY KEY,
  organization_id uuid NOT NULL REFERENCES organization(id),
  change_set_id uuid NOT NULL UNIQUE REFERENCES change_set(id),
  waves int[] NOT NULL,
  current_wave_index int NOT NULL DEFAULT 0,
  wave_started_at timestamptz NOT NULL DEFAULT now(),
  min_wave_minutes int NOT NULL CHECK (min_wave_minutes >= 1),
  failure_threshold_percent int NOT NULL CHECK (failure_threshold_percent BETWEEN 0 AND 100),
  failure_threshold_min int NOT NULL CHECK (failure_threshold_min >= 0),
  canary_device_group_id uuid,
  status text NOT NULL CHECK (status IN ('running', 'halted', 'completed', 'reverted')),
  halted_reason text,
  evaluation_since timestamptz NOT NULL DEFAULT now(),
  started_by text NOT NULL,
  started_at timestamptz NOT NULL DEFAULT now(),
  ended_at timestamptz,
  ended_reason text,
  updated_at timestamptz NOT NULL DEFAULT now(),
  CHECK (current_wave_index >= 0 AND current_wave_index < cardinality(waves)),
  -- A composite key keeps the group inside the organization; SET NULL names the column so the organization stays.
  FOREIGN KEY (organization_id, canary_device_group_id) REFERENCES device_group (organization_id, id)
    ON DELETE SET NULL (canary_device_group_id)
);
CREATE UNIQUE INDEX config_rollout_one_open_idx ON config_rollout (organization_id) WHERE status IN ('running', 'halted');
CREATE INDEX config_rollout_org_started_idx ON config_rollout (organization_id, started_at);
ALTER TABLE config_rollout ENABLE ROW LEVEL SECURITY;
ALTER TABLE config_rollout FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON config_rollout TO paddock_api, paddock_compiler, paddock_worker
  USING (organization_id = current_setting('paddock.org_id')::uuid)
  WITH CHECK (organization_id = current_setting('paddock.org_id')::uuid);
GRANT SELECT, INSERT, UPDATE ON config_rollout TO paddock_api;
GRANT SELECT ON config_rollout TO paddock_compiler;
GRANT SELECT, UPDATE ON config_rollout TO paddock_worker;

ALTER TABLE bundle ADD COLUMN config_rollout_id uuid REFERENCES config_rollout(id);
CREATE INDEX bundle_rollout_idx ON bundle (config_rollout_id) WHERE config_rollout_id IS NOT NULL;

-- The compiler overlays the before-states of the open rollout's change set; the worker derives the staged resource IDs
-- from its plan and counts the reports of the bundles that carry the rollout.
CREATE POLICY compiler_rollout ON change_set TO paddock_compiler
  USING (organization_id = current_setting('paddock.org_id')::uuid);
GRANT SELECT (id, organization_id, plan, before) ON change_set TO paddock_compiler;
GRANT SELECT (plan) ON change_set TO paddock_worker;
GRANT SELECT (config_rollout_id) ON bundle TO paddock_worker;

-- Bucket of a device in one rollout: FNV-1a (32 bit) of '<device>:<rollout>' modulo 100, so every rollout draws its
-- waves anew. domain/configrollout.Bucket computes the same value in Go; a test keeps both equal.
-- +goose StatementBegin
CREATE FUNCTION paddock_config_rollout_bucket(device_id uuid, rollout_id uuid) RETURNS int LANGUAGE plpgsql IMMUTABLE STRICT AS $$
DECLARE
  h bigint := 2166136261;
  b bytea := convert_to(device_id::text || ':' || rollout_id::text, 'UTF8');
BEGIN
  FOR i IN 0 .. length(b) - 1 LOOP
    h := ((h # get_byte(b, i)) * 16777619) & 4294967295;
  END LOOP;
  RETURN (h % 100)::int;
END $$;
-- +goose StatementEnd

-- Counts of the rollout evaluation (plan M11 decision 27): eligible are the active devices of the caller's organization
-- in the waves up to pct or in the canary group; failed are the eligible devices whose newest report on a bundle of
-- the rollout since "since" is a rejection, or an apply with a failed staged resource of that version. SECURITY
-- INVOKER: row-level security of the caller applies, so only the organization's rows are counted.
CREATE FUNCTION paddock_config_rollout_stats(rollout uuid, pct int, canary uuid, since timestamptz, staged_ids text[])
  RETURNS TABLE (eligible bigint, failed bigint)
  LANGUAGE sql STABLE SECURITY INVOKER SET search_path = public AS
  $$ WITH e AS (
       SELECT d.id FROM device d
       WHERE d.state = 'active'
         AND (paddock_config_rollout_bucket(d.id, rollout) < pct
           OR EXISTS (SELECT 1 FROM device_group_member m WHERE m.device_id = d.id AND m.device_group_id = canary))
     ), latest AS (
       SELECT DISTINCT ON (r.device_id) r.device_id, r.version, r.outcome
       FROM device_bundle_report r JOIN bundle b ON b.device_id = r.device_id AND b.version = r.version
       WHERE b.config_rollout_id = rollout AND r.occurred_at >= since AND r.device_id IN (SELECT id FROM e)
       ORDER BY r.device_id, r.version DESC
     )
     SELECT (SELECT count(*) FROM e),
            (SELECT count(*) FROM latest l WHERE l.outcome = 'rejected' OR (l.outcome = 'applied' AND EXISTS (
               SELECT 1 FROM device_resource_status s
               WHERE s.device_id = l.device_id AND s.bundle_version = l.version AND s.status = 'failed'
                 AND s.resource_id = ANY(staged_ids)))) $$;
REVOKE ALL ON FUNCTION paddock_config_rollout_bucket(uuid, uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION paddock_config_rollout_stats(uuid, int, uuid, timestamptz, text[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION paddock_config_rollout_bucket(uuid, uuid) TO paddock_api, paddock_compiler, paddock_worker;
GRANT EXECUTE ON FUNCTION paddock_config_rollout_stats(uuid, int, uuid, timestamptz, text[])
  TO paddock_api, paddock_compiler, paddock_worker;
