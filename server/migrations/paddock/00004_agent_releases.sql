-- Agent releases and staged rollouts (plan M2b §3.3). Forward-only: there is no Down migration.
-- Releases, artifacts and rollouts are platform data (no organization; role paddock_platform only). Update reports
-- are organization data written by the worker; the platform reads them only as counts through SECURITY DEFINER
-- functions.
-- +goose Up

CREATE TABLE agent_release (
  version text PRIMARY KEY CHECK (version ~ '^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$'
                                  AND char_length(version) <= 64),
  status text NOT NULL DEFAULT 'draft' CHECK (status IN ('draft','published')),
  created_by text NOT NULL, created_at timestamptz NOT NULL DEFAULT now(), published_at timestamptz
);
CREATE TABLE agent_artifact (
  version text NOT NULL REFERENCES agent_release(version), arch text NOT NULL CHECK (arch IN ('amd64','arm64')),
  sha256 text NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'), size bigint NOT NULL CHECK (size > 0),
  minisig text NOT NULL,      -- standard base64 of the .minisig file
  object_key text NOT NULL,   -- releases/<version>/<arch>/paddockd in paddock-agent-artifacts
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (version, arch)
);
CREATE TABLE agent_rollout (
  version text PRIMARY KEY REFERENCES agent_release(version),
  waves int[] NOT NULL DEFAULT '{1,10,50,100}',
  current_wave_index int NOT NULL DEFAULT 0, wave_started_at timestamptz NOT NULL DEFAULT now(),
  min_wave_minutes int NOT NULL DEFAULT 1440 CHECK (min_wave_minutes >= 1),
  failure_threshold_percent int NOT NULL DEFAULT 2 CHECK (failure_threshold_percent BETWEEN 0 AND 100),
  failure_threshold_min int NOT NULL DEFAULT 3 CHECK (failure_threshold_min >= 0),
  status text NOT NULL CHECK (status IN ('running','halted','completed')), halted_reason text,
  started_by text NOT NULL, started_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
  CHECK (current_wave_index >= 0 AND current_wave_index < cardinality(waves))
);
-- At most one rollout runs at a time.
CREATE UNIQUE INDEX agent_rollout_one_running_idx ON agent_rollout ((true)) WHERE status = 'running';
CREATE INDEX agent_release_created_idx ON agent_release (created_at);

CREATE TABLE agent_update_report (
  device_id uuid NOT NULL REFERENCES device(id), organization_id uuid NOT NULL,
  version text NOT NULL, outcome text NOT NULL CHECK (outcome IN ('updated','update_failed','rolled_back')),
  reported_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (device_id, version, outcome),
  FOREIGN KEY (organization_id, device_id) REFERENCES device (organization_id, id)
);
CREATE INDEX agent_update_report_version_idx ON agent_update_report (version, outcome);
ALTER TABLE agent_update_report ENABLE ROW LEVEL SECURITY;  ALTER TABLE agent_update_report FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON agent_update_report TO paddock_worker
  USING (organization_id = current_setting('paddock.org_id')::uuid)
  WITH CHECK (organization_id = current_setting('paddock.org_id')::uuid);

-- Rollout bucket of a device: FNV-1a (32 bit) of the canonical UUID text modulo 100. The gateway computes the same
-- value in Go (domain/agentrelease.Bucket); a test keeps both equal.
-- +goose StatementBegin
CREATE FUNCTION paddock_rollout_bucket(id uuid) RETURNS int LANGUAGE plpgsql IMMUTABLE STRICT AS $$
DECLARE
  h bigint := 2166136261;
  b bytea := convert_to(id::text, 'UTF8');
BEGIN
  FOR i IN 0 .. length(b) - 1 LOOP
    h := ((h # get_byte(b, i)) * 16777619) & 4294967295;
  END LOOP;
  RETURN (h % 100)::int;
END $$;
-- +goose StatementEnd

-- Counts for the rollout evaluation and the portal: active devices in the waves up to pct (all organizations),
-- and devices that reported an outcome for version. Nothing but counts leaves the function.
CREATE FUNCTION paddock_agent_rollout_stats(release text, pct int)
  RETURNS TABLE (eligible bigint, updated bigint, failed bigint)
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS
  $$ SELECT
       (SELECT count(*) FROM device WHERE state = 'active' AND paddock_rollout_bucket(id) < pct),
       (SELECT count(DISTINCT device_id) FROM agent_update_report WHERE version = release AND outcome = 'updated'),
       (SELECT count(DISTINCT device_id) FROM agent_update_report
          WHERE version = release AND outcome IN ('update_failed','rolled_back')) $$;
REVOKE ALL ON FUNCTION paddock_agent_rollout_stats(text, int) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION paddock_agent_rollout_stats(text, int) TO paddock_platform;

GRANT SELECT, INSERT, UPDATE ON agent_release, agent_artifact, agent_rollout TO paddock_platform;
GRANT SELECT, INSERT ON agent_update_report TO paddock_worker;

-- +goose Down
