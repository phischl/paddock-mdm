-- Staged configuration rollouts, settings per organization (plan M11 decisions 23 and 24). Forward-only: there is no
-- Down migration. Without a row the defaults apply (rollouts off). The api writes the row, the compiler and the worker
-- read it. Changing it never touches a running rollout, whose parameters are copied when it starts.
-- +goose Up

CREATE TABLE organization_rollout_settings (
  organization_id uuid PRIMARY KEY REFERENCES organization(id),
  enabled boolean NOT NULL DEFAULT false,
  waves int[] NOT NULL DEFAULT '{1,10,50,100}',
  min_wave_minutes int NOT NULL DEFAULT 60 CHECK (min_wave_minutes >= 1),
  failure_threshold_percent int NOT NULL DEFAULT 2 CHECK (failure_threshold_percent BETWEEN 0 AND 100),
  failure_threshold_min int NOT NULL DEFAULT 3 CHECK (failure_threshold_min >= 0),
  canary_device_group_id uuid,
  updated_at timestamptz NOT NULL DEFAULT now(),
  updated_by uuid,
  -- A composite key keeps the group inside the organization; SET NULL names the column so the organization stays.
  FOREIGN KEY (organization_id, canary_device_group_id) REFERENCES device_group (organization_id, id)
    ON DELETE SET NULL (canary_device_group_id)
);
ALTER TABLE organization_rollout_settings ENABLE ROW LEVEL SECURITY;
ALTER TABLE organization_rollout_settings FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON organization_rollout_settings TO paddock_api, paddock_compiler, paddock_worker
  USING (organization_id = current_setting('paddock.org_id')::uuid)
  WITH CHECK (organization_id = current_setting('paddock.org_id')::uuid);
GRANT SELECT, INSERT, UPDATE ON organization_rollout_settings TO paddock_api;
GRANT SELECT ON organization_rollout_settings TO paddock_compiler, paddock_worker;
