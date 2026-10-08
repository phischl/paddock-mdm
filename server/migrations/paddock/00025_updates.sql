-- Update management (plan M5b decisions 1–3 and 9). Forward-only: there is no Down migration.
-- organization_update_settings: the schedule of daily security and regular updates and the staleness thresholds;
-- without a row the defaults apply. package_hold: packages held organization-wide (device_group_id NULL) or for a
-- device group, optionally pinned to a version. The api writes both, the compiler renders them into the updates
-- resource of v2 bundles, the worker reads the thresholds.
-- +goose Up

CREATE TABLE organization_update_settings (
  organization_id uuid PRIMARY KEY REFERENCES organization(id),
  security_daily_at text NOT NULL DEFAULT '03:00' CHECK (security_daily_at ~ '^([01][0-9]|2[0-3]):[0-5][0-9]$'),
  regular_schedule text NOT NULL DEFAULT 'Sat 04:00' CHECK (char_length(regular_schedule) BETWEEN 5 AND 64),
  regular_updates_enabled boolean NOT NULL DEFAULT true,
  max_random_delay_min int NOT NULL DEFAULT 60 CHECK (max_random_delay_min BETWEEN 0 AND 720),
  staleness_warning_h int NOT NULL DEFAULT 24 CHECK (staleness_warning_h BETWEEN 1 AND 720),
  staleness_critical_h int NOT NULL DEFAULT 168 CHECK (staleness_critical_h <= 2160),
  updated_at timestamptz NOT NULL DEFAULT now(),
  updated_by uuid,
  CHECK (staleness_critical_h > staleness_warning_h)
);
ALTER TABLE organization_update_settings ENABLE ROW LEVEL SECURITY;
ALTER TABLE organization_update_settings FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON organization_update_settings TO paddock_api, paddock_compiler, paddock_worker
  USING (organization_id = current_setting('paddock.org_id')::uuid)
  WITH CHECK (organization_id = current_setting('paddock.org_id')::uuid);
GRANT SELECT, INSERT, UPDATE ON organization_update_settings TO paddock_api;
GRANT SELECT ON organization_update_settings TO paddock_compiler, paddock_worker;

CREATE TABLE package_hold (
  id uuid PRIMARY KEY,
  organization_id uuid NOT NULL REFERENCES organization(id),
  device_group_id uuid REFERENCES device_group(id) ON DELETE CASCADE,
  package text NOT NULL CHECK (package ~ '^[a-z0-9][a-z0-9+.-]+$' AND char_length(package) <= 128),
  version text CHECK (version ~ '^[A-Za-z0-9.+:~-]+$' AND char_length(version) <= 128),
  reason text NOT NULL DEFAULT '' CHECK (char_length(reason) <= 500),
  created_by uuid,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE NULLS NOT DISTINCT (organization_id, device_group_id, package),
  FOREIGN KEY (organization_id, device_group_id) REFERENCES device_group (organization_id, id) ON DELETE CASCADE
);
CREATE INDEX package_hold_org_package_idx ON package_hold (organization_id, package);
CREATE INDEX package_hold_org_created_idx ON package_hold (organization_id, created_at);
ALTER TABLE package_hold ENABLE ROW LEVEL SECURITY;
ALTER TABLE package_hold FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON package_hold TO paddock_api, paddock_compiler
  USING (organization_id = current_setting('paddock.org_id')::uuid)
  WITH CHECK (organization_id = current_setting('paddock.org_id')::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON package_hold TO paddock_api;
GRANT SELECT ON package_hold TO paddock_compiler;

-- +goose Down
