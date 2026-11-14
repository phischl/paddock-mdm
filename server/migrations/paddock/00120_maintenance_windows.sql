-- Maintenance windows per device group and the urgent flag of a software assignment (PDK-809, plan M13c decisions 4
-- and 7; the plan's 00110 was taken). A device installs and removes the software of its policy only inside the union
-- of the windows of its device groups; an assignment marked urgent ignores the window. A group has at most one window:
-- days are ISO weekdays (1 = Monday), the window starts at start_minute after local midnight in the IANA timezone and
-- lasts duration_minutes, so it may run past midnight into the next day. The timezone is checked for its form here and
-- for being loadable by the api. The window goes with its device group. Forward-only: there is no Down migration.
-- +goose Up
CREATE TABLE device_group_maintenance_window (
  organization_id uuid NOT NULL REFERENCES organization (id),
  device_group_id uuid NOT NULL,
  days int[] NOT NULL CHECK (cardinality(days) BETWEEN 1 AND 7 AND days <@ ARRAY[1, 2, 3, 4, 5, 6, 7]),
  start_minute int NOT NULL CHECK (start_minute BETWEEN 0 AND 1439),
  duration_minutes int NOT NULL CHECK (duration_minutes BETWEEN 30 AND 1440),
  timezone text NOT NULL CHECK (timezone ~ '^[A-Za-z][A-Za-z0-9_+/-]{0,63}$'),
  updated_by uuid,
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id, device_group_id),
  FOREIGN KEY (organization_id, device_group_id) REFERENCES device_group (organization_id, id) ON DELETE CASCADE
);
CREATE UNIQUE INDEX device_group_maintenance_window_group ON device_group_maintenance_window (device_group_id);

ALTER TABLE device_group_maintenance_window ENABLE ROW LEVEL SECURITY;
ALTER TABLE device_group_maintenance_window FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON device_group_maintenance_window TO paddock_api, paddock_compiler
  USING (organization_id = current_setting('paddock.org_id')::uuid)
  WITH CHECK (organization_id = current_setting('paddock.org_id')::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON device_group_maintenance_window TO paddock_api;
GRANT SELECT ON device_group_maintenance_window TO paddock_compiler;

ALTER TABLE software_assignment ADD COLUMN urgent boolean NOT NULL DEFAULT false;

-- Waves against maintenance windows (architect decision A10-16). A wave advances only once min_wave_minutes passed
-- since the first device that joined in the wave applied, and once the applied share of those devices reaches
-- wave_success_threshold_percent or none of them still waits for its window. The worker records the first apply, the
-- count it last saw, the devices it last saw outstanding (waiting for a window or awaiting a retry after a resume, A10-19)
-- and when the wave last made progress; stall_warned_at keeps the stall warning to once per stall. The
-- settings are copied into a rollout when it starts, as the other rollout parameters are.
ALTER TABLE organization_rollout_settings
  ADD COLUMN wave_success_threshold_percent int NOT NULL DEFAULT 90 CHECK (wave_success_threshold_percent BETWEEN 1 AND 100),
  ADD COLUMN stall_warning_hours int NOT NULL DEFAULT 24 CHECK (stall_warning_hours BETWEEN 1 AND 720);
ALTER TABLE config_rollout
  ADD COLUMN wave_success_threshold_percent int NOT NULL DEFAULT 90 CHECK (wave_success_threshold_percent BETWEEN 1 AND 100),
  ADD COLUMN stall_warning_hours int NOT NULL DEFAULT 24 CHECK (stall_warning_hours BETWEEN 1 AND 720),
  ADD COLUMN wave_first_applied_at timestamptz,
  ADD COLUMN wave_applied int NOT NULL DEFAULT 0 CHECK (wave_applied >= 0),
  ADD COLUMN wave_progress_at timestamptz NOT NULL DEFAULT now(),
  ADD COLUMN wave_outstanding int NOT NULL DEFAULT 0 CHECK (wave_outstanding >= 0),
  ADD COLUMN stall_warned_at timestamptz;

-- +goose Down
