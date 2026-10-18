-- Login history (ADR 0037 decision 6, ADR 0032 amendment 2026-10-17, plan M8d decision 14, PDK-223): off by default;
-- while an organization has it on, every session start a device reports is stored with user name and time, and the
-- worker deletes rows older than login_history_days. Switching it off deletes every row of the organization at once.
-- Forward-only: there is no Down migration.
-- +goose Up
ALTER TABLE organization_login_settings
  ADD COLUMN login_history_enabled boolean NOT NULL DEFAULT false,
  ADD COLUMN login_history_days int NOT NULL DEFAULT 90 CHECK (login_history_days BETWEEN 7 AND 365);

CREATE TABLE device_login_event (
  id uuid PRIMARY KEY, organization_id uuid NOT NULL, device_id uuid NOT NULL REFERENCES device(id),
  username text NOT NULL, at timestamptz NOT NULL,
  UNIQUE (device_id, username, at),
  FOREIGN KEY (organization_id, device_id) REFERENCES device (organization_id, id)
);
CREATE INDEX device_login_event_device_at_idx ON device_login_event (organization_id, device_id, at DESC);
CREATE INDEX device_login_event_org_at_idx ON device_login_event (organization_id, at);

ALTER TABLE device_login_event ENABLE ROW LEVEL SECURITY;
ALTER TABLE device_login_event FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON device_login_event TO paddock_api, paddock_worker
  USING (organization_id = current_setting('paddock.org_id')::uuid)
  WITH CHECK (organization_id = current_setting('paddock.org_id')::uuid);
GRANT SELECT, DELETE ON device_login_event TO paddock_api;
GRANT SELECT, INSERT, DELETE ON device_login_event TO paddock_worker;

-- +goose Down
