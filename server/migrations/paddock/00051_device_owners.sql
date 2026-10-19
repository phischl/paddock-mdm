-- Device owners (ADR 0037 decision 5, plan M8d decision 1, PDK-220): the users responsible for a device. Owners carry
-- no login or sudo rights and are not part of the bundle. Deleting a user removes it as an owner. Forward-only: there
-- is no Down migration.
-- +goose Up
CREATE TABLE device_owner (
  organization_id uuid NOT NULL, device_id uuid NOT NULL, user_id uuid NOT NULL,
  assigned_at timestamptz NOT NULL DEFAULT now(), assigned_by uuid,
  PRIMARY KEY (device_id, user_id),
  FOREIGN KEY (organization_id, device_id) REFERENCES device (organization_id, id),
  FOREIGN KEY (organization_id, user_id) REFERENCES app_user (organization_id, id) ON DELETE CASCADE
);
CREATE INDEX device_owner_user_idx ON device_owner (organization_id, user_id);

ALTER TABLE device_owner ENABLE ROW LEVEL SECURITY;
ALTER TABLE device_owner FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON device_owner TO paddock_api, paddock_worker
  USING (organization_id = current_setting('paddock.org_id')::uuid)
  WITH CHECK (organization_id = current_setting('paddock.org_id')::uuid);
GRANT SELECT, INSERT, DELETE ON device_owner TO paddock_api;
GRANT SELECT ON device_owner TO paddock_worker;

-- +goose Down
