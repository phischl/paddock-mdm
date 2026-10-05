-- Device commands (plan M4a decision 1). Forward-only: there is no Down migration. The api issues commands, the
-- worker signs and delivers them (Valkey cmd:<device_id>), records delivery and results and expires them.
-- +goose Up

CREATE TABLE device_command (
  id uuid PRIMARY KEY, organization_id uuid NOT NULL, device_id uuid NOT NULL REFERENCES device(id),
  type text NOT NULL, params jsonb NOT NULL DEFAULT '{}',
  status text NOT NULL CHECK (status IN ('pending','delivered','succeeded','failed','expired','cancelled')),
  issued_by uuid, issued_at timestamptz NOT NULL DEFAULT now(), expires_at timestamptz NOT NULL,
  -- Decision 17: a command scheduled for later (rotation after a reveal) is published to devices only when due.
  not_before timestamptz,
  delivered_at timestamptz, finished_at timestamptz, result jsonb,
  CHECK (expires_at > issued_at),
  FOREIGN KEY (organization_id, device_id) REFERENCES device (organization_id, id)
);
CREATE INDEX device_command_org_device_issued_idx ON device_command (organization_id, device_id, issued_at);
CREATE INDEX device_command_open_idx ON device_command (organization_id, expires_at) WHERE status IN ('pending','delivered');

ALTER TABLE device_command ENABLE ROW LEVEL SECURITY;  ALTER TABLE device_command FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON device_command TO paddock_api, paddock_worker
  USING (organization_id = current_setting('paddock.org_id')::uuid)
  WITH CHECK (organization_id = current_setting('paddock.org_id')::uuid);

GRANT SELECT, INSERT ON device_command TO paddock_api;
GRANT SELECT, UPDATE ON device_command TO paddock_worker;

-- +goose Down
