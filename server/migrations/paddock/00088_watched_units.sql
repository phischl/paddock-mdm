-- Presence policy (plan M9 decision 38, PDK-130): the systemd units of third-party agents (an EDR or SIEM agent such as
-- wazuh-agent.service) an organization wants reported when they stop. Paddock never deploys, starts or restarts them;
-- the list travels in the bundle and the agent only watches (PDK-131). Forward-only: there is no Down migration.
-- +goose Up
CREATE TABLE watched_unit (
  organization_id uuid NOT NULL REFERENCES organization(id),
  unit text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id, unit)
);
ALTER TABLE watched_unit ENABLE ROW LEVEL SECURITY;
ALTER TABLE watched_unit FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON watched_unit TO paddock_api, paddock_compiler
  USING (organization_id = current_setting('paddock.org_id')::uuid)
  WITH CHECK (organization_id = current_setting('paddock.org_id')::uuid);
GRANT SELECT, INSERT, DELETE ON watched_unit TO paddock_api;
GRANT SELECT ON watched_unit TO paddock_compiler;

-- +goose Down
