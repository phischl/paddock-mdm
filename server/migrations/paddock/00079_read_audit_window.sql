-- server/migrations/paddock/00079_read_audit_window.sql
-- Coalescing keys of read-access audit events (ADR 0032 §4, plan M10 decision 18). Forward-only.
-- +goose Up
CREATE TABLE read_audit_window (
  organization_id uuid NOT NULL REFERENCES organization(id),
  actor_id text NOT NULL,
  code text NOT NULL,
  target_id text NOT NULL DEFAULT '',
  window_start timestamptz NOT NULL,
  PRIMARY KEY (organization_id, actor_id, code, target_id, window_start)
);
CREATE INDEX read_audit_window_start_idx ON read_audit_window (organization_id, window_start);
ALTER TABLE read_audit_window ENABLE ROW LEVEL SECURITY;
ALTER TABLE read_audit_window FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON read_audit_window TO paddock_api, paddock_worker
  USING (organization_id = current_setting('paddock.org_id')::uuid)
  WITH CHECK (organization_id = current_setting('paddock.org_id')::uuid);
GRANT SELECT, INSERT ON read_audit_window TO paddock_api;
GRANT SELECT, DELETE ON read_audit_window TO paddock_worker;
-- +goose Down
