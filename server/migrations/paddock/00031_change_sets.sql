-- Change sets (plan M6c decision 17). Forward-only: there is no Down migration.
-- Every non-empty apply of PUT /api/v1/config records what it changed: the actor, the source and the plan. Change
-- sets are evidence next to the audit event config.applied; they are never updated or deleted.
-- +goose Up

CREATE TABLE change_set (
  id              uuid PRIMARY KEY,
  organization_id uuid NOT NULL REFERENCES organization(id),
  applied_at      timestamptz NOT NULL DEFAULT now(),
  actor           jsonb NOT NULL,
  source          text NOT NULL CHECK (source IN ('session', 'api_token')),
  created_n       int NOT NULL,
  updated_n       int NOT NULL,
  deleted_n       int NOT NULL,
  sections        text[] NOT NULL,
  plan            jsonb NOT NULL
);
CREATE INDEX change_set_org_applied_idx ON change_set (organization_id, applied_at);
ALTER TABLE change_set ENABLE ROW LEVEL SECURITY;
ALTER TABLE change_set FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON change_set TO paddock_api
  USING (organization_id = current_setting('paddock.org_id')::uuid)
  WITH CHECK (organization_id = current_setting('paddock.org_id')::uuid);
GRANT SELECT, INSERT ON change_set TO paddock_api;
