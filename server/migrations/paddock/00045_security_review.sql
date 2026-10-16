-- Review of existing data (ADR 0034 decision 7, plan M8s decision 24): an effectively Full permission profile and a
-- managed file on a sensitive path record when and by whom an organization administrator confirmed them with a
-- step-up. Rows created before the step-up rule covered them keep NULL and are listed by GET /api/v1/security-review
-- until confirmed; nothing is withdrawn. No backfill. Forward-only: there is no Down migration.
-- +goose Up
ALTER TABLE permission_profile
  ADD COLUMN root_grant_confirmed_at timestamptz,
  ADD COLUMN root_grant_confirmed_by uuid REFERENCES admin_account(id) ON DELETE SET NULL;
ALTER TABLE managed_file
  ADD COLUMN sensitive_confirmed_at timestamptz,
  ADD COLUMN sensitive_confirmed_by uuid REFERENCES admin_account(id) ON DELETE SET NULL;

-- paddock-server admin security-review runs with the worker's role (plan M8s decision 28) and classifies the managed
-- files of every organization; the worker could read profiles and assignments already.
GRANT SELECT ON managed_file TO paddock_worker;
ALTER POLICY tenant ON managed_file TO paddock_api, paddock_compiler, paddock_worker;

-- Operator roots of the managed files (ADR 0034 amendment 2026-10-16, plan M8s decision 7c): below these directory
-- prefixes an operator may manage files without a step-up; everywhere else (outside the denied paths) only an
-- organization administrator with a step-up. Empty by default; without a row the list is empty. The worker reads it
-- for paddock-server admin security-review.
CREATE TABLE organization_managed_file_settings (
  organization_id uuid PRIMARY KEY REFERENCES organization(id),
  managed_file_operator_roots text[] NOT NULL DEFAULT '{}' CHECK (cardinality(managed_file_operator_roots) <= 50),
  updated_at timestamptz NOT NULL DEFAULT now(),
  updated_by uuid
);
ALTER TABLE organization_managed_file_settings ENABLE ROW LEVEL SECURITY;
ALTER TABLE organization_managed_file_settings FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON organization_managed_file_settings TO paddock_api, paddock_worker
  USING (organization_id = current_setting('paddock.org_id')::uuid)
  WITH CHECK (organization_id = current_setting('paddock.org_id')::uuid);
GRANT SELECT, INSERT, UPDATE ON organization_managed_file_settings TO paddock_api;
GRANT SELECT ON organization_managed_file_settings TO paddock_worker;

-- +goose Down
