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

-- +goose Down
