-- Administrator accounts that lost their role or were deactivated in the identity provider (plan M8s decisions 20–22,
-- ADR 0034 decision 5): disabled_at is set by the step-up check of the api and by the worker round admin-accounts, and
-- cleared by the next successful login. The worker reads and updates the accounts of one organization at a time, in
-- that organization's context. Forward-only: there is no Down migration.
-- +goose Up
ALTER TABLE admin_account ADD COLUMN disabled_at timestamptz;

CREATE POLICY tenant_worker ON admin_account FOR ALL TO paddock_worker
  USING (organization_id = current_setting('paddock.org_id')::uuid)
  WITH CHECK (organization_id = current_setting('paddock.org_id')::uuid);
GRANT SELECT, UPDATE (role, disabled_at) ON admin_account TO paddock_worker;
