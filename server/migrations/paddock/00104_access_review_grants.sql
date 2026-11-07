-- Access review (plan M12 decision 24, PDK-754): the API reads the worker's role-membership snapshot of the caller's
-- organization for the access review report. The grant is read-only: the members and their snapshot times stay
-- evidence the worker writes. The plan names this file 00103; that number went to a pending change. A policy named
-- tenant exists on both tables for the worker (00070), hence tenant_api_read. The platform report needs no grant: the
-- platform pool reads platform_role_member already.
-- Forward-only: there is no Down migration.
-- +goose Up
CREATE POLICY tenant_api_read ON organization_role_member FOR SELECT TO paddock_api
  USING (organization_id = current_setting('paddock.org_id')::uuid);
CREATE POLICY tenant_api_read ON organization_role_snapshot FOR SELECT TO paddock_api
  USING (organization_id = current_setting('paddock.org_id')::uuid);
GRANT SELECT ON organization_role_member, organization_role_snapshot TO paddock_api;

-- +goose Down
