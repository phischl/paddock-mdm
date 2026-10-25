-- Audited role membership (plan M8b decision 34, PDK-111): the worker keeps the last seen members of every Paddock role
-- group in Authentik and the Authentik superusers, and when an organization (or the platform) had its first snapshot,
-- so that every later difference is recorded as admin.role_granted or admin.role_revoked. organization_role_member and
-- organization_role_snapshot are organization data: RLS enabled and forced, policy on paddock.org_id, worker only.
-- platform_role_member and platform_role_snapshot are platform-scoped data without an organization_id, and therefore
-- without RLS: they are reachable only through the paddock_platform pool (the only role with a grant), never with an
-- organization context. The API has no grant on any of them: the tables are evidence the worker writes. The plan
-- names this file 00045; that number was taken.
-- Forward-only: there is no Down migration.
-- +goose Up
CREATE TABLE organization_role_member (
  organization_id uuid NOT NULL REFERENCES organization (id),
  role text NOT NULL CHECK (role IN ('org_admin', 'org_operator', 'org_auditor')),
  authentik_pk text NOT NULL, username text NOT NULL, first_seen_at timestamptz NOT NULL,
  PRIMARY KEY (organization_id, role, authentik_pk)
);
CREATE TABLE organization_role_snapshot (
  organization_id uuid PRIMARY KEY REFERENCES organization (id), taken_at timestamptz NOT NULL
);
CREATE TABLE platform_role_member (
  role text NOT NULL CHECK (role IN ('platform_admin', 'authentik_superuser')), authentik_pk text NOT NULL,
  username text NOT NULL, first_seen_at timestamptz NOT NULL, PRIMARY KEY (role, authentik_pk)
);
CREATE TABLE platform_role_snapshot (
  singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton), taken_at timestamptz NOT NULL
);

ALTER TABLE organization_role_member ENABLE ROW LEVEL SECURITY;
ALTER TABLE organization_role_member FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON organization_role_member TO paddock_worker
  USING (organization_id = current_setting('paddock.org_id')::uuid)
  WITH CHECK (organization_id = current_setting('paddock.org_id')::uuid);
ALTER TABLE organization_role_snapshot ENABLE ROW LEVEL SECURITY;
ALTER TABLE organization_role_snapshot FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON organization_role_snapshot TO paddock_worker
  USING (organization_id = current_setting('paddock.org_id')::uuid)
  WITH CHECK (organization_id = current_setting('paddock.org_id')::uuid);
GRANT SELECT, INSERT, DELETE ON organization_role_member TO paddock_worker;
GRANT SELECT, INSERT ON organization_role_snapshot TO paddock_worker;
GRANT SELECT, INSERT, DELETE ON platform_role_member TO paddock_platform;
GRANT SELECT, INSERT ON platform_role_snapshot TO paddock_platform;

-- +goose Down
