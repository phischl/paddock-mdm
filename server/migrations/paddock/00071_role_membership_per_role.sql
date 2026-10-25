-- Audited role membership, review of PDK-111 (plan M8b amendment 2026-10-25, decisions 34 and 35): the baseline is kept
-- per role, so a role that cannot be read does not leave the other roles in baseline, and a member is only revoked
-- once two consecutive successful listings missed it. The snapshot tables are keyed by role. A snapshot taken before
-- this migration covered every role of its scope (it was written only after all roles compared), so it is copied to
-- each role. The member tables gain missing_since, set by the first listing that misses a member and cleared when a
-- listing shows it again; the worker (organizations) and the platform pool (platform) may update it. RLS of the
-- organization tables is unchanged (00070); the platform tables stay platform-scoped, reachable only through the
-- paddock_platform pool.
-- Forward-only: there is no Down migration.
-- +goose Up
ALTER TABLE organization_role_member ADD COLUMN missing_since timestamptz;
ALTER TABLE platform_role_member ADD COLUMN missing_since timestamptz;

ALTER TABLE organization_role_snapshot DROP CONSTRAINT organization_role_snapshot_pkey;
ALTER TABLE organization_role_snapshot ADD COLUMN role text NOT NULL DEFAULT 'org_admin';
INSERT INTO organization_role_snapshot (organization_id, role, taken_at)
  SELECT s.organization_id, r.role, s.taken_at FROM organization_role_snapshot s
  CROSS JOIN (VALUES ('org_operator'), ('org_auditor')) AS r (role);
ALTER TABLE organization_role_snapshot ALTER COLUMN role DROP DEFAULT;
ALTER TABLE organization_role_snapshot ADD CONSTRAINT organization_role_snapshot_role_check
  CHECK (role IN ('org_admin', 'org_operator', 'org_auditor'));
ALTER TABLE organization_role_snapshot ADD PRIMARY KEY (organization_id, role);

ALTER TABLE platform_role_snapshot ADD COLUMN role text NOT NULL DEFAULT 'platform_admin';
ALTER TABLE platform_role_snapshot DROP CONSTRAINT platform_role_snapshot_pkey;
ALTER TABLE platform_role_snapshot DROP COLUMN singleton;
INSERT INTO platform_role_snapshot (role, taken_at) SELECT 'authentik_superuser', taken_at FROM platform_role_snapshot;
ALTER TABLE platform_role_snapshot ALTER COLUMN role DROP DEFAULT;
ALTER TABLE platform_role_snapshot ADD CONSTRAINT platform_role_snapshot_role_check
  CHECK (role IN ('platform_admin', 'authentik_superuser'));
ALTER TABLE platform_role_snapshot ADD PRIMARY KEY (role);

GRANT UPDATE (missing_since) ON organization_role_member TO paddock_worker;
GRANT UPDATE (missing_since) ON platform_role_member TO paddock_platform;

-- +goose Down
