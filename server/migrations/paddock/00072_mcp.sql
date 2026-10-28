-- Per-user MCP write opt-in and MCP policies per organization and for the platform (ADR 0044, plan M14).
-- organization_mcp_settings is organization data (RLS enabled and forced, policy on paddock.org_id).
-- platform_mcp_settings is platform-scoped data without an organization_id and therefore without RLS: reachable only
-- through the paddock_platform pool, listed in the RLS lint allow list. MCP sessions live in Valkey, not here.
-- action.source keeps the audit source an action was started with, so that the reaper finalizes a stuck action of an
-- MCP session with source mcp (plan M14 amendment 2026-10-28). NULL marks rows written before this migration; the
-- reaper derives their source from the actor type as before.
-- Forward-only: there is no Down migration.
-- +goose Up
ALTER TABLE admin_account ADD COLUMN mcp_write_enabled_at timestamptz;
ALTER TABLE platform_admin ADD COLUMN mcp_write_enabled_at timestamptz;
ALTER TABLE action ADD COLUMN source text
  CHECK (source IN ('portal', 'platform', 'system', 'device', 'api', 'mcp'));

CREATE TABLE organization_mcp_settings (
  organization_id    uuid PRIMARY KEY REFERENCES organization(id),
  enabled            boolean NOT NULL DEFAULT false,
  write_enabled      boolean NOT NULL DEFAULT false,
  mode               text NOT NULL DEFAULT 'all' CHECK (mode IN ('all', 'selected')),
  allowed_operations text[] NOT NULL DEFAULT '{}' CHECK (cardinality(allowed_operations) <= 500),
  updated_at         timestamptz NOT NULL DEFAULT now(),
  updated_by         uuid,
  CHECK (mode = 'selected' OR cardinality(allowed_operations) = 0)
);
ALTER TABLE organization_mcp_settings ENABLE ROW LEVEL SECURITY;
ALTER TABLE organization_mcp_settings FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON organization_mcp_settings TO paddock_api
  USING (organization_id = current_setting('paddock.org_id')::uuid)
  WITH CHECK (organization_id = current_setting('paddock.org_id')::uuid);
GRANT SELECT, INSERT, UPDATE ON organization_mcp_settings TO paddock_api;

CREATE TABLE platform_mcp_settings (
  singleton          boolean PRIMARY KEY DEFAULT true CHECK (singleton),
  enabled            boolean NOT NULL DEFAULT false,
  write_enabled      boolean NOT NULL DEFAULT false,
  mode               text NOT NULL DEFAULT 'all' CHECK (mode IN ('all', 'selected')),
  allowed_operations text[] NOT NULL DEFAULT '{}' CHECK (cardinality(allowed_operations) <= 500),
  updated_at         timestamptz NOT NULL DEFAULT now(),
  updated_by         uuid REFERENCES platform_admin(id),
  CHECK (mode = 'selected' OR cardinality(allowed_operations) = 0)
);
GRANT SELECT, INSERT, UPDATE ON platform_mcp_settings TO paddock_platform;
