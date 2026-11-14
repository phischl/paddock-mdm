-- Retired organizations (plan M17 decision 16, ADR 0052 decision 6): the audit writer records the final verification
-- of a deleted organization's chain here, then skips the organization in the nightly verification and writes no
-- further events into it. The organization's index, objects and manifests stay under their normal retention.
-- Forward-only: there is no Down migration.
-- +goose Up
CREATE TABLE audit_org_retired (
  organization_id   uuid PRIMARY KEY,
  retired_at        timestamptz NOT NULL DEFAULT now(),
  final_verified_at timestamptz,
  final_outcome     text CHECK (final_outcome IN ('verified','failed'))
);
ALTER TABLE audit_org_retired ENABLE ROW LEVEL SECURITY; ALTER TABLE audit_org_retired FORCE ROW LEVEL SECURITY;
CREATE POLICY writer ON audit_org_retired TO paddock_audit_writer USING (true) WITH CHECK (true);
GRANT SELECT, INSERT, UPDATE ON audit_org_retired TO paddock_audit_writer;
-- No grant to paddock_audit_reader.

-- +goose Down
