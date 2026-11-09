-- Compile warnings (PDK-918, architect decisions A10-9 and A10-10): what the compiler had to shorten or drop from a
-- device's bundle against what an administrator assigned, so the portal can show it next to the assignment and the
-- device instead of a server log line only. The compiler replaces a device's rows with every compile of the device, so
-- the table holds the current state and never grows beyond the warnings of the latest compiles. The code is a stable
-- English identifier from the compiler (audience_truncated, flatpak_forbidden); params hold its values, never user
-- names. assignment_id and catalog_entry_id are not foreign keys: an assignment deleted after the compile's snapshot
-- must not fail the write, and its deletion recompiles the device, which drops the row. Forward-only: there is no Down
-- migration.
-- +goose Up
CREATE TABLE compile_warning (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid NOT NULL REFERENCES organization (id),
  device_id uuid NOT NULL,
  assignment_id uuid,
  catalog_entry_id uuid,
  code text NOT NULL CHECK (code ~ '^[a-z][a-z_]{0,63}$'),
  params jsonb NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(params) = 'object' AND octet_length(params::text) <= 1024),
  created_at timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (organization_id, device_id) REFERENCES device (organization_id, id) ON DELETE CASCADE
);
CREATE INDEX compile_warning_device ON compile_warning (organization_id, device_id);
CREATE INDEX compile_warning_assignment ON compile_warning (organization_id, assignment_id) WHERE assignment_id IS NOT NULL;

ALTER TABLE compile_warning ENABLE ROW LEVEL SECURITY;
ALTER TABLE compile_warning FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON compile_warning TO paddock_api, paddock_compiler
  USING (organization_id = current_setting('paddock.org_id')::uuid)
  WITH CHECK (organization_id = current_setting('paddock.org_id')::uuid);
GRANT SELECT ON compile_warning TO paddock_api;
GRANT SELECT, INSERT, DELETE ON compile_warning TO paddock_compiler;

-- +goose Down
