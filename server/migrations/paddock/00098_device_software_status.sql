-- What a device reports about the catalog entries it manages (plan M13a §3.4, PDK-411): one row per device and entry,
-- replaced by the device's next report that carries its items; current state only (ADR 0032 §1), so a row follows the
-- device record and its entry. The entry is an organization-bound foreign key, so a device cannot report on another
-- organization's entry. The worker writes the rows with its heartbeat and needs to see which entries exist, but only
-- their IDs. software_digest is the digest of the last stored report. The plan names this file 00070; numbers 00097
-- (device platform, PDK-695) and 00098 were assigned by plan M13a amendment 2026-11-02. Forward-only: there is no Down
-- migration.
-- +goose Up
CREATE TABLE device_software_status (
  device_id uuid NOT NULL REFERENCES device (id),
  organization_id uuid NOT NULL,
  catalog_entry_id uuid NOT NULL,
  package text NOT NULL CHECK (char_length(package) BETWEEN 1 AND 255),
  intent text NOT NULL CHECK (char_length(intent) BETWEEN 1 AND 16),
  state text NOT NULL CHECK (state IN ('installed', 'held', 'absent', 'pending', 'failed')),
  version text NOT NULL DEFAULT '' CHECK (char_length(version) <= 128),
  reason text NOT NULL DEFAULT '' CHECK (char_length(reason) <= 64),
  error text NOT NULL DEFAULT '' CHECK (char_length(error) <= 200),
  reported_at timestamptz NOT NULL,
  PRIMARY KEY (device_id, catalog_entry_id),
  FOREIGN KEY (organization_id, device_id) REFERENCES device (organization_id, id),
  FOREIGN KEY (organization_id, catalog_entry_id) REFERENCES software_catalog_entry (organization_id, id) ON DELETE CASCADE
);
CREATE INDEX device_software_status_org_entry ON device_software_status (organization_id, catalog_entry_id, state);

ALTER TABLE device_software_status ENABLE ROW LEVEL SECURITY;
ALTER TABLE device_software_status FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON device_software_status TO paddock_api, paddock_worker
  USING (organization_id = current_setting('paddock.org_id')::uuid)
  WITH CHECK (organization_id = current_setting('paddock.org_id')::uuid);
GRANT SELECT ON device_software_status TO paddock_api;
GRANT SELECT, INSERT, UPDATE, DELETE ON device_software_status TO paddock_worker;

CREATE POLICY tenant_worker ON software_catalog_entry FOR SELECT TO paddock_worker
  USING (organization_id = current_setting('paddock.org_id')::uuid);
GRANT SELECT (id, organization_id) ON software_catalog_entry TO paddock_worker;

ALTER TABLE device_status ADD COLUMN software_digest text NOT NULL DEFAULT '';

-- +goose Down
