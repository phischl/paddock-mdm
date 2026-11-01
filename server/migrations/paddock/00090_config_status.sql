-- Apply status of a device (plan M11 decisions 12 and 13, PDK-151): what the agent reported for each bundle version
-- (device_bundle_report) and for each resource of the bundle (device_resource_status). The agent's apply report is
-- status, not evidence: the audit event keeps only what it always carried. Retention class per ADR 0032 §1, row
-- device_bundle_report/device_resource_status: current state only, overwritten by the device's next report; rows of a
-- retired device stay with the device record. The plan names this file 00045; that number was taken.
-- Forward-only: there is no Down migration.
-- +goose Up
CREATE TABLE device_bundle_report (
  device_id uuid NOT NULL REFERENCES device (id), organization_id uuid NOT NULL,
  version bigint NOT NULL, outcome text NOT NULL CHECK (outcome IN ('applied', 'rejected')),
  mode text NOT NULL DEFAULT 'enforce' CHECK (mode IN ('enforce', 'report_only')),
  changed int NOT NULL DEFAULT 0, error_count int NOT NULL DEFAULT 0, reason text,
  occurred_at timestamptz NOT NULL, recorded_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (device_id, version),
  FOREIGN KEY (organization_id, device_id) REFERENCES device (organization_id, id)
);
CREATE INDEX device_bundle_report_org_occurred_idx ON device_bundle_report (organization_id, occurred_at);

CREATE TABLE device_resource_status (
  device_id uuid NOT NULL REFERENCES device (id), organization_id uuid NOT NULL,
  resource_id text NOT NULL CHECK (char_length(resource_id) <= 512),
  status text NOT NULL CHECK (status IN ('applied', 'failed', 'pending', 'drift_corrected')),
  message text NOT NULL DEFAULT '' CHECK (char_length(message) <= 1024),
  changes text[] NOT NULL DEFAULT '{}',
  bundle_version bigint NOT NULL, occurred_at timestamptz NOT NULL,
  PRIMARY KEY (device_id, resource_id),
  FOREIGN KEY (organization_id, device_id) REFERENCES device (organization_id, id)
);
CREATE INDEX device_resource_status_org_resource_idx ON device_resource_status (organization_id, resource_id, status);
CREATE INDEX device_resource_status_org_status_idx ON device_resource_status (organization_id, status);

ALTER TABLE device_bundle_report ENABLE ROW LEVEL SECURITY;
ALTER TABLE device_bundle_report FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON device_bundle_report TO paddock_api, paddock_worker
  USING (organization_id = current_setting('paddock.org_id')::uuid)
  WITH CHECK (organization_id = current_setting('paddock.org_id')::uuid);
ALTER TABLE device_resource_status ENABLE ROW LEVEL SECURITY;
ALTER TABLE device_resource_status FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON device_resource_status TO paddock_api, paddock_worker
  USING (organization_id = current_setting('paddock.org_id')::uuid)
  WITH CHECK (organization_id = current_setting('paddock.org_id')::uuid);
GRANT SELECT ON device_bundle_report, device_resource_status TO paddock_api;
GRANT SELECT, INSERT, UPDATE, DELETE ON device_bundle_report, device_resource_status TO paddock_worker;

-- +goose Down
