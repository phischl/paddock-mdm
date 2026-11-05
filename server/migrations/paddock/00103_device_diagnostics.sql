-- Diagnostics bundles (ADR 0048, plan M12 decision 3, PDK-747): one row per collect_status request, its ID the command
-- ID. requested → uploaded (the command result) → stored (the worker verified size and SHA-256) → expired (the
-- retention round deleted the object 7 days later) or purged; failed when the device refused, the upload did not
-- arrive or did not match; expired as well when the command expired unanswered. uploaded_at anchors the worker's
-- verification window. expires_at is when the object goes: 7 days after stored, or the upload window after a bundle
-- ended unstored (its key material goes at once, its object by the derived key; NULL once deleted). The api requests
-- and (PDK-749) downloads and purges; the worker records announcements, results, verification and retention. The
-- gateway has no grant: it publishes the announcement to the worker. Forward-only: there is no Down migration.
-- +goose Up
CREATE TABLE device_diagnostics (
  id uuid PRIMARY KEY,
  organization_id uuid NOT NULL, device_id uuid NOT NULL REFERENCES device (id),
  requested_by text NOT NULL, requested_at timestamptz NOT NULL DEFAULT now(),
  reason text NOT NULL CHECK (char_length(reason) BETWEEN 2 AND 500),
  state text NOT NULL CHECK (state IN ('requested','uploaded','stored','failed','expired','purged')),
  object_key text, size bigint, sha256 text, nonce bytea, wrapped_dek bytea,
  files int, truncated_entries text[] NOT NULL DEFAULT '{}', notified_sessions int,
  uploaded_at timestamptz, stored_at timestamptz, expires_at timestamptz, failed_reason text,
  download_count int NOT NULL DEFAULT 0, last_downloaded_at timestamptz, purged_at timestamptz,
  FOREIGN KEY (organization_id, device_id) REFERENCES device (organization_id, id)
);
CREATE INDEX device_diagnostics_org_device_idx ON device_diagnostics (organization_id, device_id, requested_at DESC);
CREATE INDEX device_diagnostics_expiry_idx ON device_diagnostics (expires_at) WHERE state IN ('stored','failed','expired');

ALTER TABLE device_diagnostics ENABLE ROW LEVEL SECURITY;
ALTER TABLE device_diagnostics FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON device_diagnostics TO paddock_api, paddock_worker
  USING (organization_id = current_setting('paddock.org_id')::uuid)
  WITH CHECK (organization_id = current_setting('paddock.org_id')::uuid);
GRANT SELECT, INSERT, UPDATE ON device_diagnostics TO paddock_api;
GRANT SELECT, UPDATE, DELETE ON device_diagnostics TO paddock_worker;

-- +goose Down
