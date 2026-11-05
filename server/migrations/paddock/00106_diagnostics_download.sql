-- Download of diagnostics bundles (ADR 0048 decision 4, plan M12 decision 4, PDK-749). key_version is the escrow-wrap
-- version the device wrapped the bundle's data key with (PDK-779, additive in POST /v1/diagnostics under ADR 0013);
-- NULL for an agent that did not report it. The escrow-reader reads, inside the organization of a decryption request,
-- only what it needs to unwrap a bundle's key for purpose diagnostics: the columns below, never the bundle's metadata
-- (reason, requester, hashes). Forward-only: there is no Down migration.
-- +goose Up

ALTER TABLE device_diagnostics ADD COLUMN key_version int CHECK (key_version >= 1);

CREATE POLICY escrow_reader ON device_diagnostics FOR SELECT TO paddock_escrow_reader
  USING (organization_id = current_setting('paddock.org_id')::uuid);
GRANT SELECT (id, organization_id, device_id, state, wrapped_dek, key_version) ON device_diagnostics TO paddock_escrow_reader;

-- A purged bundle stays due for the retention round until the presigned uploads issued before the purge have expired.
DROP INDEX device_diagnostics_expiry_idx;
CREATE INDEX device_diagnostics_expiry_idx ON device_diagnostics (expires_at) WHERE state IN ('stored','failed','expired','purged');

-- +goose Down
