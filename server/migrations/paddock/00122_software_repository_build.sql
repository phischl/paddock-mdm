-- The worker's build of the organizations' Paddock repositories (plan M13c decision 13, ADR 0050 decision 3, PDK-813).
-- The worker generates an organization's signing key on the first build and a new one when an administrator rotates
-- it: the api only queues the rotation in key_rotation_requested_at, because software-repo-wrap, the Transit key of the
-- signing keys, is the worker's alone (M13c amendment 2026-11-09 (PDK-812)). The worker maintains the system source of
-- the repository (kind paddock) with the current public key, so it inserts and updates that one row of software_source
-- and no other. After a rotation the previous private key stays, Transit-wrapped like the current one, until
-- previous_retired_at plus 30 days: the worker signs the index with both keys meanwhile, so a device that still has the
-- old key keeps verifying the repository (§3.8 L5, M13c amendment 2026-11-09 (PDK-813, fix round 1)). Forward-only:
-- there is no Down migration.
-- +goose Up
ALTER TABLE software_repository ADD COLUMN key_rotation_requested_at timestamptz,
  ADD COLUMN previous_private_ciphertext text;

CREATE POLICY worker_paddock_source ON software_source TO paddock_worker
  USING (organization_id = current_setting('paddock.org_id')::uuid AND kind = 'paddock')
  WITH CHECK (organization_id = current_setting('paddock.org_id')::uuid AND kind = 'paddock');
GRANT SELECT, INSERT, UPDATE ON software_source TO paddock_worker;

-- +goose Down
