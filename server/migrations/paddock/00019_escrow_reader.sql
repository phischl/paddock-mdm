-- The escrow-reader role (plan M4b.1 decisions 5 and 6). Forward-only: there is no Down migration.
-- paddock_escrow_reader is created with the cluster (deploy/compose/postgres/init/10-roles.sh; existing installations
-- create it as described in docs/operations/escrow-reader.md). It reads, inside the organization of a decryption
-- request, the administrator of the step-up token, the device and the escrows to decrypt, and nothing else.
-- +goose Up

CREATE POLICY escrow_reader ON admin_account FOR SELECT TO paddock_escrow_reader
  USING (organization_id = current_setting('paddock.org_id')::uuid);
CREATE POLICY escrow_reader ON device FOR SELECT TO paddock_escrow_reader
  USING (organization_id = current_setting('paddock.org_id')::uuid);
CREATE POLICY escrow_reader ON escrow_secret FOR SELECT TO paddock_escrow_reader
  USING (organization_id = current_setting('paddock.org_id')::uuid);

GRANT SELECT ON admin_account, device, escrow_secret TO paddock_escrow_reader;

-- +goose Down
