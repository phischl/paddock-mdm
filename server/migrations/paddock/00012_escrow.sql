-- Escrowed secrets (plan M4a decision 11, shared with M4b). Forward-only: there is no Down migration. The worker
-- stores what devices upload through /v1/escrow and activates a generation once the device confirms it; the api
-- reads ciphertexts for a reveal and decrypts them with OpenBao (escrow-wrap), never stores plaintext.
-- +goose Up

CREATE TABLE escrow_secret (
  id uuid PRIMARY KEY,                     -- escrow_id chosen by the device
  organization_id uuid NOT NULL, device_id uuid NOT NULL REFERENCES device(id),
  kind text NOT NULL CHECK (kind IN ('admin_password')),
  generation int NOT NULL CHECK (generation >= 1),
  status text NOT NULL CHECK (status IN ('stored','active','superseded','failed')),
  ciphertext bytea NOT NULL CHECK (octet_length(ciphertext) BETWEEN 1 AND 4096),
  key_version int NOT NULL CHECK (key_version >= 1),
  created_at timestamptz NOT NULL DEFAULT now(), activated_at timestamptz,
  UNIQUE (device_id, kind, generation),
  FOREIGN KEY (organization_id, device_id) REFERENCES device (organization_id, id)
);
CREATE INDEX escrow_secret_org_device_idx ON escrow_secret (organization_id, device_id, kind, generation);

ALTER TABLE escrow_secret ENABLE ROW LEVEL SECURITY;  ALTER TABLE escrow_secret FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON escrow_secret TO paddock_api, paddock_worker
  USING (organization_id = current_setting('paddock.org_id')::uuid)
  WITH CHECK (organization_id = current_setting('paddock.org_id')::uuid);

GRANT SELECT ON escrow_secret TO paddock_api;
GRANT SELECT, INSERT, UPDATE ON escrow_secret TO paddock_worker;

-- +goose Down
