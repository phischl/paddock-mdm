-- A LUKS escrow upload received before an issued Destroy of its device ended is refused (PDK-794, decisions-alpha9 item 31):
-- the crypto-shredding was decided, so a device that comes back online must not re-escrow a key that the backup copy
-- would then keep. escrow_refusal is the natural key that makes the refusal's audit event
-- (device.escrow_refused_destroyed) exactly once per escrow ID. It never holds key material: the refused
-- ciphertext or header facts are dropped, which is why the refusal is not a failed escrow_secret row.
-- Forward-only: there is no Down migration.
-- +goose Up

CREATE TABLE escrow_refusal (
  id uuid NOT NULL,                        -- escrow_id chosen by the device
  organization_id uuid NOT NULL, device_id uuid NOT NULL,
  kind text NOT NULL CHECK (kind IN ('luks_recovery_key','luks_header')),
  generation int NOT NULL CHECK (generation >= 1),
  reason text NOT NULL CHECK (reason IN ('destroy_issued')),
  created_at timestamptz NOT NULL,
  -- Scoped by organization: the device chooses the escrow ID, so a global key would let another tenant's invisible
  -- row suppress this organization's refusal event (PDK-794 review round 1).
  PRIMARY KEY (organization_id, id),
  FOREIGN KEY (organization_id, device_id) REFERENCES device (organization_id, id)
);
CREATE INDEX escrow_refusal_org_device_idx ON escrow_refusal (organization_id, device_id);

ALTER TABLE escrow_refusal ENABLE ROW LEVEL SECURITY;  ALTER TABLE escrow_refusal FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON escrow_refusal TO paddock_worker
  USING (organization_id = current_setting('paddock.org_id')::uuid)
  WITH CHECK (organization_id = current_setting('paddock.org_id')::uuid);

GRANT SELECT, INSERT ON escrow_refusal TO paddock_worker;

-- +goose Down
