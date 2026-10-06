-- Disk encryption escrow (plan M4b decisions 8–13). Forward-only: there is no Down migration.
-- escrow_secret also holds the LUKS recovery key of a device (RSA-OAEP ciphertext like the administrator password)
-- and the generations of its LUKS header: the sealed header lives in the bucket paddock-escrow under object_key; the
-- row keeps the wrapped header key, the nonce, and size and SHA-256 of the object. A header is pending until the
-- worker found the uploaded object with that size and SHA-256. The fleet list filters devices by the disk state of
-- their last check-in.
-- +goose Up

ALTER TABLE escrow_secret DROP CONSTRAINT escrow_secret_kind_check;
ALTER TABLE escrow_secret ADD CONSTRAINT escrow_secret_kind_check
  CHECK (kind IN ('admin_password','luks_recovery_key','luks_header'));
ALTER TABLE escrow_secret DROP CONSTRAINT escrow_secret_status_check;
ALTER TABLE escrow_secret ADD CONSTRAINT escrow_secret_status_check
  CHECK (status IN ('pending','stored','active','superseded','failed'));
ALTER TABLE escrow_secret ALTER COLUMN ciphertext DROP NOT NULL;
ALTER TABLE escrow_secret
  ADD COLUMN object_key text,
  ADD COLUMN wrapped_dek bytea CHECK (octet_length(wrapped_dek) BETWEEN 1 AND 4096),
  ADD COLUMN nonce bytea CHECK (octet_length(nonce) = 12),
  ADD COLUMN sha256 text CHECK (sha256 ~ '^[0-9a-f]{64}$'),
  ADD COLUMN size bigint CHECK (size BETWEEN 1 AND 33554432);
ALTER TABLE escrow_secret ADD CONSTRAINT escrow_secret_kind_fields CHECK (
  CASE WHEN kind = 'luks_header'
    THEN ciphertext IS NULL AND object_key IS NOT NULL AND wrapped_dek IS NOT NULL AND nonce IS NOT NULL
         AND sha256 IS NOT NULL AND size IS NOT NULL
    ELSE ciphertext IS NOT NULL AND object_key IS NULL AND wrapped_dek IS NULL AND nonce IS NULL AND sha256 IS NULL
         AND size IS NULL AND status <> 'pending'
  END);
CREATE INDEX escrow_secret_pending_idx ON escrow_secret (organization_id, created_at) WHERE status = 'pending';

CREATE INDEX device_status_disk_state_idx ON device_status (organization_id, (health -> 'disk' ->> 'state'));

-- +goose Down
