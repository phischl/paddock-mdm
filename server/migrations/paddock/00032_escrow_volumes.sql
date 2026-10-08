-- Header escrow of every LUKS volume (PDK-009, plan M4c.1 amendment 2026-10-08). Forward-only: there is no Down
-- migration.
-- escrow_secret.volume is the LUKS UUID of the volume a header generation belongs to. Headers escrowed before carry
-- none: they are the root volume's, their object keys (org/<org>/devices/<dev>/luks-header/<generation>.bin) stay as
-- recorded, and the worker sets the root volume's UUID on them with the device's first check-in that reports it;
-- until then they are matched as the root volume's (the database cannot know the UUID here).
-- revocation_request.volumes are the volumes with a confirmed header escrow that a Lock or self-lock token carries;
-- a self-lock token is re-issued when that set changes. The revocation-issuer reads device_status for the
-- revoke_capabilities of the device's paddock-revoke (a build before PDK-009 refuses tokens with volumes).
-- +goose Up

ALTER TABLE escrow_secret ADD COLUMN volume uuid;
ALTER TABLE escrow_secret ADD CONSTRAINT escrow_secret_volume_kind CHECK (volume IS NULL OR kind = 'luks_header');
CREATE INDEX escrow_secret_volume_idx ON escrow_secret (organization_id, device_id, volume, generation)
  WHERE kind = 'luks_header';

ALTER TABLE revocation_request ADD COLUMN volumes uuid[] NOT NULL DEFAULT '{}';

CREATE POLICY revocation ON device_status FOR SELECT TO paddock_revocation
  USING (organization_id = current_setting('paddock.org_id')::uuid);
GRANT SELECT ON device_status TO paddock_revocation;

-- +goose Down
