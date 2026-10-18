-- Disk unlock mode (ADR 0038 decision 1, plan M8d decision 44, PDK-231): new installations unlock their disk with
-- TPM2 + boot PIN (tpm_pin, the default) or with the TPM alone (tpm_only); device groups override it (migration
-- 00053). The autoinstall embeds the mode, the bundle carries it so the agent reports a mismatch. Forward-only: there is
-- no Down migration.
-- +goose Up
ALTER TABLE organization_login_settings
  ADD COLUMN disk_unlock_mode text NOT NULL DEFAULT 'tpm_pin' CHECK (disk_unlock_mode IN ('tpm_pin','tpm_only'));

-- +goose Down
