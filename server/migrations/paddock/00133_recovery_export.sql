-- Encrypted recovery export during the grace period (plan M17 amendment b decision 21; ADR 0052 amendment b decision 8).
-- An organization may take at most five exports per grace period. The count belongs to the pending deletion it was
-- taken in: recovery_exports_since holds that deletion's deletion_requested_at, so a cancelled and newly requested
-- deletion starts again at zero without the deletion request having to know about exports. The api reserves an export
-- inside the organization's own context (InOrg, or InPendingDeletionOrg for a platform administrator) and releases it
-- again when the export fails, so only successful exports count; the column grant lets it change these two columns of
-- its own row (policy org_self) and nothing else. Forward-only: there is no Down migration.
-- +goose Up

ALTER TABLE organization
  ADD COLUMN recovery_exports       int NOT NULL DEFAULT 0 CHECK (recovery_exports >= 0),
  ADD COLUMN recovery_exports_since timestamptz;

GRANT UPDATE (recovery_exports, recovery_exports_since) ON organization TO paddock_api;

-- The escrow-reader checks the pending deletion itself before it decrypts an export, inside the organization of the
-- request, and sees nothing of the organization but its state.
CREATE POLICY escrow_reader ON organization FOR SELECT TO paddock_escrow_reader
  USING (id = current_setting('paddock.org_id')::uuid);
GRANT SELECT (id, status, delete_after) ON organization TO paddock_escrow_reader;

-- +goose Down
