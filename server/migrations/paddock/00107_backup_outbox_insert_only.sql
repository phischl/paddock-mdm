-- The backup role (plan M15 decision 15) records its run events like every recorder: it inserts outbox rows and never
-- reads them back. Migration 00100 granted SELECT as well; the outbox carries every organization's pending events, so
-- the grant is narrowed to INSERT (PDK-729 review, minor 3).
-- An escrowed LUKS header copy leaves the backup set only on audited evidence that the device's escrow was removed on
-- purpose (plan M15, amendment 2026-11-05, A2 note of decisions-alpha9 item 27): the revocation-issuer's successful
-- Destroy, device.escrow_destroyed, the only path that deletes header objects. The role reads exactly those finished
-- actions of every organization, read-only (FOR SELECT; its INSERT stays bound to the platform pseudo-organization by
-- policy backup), and only inside its platform context, so a missing context still fails closed.
-- Forward-only: there is no Down migration.
-- +goose Up
REVOKE SELECT ON outbox FROM paddock_backup;
CREATE POLICY backup_escrow_evidence ON action FOR SELECT TO paddock_backup
  USING (current_setting('paddock.org_id')::uuid = '00000000-0000-0000-0000-000000000000'::uuid
    AND code = 'device.escrow_destroyed' AND status = 'finished' AND outcome = 'success');

-- +goose Down
