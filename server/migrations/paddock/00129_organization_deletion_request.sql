-- Organization deletion request (plan M17 decisions 3 and 4, amendment 2026-11-14 c item 1; ADR 0052 decision 2).
-- The request records how many devices received the offboarding uninstall and how many were skipped; the counts are
-- NULL while no deletion is requested and while the request still issues its uninstalls, are cleared by a cancel and
-- stay on the tombstone. They are not derived from device_command, whose rows the database step deletes.
-- device.uninstall_reason marks the uninstalls the system issued for the offboarding, so that cancelling the deletion
-- withdraws exactly those and never an uninstall an organization administrator requested. Forward-only: there is no
-- Down migration.
-- +goose Up

ALTER TABLE organization
  ADD COLUMN deletion_uninstalls_issued  int CHECK (deletion_uninstalls_issued >= 0),
  ADD COLUMN deletion_uninstalls_skipped int CHECK (deletion_uninstalls_skipped >= 0),
  ADD CONSTRAINT organization_deletion_uninstalls_consistent CHECK (
    (deletion_uninstalls_issued IS NULL) = (deletion_uninstalls_skipped IS NULL) AND
    (delete_after IS NOT NULL OR deletion_uninstalls_issued IS NULL));

ALTER TABLE device
  ADD COLUMN uninstall_reason text CHECK (uninstall_reason IN ('organization_offboarding')),
  ADD CONSTRAINT device_uninstall_reason_requested CHECK (uninstall_reason IS NULL OR uninstall_requested_at IS NOT NULL);
