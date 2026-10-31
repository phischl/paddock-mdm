-- server/migrations/paddock/00080_retention_control_plane.sql
-- The worker's retention round deletes finished device commands, cleared device alerts and filled event gaps
-- PADDOCK_AUDIT_INDEX_RETENTION_DAYS after they finished, cleared or were filled (ADR 0032 amendments 2026-10-18 and
-- 2026-10-31, PDK-180), in batches that each find their rows through the partial indexes below instead of scanning the
-- table (plan M10 amendment 2026-10-30). A command still referenced by a disk conversion or as a device's uninstall
-- command is kept; the indexes on the referencing columns serve that check and the foreign keys' own check on delete.
-- Forward-only: there is no Down migration.
-- +goose Up
GRANT DELETE ON device_command, device_alert, device_event_gap TO paddock_worker;
CREATE INDEX device_command_org_finished_idx ON device_command (organization_id, finished_at)
  WHERE status IN ('succeeded','failed','expired','cancelled');
CREATE INDEX device_alert_org_cleared_idx ON device_alert (organization_id, cleared_at) WHERE cleared_at IS NOT NULL;
CREATE INDEX device_event_gap_org_filled_idx ON device_event_gap (organization_id, filled_at) WHERE filled_at IS NOT NULL;
CREATE INDEX device_disk_conversion_command_idx ON device_disk_conversion (command_id);
CREATE INDEX device_disk_conversion_abort_command_idx ON device_disk_conversion (abort_command_id)
  WHERE abort_command_id IS NOT NULL;
CREATE INDEX device_uninstall_command_idx ON device (uninstall_command_id) WHERE uninstall_command_id IS NOT NULL;
-- +goose Down
