-- The platform inputs a device's latest compile saw (PDK-695, plan M13a decisions 8 and 14): the compiler's reconcile
-- loop recompiles an active device whose architecture or os-release no longer match them, as it does for an outdated
-- bundle schema. They are kept on the device, not on the bundle, because a recompile that changes no content publishes
-- no bundle but must still record what it saw. Existing devices start in sync, so the upgrade recompiles no fleet.
-- Forward-only: there is no Down migration.
-- +goose Up
ALTER TABLE device
  ADD COLUMN compiled_arch text NOT NULL DEFAULT '',
  ADD COLUMN compiled_os_id text NOT NULL DEFAULT '',
  ADD COLUMN compiled_os_version_id text NOT NULL DEFAULT '';

UPDATE device d SET
  compiled_arch = coalesce((SELECT s.arch FROM device_status s WHERE s.device_id = d.id), ''),
  compiled_os_id = coalesce(d.os_release ->> 'id', ''),
  compiled_os_version_id = coalesce(d.os_release ->> 'version_id', '');

GRANT UPDATE (compiled_arch, compiled_os_id, compiled_os_version_id) ON device TO paddock_compiler;

-- +goose Down
