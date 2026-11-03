-- Whether the last software report of a device left items out to keep the check-in small (plan M13a amendment
-- 2026-11-02, PDK-700): the device's managed-software list shows it, so a missing row is not read as "not managed".
-- Forward-only: there is no Down migration.
-- +goose Up
ALTER TABLE device_status ADD COLUMN software_truncated boolean NOT NULL DEFAULT false;

-- +goose Down
