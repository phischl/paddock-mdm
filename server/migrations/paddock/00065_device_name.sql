-- Device name set from the platform (ADR 0041, plan M8h decision 1): the desired hostname of a device. NULL = not
-- managed. device.hostname stays the name the device reports. Forward-only: there is no Down migration.
-- +goose Up
ALTER TABLE device ADD COLUMN name text
  CHECK (name ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$' AND name <> 'localhost');
CREATE UNIQUE INDEX device_org_name_key ON device (organization_id, name)
  WHERE name IS NOT NULL AND state <> 'retired';
-- +goose Down
