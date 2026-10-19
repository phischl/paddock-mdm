-- Hardware facts from the inventory (ADR 0037 decision 7, plan M8d decision 7, PDK-221): vendor, model, serial
-- number, CPU, memory and disk size of the host, written by the inventory sync with the rest of the inventory
-- reference. Free disk space, uptime and network addresses stay in Fleet. The serial number is searchable (index).
-- Forward-only: there is no Down migration.
-- +goose Up
ALTER TABLE device_inventory_ref
  ADD COLUMN hardware_vendor text NOT NULL DEFAULT '',
  ADD COLUMN hardware_model text NOT NULL DEFAULT '',
  ADD COLUMN hardware_serial text NOT NULL DEFAULT '',
  ADD COLUMN cpu_brand text NOT NULL DEFAULT '',
  ADD COLUMN cpu_cores int NOT NULL DEFAULT 0,
  ADD COLUMN memory_bytes bigint NOT NULL DEFAULT 0,
  ADD COLUMN disk_total_bytes bigint NOT NULL DEFAULT 0;
CREATE INDEX device_inventory_ref_org_serial_idx ON device_inventory_ref (organization_id, hardware_serial);

-- +goose Down
