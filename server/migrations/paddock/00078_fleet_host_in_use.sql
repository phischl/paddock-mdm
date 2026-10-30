-- server/migrations/paddock/00078_fleet_host_in_use.sql
-- One Fleet serves every organization, so before the retention round deletes a retired device's Fleet host it asks
-- whether any other device in any organization still uses that host or that hardware (plan M10 amendment 2026-10-30,
-- PDK-138): another device's inventory reference to the host, or an active or quarantined device with the same hardware
-- UUID that has no reference yet because its first inventory sync is still pending. The function answers only yes or
-- no; it never returns another organization's rows or IDs. Only paddock_platform may call it. Forward-only: there is no
-- Down migration.
-- +goose Up
-- +goose StatementBegin
CREATE FUNCTION paddock_fleet_host_in_use(retired_device uuid, host text)
  RETURNS boolean
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS
  $$ SELECT EXISTS (SELECT 1 FROM device_inventory_ref r WHERE r.external_id = host AND r.device_id <> retired_device)
         OR EXISTS (SELECT 1 FROM device d JOIN device rd ON rd.id = retired_device
                    WHERE d.id <> retired_device AND d.state IN ('active','quarantined')
                      AND rd.hardware_uuid <> '' AND lower(d.hardware_uuid) = lower(rd.hardware_uuid)) $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION paddock_fleet_host_in_use(uuid, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION paddock_fleet_host_in_use(uuid, text) TO paddock_platform;
-- +goose Down
