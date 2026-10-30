-- server/migrations/paddock/00076_fleet_host_in_use.sql
-- One Fleet serves every organization, so before the retention round deletes a retired device's Fleet host it asks
-- whether any other device in any organization still uses that host or that hardware (plan M10 amendments 2026-10-30,
-- PDK-138). The answer is 'ref' when another device's inventory reference names the host, 'hardware' when an active,
-- quarantined or pending device with the same hardware UUID has no reference yet (its first inventory sync is still
-- pending, so it may become the host's user), and 'none' otherwise. It never returns another organization's rows or
-- IDs. Only paddock_platform may call it. The search path is pinned with pg_temp last and every table is qualified, so
-- a caller's temporary table cannot shadow device or device_inventory_ref (as 00034). Forward-only: there is no Down
-- migration.
-- +goose Up
-- +goose StatementBegin
CREATE FUNCTION paddock_fleet_host_in_use(retired_device uuid, host text)
  RETURNS text
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public, pg_temp AS
  $$ SELECT CASE
       WHEN EXISTS (SELECT 1 FROM public.device_inventory_ref r WHERE r.external_id = host AND r.device_id <> retired_device)
         THEN 'ref'
       WHEN EXISTS (SELECT 1 FROM public.device d JOIN public.device rd ON rd.id = retired_device
                    WHERE d.id <> retired_device AND d.state IN ('active','quarantined','pending')
                      AND rd.hardware_uuid <> '' AND lower(d.hardware_uuid) = lower(rd.hardware_uuid)
                      AND NOT EXISTS (SELECT 1 FROM public.device_inventory_ref x WHERE x.device_id = d.id))
         THEN 'hardware'
       ELSE 'none' END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION paddock_fleet_host_in_use(uuid, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION paddock_fleet_host_in_use(uuid, text) TO paddock_platform;
-- +goose Down
