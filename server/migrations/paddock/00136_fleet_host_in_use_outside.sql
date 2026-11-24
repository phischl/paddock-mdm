-- server/migrations/paddock/00136_fleet_host_in_use_outside.sql
-- The organization deletion deletes every Fleet host of the organization's devices unless a device of another
-- organization still uses it (plan M17 amendment l point 1, PDK-1058). paddock_fleet_host_in_use excludes only the one
-- device it is asked about, so two devices of the deleting organization on one host (a re-enrolled machine) kept each
-- other's host alive. This variant ignores every device of the given organization, both for the inventory reference
-- ('ref') and for the hardware answer ('hardware': an active, quarantined or pending device of another organization with
-- the hardware of one of the organization's devices on the host and no reference yet). It never returns another
-- organization's rows or IDs. Only paddock_platform may call it. The search path is pinned with pg_temp last and every
-- table is qualified (as 00076). Forward-only: there is no Down migration.
-- +goose Up
-- +goose StatementBegin
CREATE FUNCTION paddock_fleet_host_in_use_outside(org uuid, host text)
  RETURNS text
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public, pg_temp AS
  $$ SELECT CASE
       WHEN EXISTS (SELECT 1 FROM public.device_inventory_ref r
                    WHERE r.external_id = host AND r.organization_id <> org)
         THEN 'ref'
       WHEN EXISTS (SELECT 1 FROM public.device d
                    JOIN public.device_inventory_ref own ON own.external_id = host AND own.organization_id = org
                    JOIN public.device od ON od.id = own.device_id
                    WHERE d.organization_id <> org AND d.state IN ('active','quarantined','pending')
                      AND od.hardware_uuid <> '' AND lower(d.hardware_uuid) = lower(od.hardware_uuid)
                      AND NOT EXISTS (SELECT 1 FROM public.device_inventory_ref x WHERE x.device_id = d.id))
         THEN 'hardware'
       ELSE 'none' END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION paddock_fleet_host_in_use_outside(uuid, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION paddock_fleet_host_in_use_outside(uuid, text) TO paddock_platform;
-- +goose Down
