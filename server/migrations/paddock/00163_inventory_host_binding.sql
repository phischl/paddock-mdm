-- Inventory hosts bound to their device: the binding each device reports, its pending device token, and the claim
-- watch's state (ADR 0057; plan M5a amendment 2026-11-17 e and its review round 1, which define every column).
-- Forward-only: there is no Down migration.
-- +goose Up
CREATE TABLE device_fleet_binding (
  device_id uuid PRIMARY KEY REFERENCES device(id),
  organization_id uuid NOT NULL,
  pending_token text CHECK (pending_token ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'),
  token_reported_at timestamptz,
  host_id text CHECK (host_id ~ '^[0-9]{1,19}$'),
  bound_at timestamptz,
  reset_announced_at timestamptz,
  suspended_at timestamptz,
  FOREIGN KEY (organization_id, device_id) REFERENCES device (organization_id, id)
);
CREATE INDEX device_fleet_binding_host ON device_fleet_binding (host_id) WHERE host_id IS NOT NULL;
-- The organization deletion deletes by organization_id.
CREATE INDEX device_fleet_binding_org_idx ON device_fleet_binding (organization_id);
ALTER TABLE device_fleet_binding ENABLE ROW LEVEL SECURITY;
ALTER TABLE device_fleet_binding FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON device_fleet_binding TO paddock_worker
  USING (organization_id = current_setting('paddock.org_id')::uuid)
  WITH CHECK (organization_id = current_setting('paddock.org_id')::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON device_fleet_binding TO paddock_worker;
INSERT INTO offboarding_table (table_name, delete_order) VALUES ('device_fleet_binding', 165);

-- Hosts a device left, reserved for it until Fleet deleted them (review round 2); removed_at keeps the row so that the
-- same host is not recorded again for the device.
CREATE TABLE device_inventory_left_host (
  device_id uuid NOT NULL REFERENCES device(id),
  organization_id uuid NOT NULL,
  host_id text NOT NULL CHECK (host_id ~ '^[0-9]{1,19}$'),
  reason text NOT NULL CHECK (reason IN ('replaced','relisted','retired')),
  left_at timestamptz NOT NULL,
  attempted_at timestamptz,
  removed_at timestamptz,
  PRIMARY KEY (device_id, host_id),
  FOREIGN KEY (organization_id, device_id) REFERENCES device (organization_id, id)
);
CREATE INDEX device_inventory_left_host_host ON device_inventory_left_host (host_id) WHERE removed_at IS NULL;
-- The organization deletion deletes by organization_id.
CREATE INDEX device_inventory_left_host_org_idx ON device_inventory_left_host (organization_id);
ALTER TABLE device_inventory_left_host ENABLE ROW LEVEL SECURITY;
ALTER TABLE device_inventory_left_host FORCE ROW LEVEL SECURITY;
-- The API role retires devices, which reserves their stored host (review round 3); it may only insert.
CREATE POLICY tenant ON device_inventory_left_host TO paddock_api, paddock_worker
  USING (organization_id = current_setting('paddock.org_id')::uuid)
  WITH CHECK (organization_id = current_setting('paddock.org_id')::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON device_inventory_left_host TO paddock_worker;
GRANT INSERT ON device_inventory_left_host TO paddock_api;
-- ON CONFLICT needs SELECT on the conflict columns (review round 3, amended): the API role reads only the device and
-- host IDs of its own organization's rows (forced RLS), which it already reads in device_inventory_ref.
GRANT SELECT (device_id, host_id) ON device_inventory_left_host TO paddock_api;
INSERT INTO offboarding_table (table_name, delete_order) VALUES ('device_inventory_left_host', 166);
INSERT INTO device_inventory_left_host (device_id, organization_id, host_id, reason, left_at)
SELECT r.device_id, r.organization_id, r.external_id, 'retired', now()
FROM device_inventory_ref r JOIN device d ON d.id = r.device_id
WHERE d.state = 'retired' AND r.external_id <> ''
ON CONFLICT (device_id, host_id) DO NOTHING;

ALTER TABLE device_inventory_ref ADD COLUMN fleet_enrolled_at timestamptz,
                                 ADD COLUMN fleet_reenrolled_at timestamptz,
                                 ADD COLUMN fleet_claim_since timestamptz,
                                 ADD COLUMN fleet_claim_reported_at timestamptz;

-- +goose StatementBegin
-- A retired device holds its hardware UUID until retention purged its inventory or it was retired as uninstalled
-- (plan M5a amendment e, review round 4).
CREATE OR REPLACE FUNCTION paddock_inventory_devices(uuids text[])
  RETURNS TABLE (hardware_uuid text, device_id uuid, organization_id uuid)
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public, pg_temp AS
  $$ SELECT lower(d.hardware_uuid), min(d.id::text)::uuid, min(d.organization_id::text)::uuid
     FROM public.device d
     WHERE lower(d.hardware_uuid) = ANY (SELECT lower(u) FROM unnest(uuids) u)
       AND (d.state IN ('active','quarantined')
            OR d.state = 'retired' AND d.uninstalled_at IS NULL
               AND EXISTS (SELECT 1 FROM public.device_inventory_ref r WHERE r.device_id = d.id)
               AND NOT EXISTS (SELECT 1 FROM public.retention_inventory_hold h WHERE h.device_id = d.id))
     GROUP BY lower(d.hardware_uuid)
     HAVING count(*) = 1 AND bool_and(d.state IN ('active','quarantined')) $$;

CREATE FUNCTION paddock_inventory_bindings()
  RETURNS TABLE (device_id uuid, organization_id uuid, hardware_uuid text, host_id text, pending_token text,
                 token_reported_at timestamptz, reset_announced_at timestamptz, bound_at timestamptz,
                 suspended_at timestamptz)
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public, pg_temp AS
  $$ SELECT d.id, d.organization_id, lower(d.hardware_uuid), b.host_id, b.pending_token, b.token_reported_at,
            b.reset_announced_at, b.bound_at, b.suspended_at
     FROM public.device_fleet_binding b JOIN public.device d ON d.id = b.device_id
     WHERE d.state IN ('active','quarantined') $$;

CREATE FUNCTION paddock_inventory_claim_devices()
  RETURNS TABLE (device_id uuid, organization_id uuid, hardware_uuid text, external_id text, bound_host text,
                 reset_announced_at timestamptz, bound_at timestamptz, fleet_enrolled_at timestamptz,
                 fleet_reenrolled_at timestamptz, fleet_claim_since timestamptz, fleet_claim_reported_at timestamptz,
                 suspended_at timestamptz, active boolean)
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public, pg_temp AS
  $$ SELECT d.id, d.organization_id, lower(d.hardware_uuid), i.external_id, b.host_id, b.reset_announced_at,
            b.bound_at, i.fleet_enrolled_at, i.fleet_reenrolled_at, i.fleet_claim_since, i.fleet_claim_reported_at,
            b.suspended_at, d.state = 'active'
     FROM public.device d JOIN public.device_inventory_ref i ON i.device_id = d.id
          LEFT JOIN public.device_fleet_binding b ON b.device_id = d.id
     WHERE d.state IN ('active','quarantined') $$;

CREATE FUNCTION paddock_expire_fleet_device_tokens(before timestamptz) RETURNS bigint
  LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, public, pg_temp AS
  $$ WITH x AS (UPDATE public.device_fleet_binding SET pending_token = NULL
                WHERE pending_token IS NOT NULL AND token_reported_at < before RETURNING 1)
     SELECT count(*) FROM x $$;

CREATE FUNCTION paddock_inventory_left_hosts()
  RETURNS TABLE (device_id uuid, organization_id uuid, host_id text, reason text, left_at timestamptz,
                 attempted_at timestamptz, hostname text, org_active boolean)
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public, pg_temp AS
  $$ SELECT l.device_id, l.organization_id, l.host_id, l.reason, l.left_at, l.attempted_at, d.hostname,
            o.status = 'active'
     FROM public.device_inventory_left_host l JOIN public.device d ON d.id = l.device_id
          JOIN public.organization o ON o.id = l.organization_id
     WHERE l.removed_at IS NULL
     ORDER BY l.left_at, l.device_id, l.host_id $$;

-- A binding and a reservation use a host like an inventory reference does (review round 2); 'hardware' is unchanged.
CREATE OR REPLACE FUNCTION paddock_fleet_host_in_use(retired_device uuid, host text)
  RETURNS text
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public, pg_temp AS
  $$ SELECT CASE
       WHEN EXISTS (SELECT 1 FROM public.device_inventory_ref r WHERE r.external_id = host AND r.device_id <> retired_device)
         OR EXISTS (SELECT 1 FROM public.device_fleet_binding b WHERE b.host_id = host AND b.device_id <> retired_device)
         OR EXISTS (SELECT 1 FROM public.device_inventory_left_host l
                    WHERE l.host_id = host AND l.removed_at IS NULL AND l.device_id <> retired_device)
         THEN 'ref'
       WHEN EXISTS (SELECT 1 FROM public.device d JOIN public.device rd ON rd.id = retired_device
                    WHERE d.id <> retired_device AND d.state IN ('active','quarantined','pending')
                      AND rd.hardware_uuid <> '' AND lower(d.hardware_uuid) = lower(rd.hardware_uuid)
                      AND NOT EXISTS (SELECT 1 FROM public.device_inventory_ref x WHERE x.device_id = d.id))
         THEN 'hardware'
       ELSE 'none' END $$;

CREATE OR REPLACE FUNCTION paddock_fleet_host_in_use_outside(org uuid, host text)
  RETURNS text
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public, pg_temp AS
  $$ SELECT CASE
       WHEN EXISTS (SELECT 1 FROM public.device_inventory_ref r
                    WHERE r.external_id = host AND r.organization_id <> org)
         OR EXISTS (SELECT 1 FROM public.device_fleet_binding b WHERE b.host_id = host AND b.organization_id <> org)
         OR EXISTS (SELECT 1 FROM public.device_inventory_left_host l
                    WHERE l.host_id = host AND l.removed_at IS NULL AND l.organization_id <> org)
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
REVOKE ALL ON FUNCTION paddock_inventory_left_hosts() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION paddock_inventory_left_hosts() TO paddock_platform;
REVOKE ALL ON FUNCTION paddock_inventory_bindings() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION paddock_inventory_bindings() TO paddock_platform;
REVOKE ALL ON FUNCTION paddock_inventory_claim_devices() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION paddock_inventory_claim_devices() TO paddock_platform;
REVOKE ALL ON FUNCTION paddock_expire_fleet_device_tokens(timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION paddock_expire_fleet_device_tokens(timestamptz) TO paddock_platform;

-- +goose Down
