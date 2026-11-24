-- The server-side watch of fleetd (plan M5a amendments 2026-11-16 c, E2, and d): fleet_silent_since is the worker's
-- time of the first round that found the device's fleetd silent while the device checked in; fleet_silent_checkin_at
-- the device's first check-in after the silence was found, outside a hold (amendment 2026-11-24 f, F-M1);
-- fleet_silent_reported_at when device.tamper_fleetd_silent was recorded for the current silence;
-- fleet_reset_hold_at the announced enrollment reset whose hold the watch granted last (F-15.1). Forward-only: there
-- is no Down migration.
-- +goose Up
ALTER TABLE device_inventory_ref ADD COLUMN fleet_silent_since timestamptz,
                                 ADD COLUMN fleet_silent_checkin_at timestamptz,
                                 ADD COLUMN fleet_silent_reported_at timestamptz,
                                 ADD COLUMN fleet_reset_hold_at timestamptz;

-- +goose StatementBegin
-- external_id and bound_host let the worker find the device's speaking host; the binding times and
-- fleet_reenrolled_at bound its hold (ADR 0057; amendment 2026-11-24 f, F-H1).
CREATE FUNCTION paddock_fleet_watch_devices()
  RETURNS TABLE (device_id uuid, organization_id uuid, hardware_uuid text, external_id text, bound_host text,
                 last_contact_at timestamptz, last_seen_at timestamptz, policy_updated_at timestamptz,
                 fleet_silent_since timestamptz, fleet_silent_checkin_at timestamptz,
                 fleet_silent_reported_at timestamptz, reset_announced_at timestamptz, bound_at timestamptz,
                 suspended_at timestamptz, fleet_reenrolled_at timestamptz, fleet_reset_hold_at timestamptz)
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public, pg_temp AS
  $$ SELECT d.id, d.organization_id, lower(d.hardware_uuid), i.external_id, b.host_id, s.last_contact_at,
            i.last_seen_at, i.policy_updated_at, i.fleet_silent_since, i.fleet_silent_checkin_at,
            i.fleet_silent_reported_at, b.reset_announced_at, b.bound_at, b.suspended_at, i.fleet_reenrolled_at,
            i.fleet_reset_hold_at
     FROM public.device d JOIN public.device_inventory_ref i ON i.device_id = d.id
          LEFT JOIN public.device_status s ON s.device_id = d.id
          LEFT JOIN public.device_fleet_binding b ON b.device_id = d.id
     WHERE d.state = 'active' $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION paddock_fleet_watch_devices() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION paddock_fleet_watch_devices() TO paddock_platform;

-- +goose Down
