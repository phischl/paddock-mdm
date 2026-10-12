-- The contact state of a device as an inlinable function of the device's columns and its open alert (ADR 0028
-- decision 3, PDK-089): the uuid-taking function of 00038 probed device_alert twice per call, and a SQL function with
-- a subquery is never inlined, so every row started a sub-executor (about 385 ms for the overview at 10 000 devices).
-- Every consumer now joins the open alert:
--   LEFT JOIN device_alert open_alert ON open_alert.device_id = <device>.id AND open_alert.cleared_at IS NULL
-- and passes open_alert.kind. That join relies on device_alert_open_idx (00026, UNIQUE (device_id) WHERE
-- cleared_at IS NULL): at most one open alert per device, so it never duplicates a device row. The index is part of
-- the contract of device_alert and must not be dropped or relaxed.
-- Not STRICT and without a table read, so the planner inlines the CASE; row level security applies to the joined
-- device_alert directly. EXECUTE stays with PUBLIC as for 00038. Forward-only: there is no Down migration.
-- +goose Up
DROP FUNCTION paddock_device_contact(text, timestamptz, timestamptz, uuid);

-- +goose StatementBegin
CREATE FUNCTION paddock_device_contact(state text, last_contact_at timestamptz, presumed_lost_at timestamptz, open_alert_kind text)
RETURNS text LANGUAGE sql IMMUTABLE PARALLEL SAFE AS $$
  SELECT CASE
    WHEN state <> 'active' THEN CASE WHEN last_contact_at IS NULL THEN 'never' ELSE 'ok' END
    WHEN presumed_lost_at IS NOT NULL THEN 'presumed_lost'
    WHEN open_alert_kind = 'stale_critical' THEN 'stale_critical'
    WHEN open_alert_kind = 'stale_warning' THEN 'stale_warning'
    WHEN last_contact_at IS NULL THEN 'never'
    ELSE 'ok'
  END
$$;
-- +goose StatementEnd

-- +goose Down
