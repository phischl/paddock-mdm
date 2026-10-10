-- The contact state of a device (plan M7c §6.2: never, ok, stale_warning, stale_critical, presumed_lost), derived
-- like the attention conditions, as one function so the device list, its contact filter and the overview agree.
-- SECURITY INVOKER: row level security of device_alert applies to the caller. Forward-only: there is no Down
-- migration. Numbers 00036 (M7a) and 00037 (theme) precede it.
-- +goose Up
-- +goose StatementBegin
CREATE FUNCTION paddock_device_contact(state text, last_contact_at timestamptz, presumed_lost_at timestamptz, device_id uuid)
RETURNS text LANGUAGE sql STABLE AS $$
  SELECT CASE
    WHEN state <> 'active' THEN CASE WHEN last_contact_at IS NULL THEN 'never' ELSE 'ok' END
    WHEN presumed_lost_at IS NOT NULL THEN 'presumed_lost'
    WHEN EXISTS (SELECT 1 FROM device_alert a WHERE a.device_id = paddock_device_contact.device_id AND a.cleared_at IS NULL AND a.kind = 'stale_critical') THEN 'stale_critical'
    WHEN EXISTS (SELECT 1 FROM device_alert a WHERE a.device_id = paddock_device_contact.device_id AND a.cleared_at IS NULL AND a.kind = 'stale_warning') THEN 'stale_warning'
    WHEN last_contact_at IS NULL THEN 'never'
    ELSE 'ok'
  END
$$;
-- +goose StatementEnd

-- +goose Down
