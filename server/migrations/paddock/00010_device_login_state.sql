-- Login and sudo status of a device as its agent reported it last (plan M3b decision 17). Forward-only: there is no
-- Down migration. login_state holds, per area ("login", "sudo"), the latest event of that area as
-- {"type", "occurred_at", "params"}; the params are the audit params of the event.
-- +goose Up

ALTER TABLE device_status ADD COLUMN login_state jsonb NOT NULL DEFAULT '{}';

-- +goose Down
