-- Checkpoints and replay of push destinations (plan M12 decisions 20 and 21, ADR 0031 amendment 2026-11-04 items 3 and
-- 4). A checkpoint is a delivery of kind checkpoint that takes one forward sequence number; it stores its recording day
-- and event count, so a retry and a replay send the same message (the manifest itself is immutable in the audit
-- database). A replay request sets replay_from through a column grant: replay_from is the one state column the api and
-- the platform role may write (alpha.9 decision 14a, grant over definer). Forward-only: there is no Down migration.
-- +goose Up

-- The kind check was created unnamed in migration 00085; its generated name is read from the catalog, as in 00101.
-- +goose StatementBegin
DO $$
DECLARE
  constraint_name text;
BEGIN
  SELECT c.conname INTO STRICT constraint_name
  FROM pg_constraint c
  JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = ANY (c.conkey)
  WHERE c.conrelid = 'notification_delivery'::regclass AND c.contype = 'c' AND a.attname = 'kind';
  EXECUTE format('ALTER TABLE notification_delivery DROP CONSTRAINT %I', constraint_name);
END
$$;
-- +goose StatementEnd

ALTER TABLE notification_delivery
  ADD CONSTRAINT notification_delivery_kind_check CHECK (kind IN ('events','heartbeat','test','checkpoint')),
  ADD COLUMN checkpoint_day date,
  ADD CONSTRAINT notification_delivery_checkpoint_day_check CHECK ((kind = 'checkpoint') = (checkpoint_day IS NOT NULL));

ALTER TABLE notification_destination_state
  ADD CONSTRAINT notification_destination_state_replay_from_check CHECK (replay_from IS NULL OR replay_from >= 1);

-- Row level security confines the write to the caller's own destinations: the tenant policy of migration 00085 (on
-- paddock.org_id without missing_ok, so a missing context fails closed) for paddock_api, the platform policy (nil
-- organization) for paddock_platform. The guarded UPDATE (query ReplayNotificationDestination) applies only while no
-- batch is pending, no replay runs and no skip request is pending, which closes the race with the notifier: a running
-- replay is never redirected, because the notifier records notification.replayed only while replay_from is still the
-- number it replayed from.
GRANT UPDATE (replay_from) ON notification_destination_state TO paddock_api, paddock_platform;

-- +goose Down
