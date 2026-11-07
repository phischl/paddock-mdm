-- Syslog destinations, checkpoints and replay state (plan M12 decision 16, ADR 0031 amendment 2026-11-04 items 1–4).
-- A syslog destination names a TLS receiver: host, port, an optional PEM bundle of a private CA (a public
-- certificate, stored in plain text) and an optional SNI override. checkpoints applies to webhook and syslog
-- destinations; last_checkpoint_day and replay_from are the notifier's state of the checkpoints and the replay (plan
-- M12 decisions 20 and 21). Forward-only: there is no Down migration.
-- +goose Up

-- The type check was created unnamed in migration 00085; its generated name is read from the catalog, so the
-- migration does not depend on PostgreSQL's naming rule.
-- +goose StatementBegin
DO $$
DECLARE
  constraint_name text;
BEGIN
  SELECT c.conname INTO STRICT constraint_name
  FROM pg_constraint c
  JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = ANY (c.conkey)
  WHERE c.conrelid = 'notification_destination'::regclass AND c.contype = 'c' AND a.attname = 'type';
  EXECUTE format('ALTER TABLE notification_destination DROP CONSTRAINT %I', constraint_name);
END
$$;
-- +goose StatementEnd

ALTER TABLE notification_destination
  ADD CONSTRAINT notification_destination_type_check CHECK (type IN ('webhook','email','syslog')),
  ADD COLUMN syslog_host text,
  ADD COLUMN syslog_port int CHECK (syslog_port BETWEEN 1 AND 65535),
  ADD COLUMN syslog_ca_pem text,
  ADD COLUMN syslog_server_name text,
  ADD COLUMN checkpoints boolean NOT NULL DEFAULT false;

ALTER TABLE notification_destination_state
  ADD COLUMN last_checkpoint_day date,
  ADD COLUMN replay_from bigint;

-- +goose Down
