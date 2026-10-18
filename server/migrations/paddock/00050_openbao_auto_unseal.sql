-- Automatic unseal of OpenBao (ADR 0035, plan M8u decision 2): the platform administrator's acknowledged decision
-- and the unsealer's report, one row. Platform data (role paddock_platform); the unsealer's own role reads the
-- state and writes its report. Forward-only: there is no Down migration.
-- +goose Up
CREATE TABLE openbao_auto_unseal (
  id                      smallint PRIMARY KEY CHECK (id = 1),
  state                   text NOT NULL CHECK (state IN ('disabled', 'enabled')),
  disclaimer_version      text,
  acknowledgement         text,
  acknowledged_by         text,
  acknowledged_by_subject text,
  acknowledged_at         timestamptz,
  disabled_by             text,
  disabled_at             timestamptz,
  unsealer_seen_at        timestamptz,
  unsealer_shares_present boolean NOT NULL DEFAULT false,
  unseal_count            bigint NOT NULL DEFAULT 0,
  last_unseal_at          timestamptz,
  failure_count           bigint NOT NULL DEFAULT 0,
  last_failure_at         timestamptz,
  last_failure_reason     text,
  audited_unseal_count    bigint NOT NULL DEFAULT 0,
  audited_failure_count   bigint NOT NULL DEFAULT 0,
  updated_at              timestamptz NOT NULL DEFAULT now(),
  CHECK (state = 'disabled' OR (disclaimer_version IS NOT NULL AND acknowledgement IS NOT NULL
    AND acknowledged_by IS NOT NULL AND acknowledged_at IS NOT NULL))
);
INSERT INTO openbao_auto_unseal (id, state) VALUES (1, 'disabled');
GRANT SELECT, UPDATE ON openbao_auto_unseal TO paddock_platform;
-- The counters only ever grow: the worker records one platform.openbao_auto_unsealed event per growth beyond
-- audited_*, so a lowered counter (the unsealer's column grant would allow any value) would suppress those events
-- until it caught up again. Audit integrity wins over any reset, for every role (architect decision on PDK-303).
-- +goose StatementBegin
CREATE FUNCTION openbao_auto_unseal_counters_monotonic() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.unseal_count < OLD.unseal_count OR NEW.failure_count < OLD.failure_count THEN
    RAISE EXCEPTION 'openbao_auto_unseal: unseal_count and failure_count never decrease'
      USING ERRCODE = 'check_violation',
            DETAIL = format('unseal_count %s -> %s, failure_count %s -> %s',
              OLD.unseal_count, NEW.unseal_count, OLD.failure_count, NEW.failure_count);
  END IF;
  RETURN NEW;
END $$;
-- +goose StatementEnd
CREATE TRIGGER openbao_auto_unseal_counters_monotonic BEFORE UPDATE ON openbao_auto_unseal
  FOR EACH ROW EXECUTE FUNCTION openbao_auto_unseal_counters_monotonic();
-- The unsealer's role exists only where the operator enabled automatic unseal; deploy/compose/scripts/
-- postgres-unsealer-role.sh grants the same when it creates the role after this migration ran.
-- +goose StatementBegin
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'paddock_unsealer') THEN
    GRANT SELECT ON openbao_auto_unseal TO paddock_unsealer;
    GRANT UPDATE (unsealer_seen_at, unsealer_shares_present, unseal_count, last_unseal_at, failure_count,
      last_failure_at, last_failure_reason, updated_at) ON openbao_auto_unseal TO paddock_unsealer;
  END IF;
END $$;
-- +goose StatementEnd
