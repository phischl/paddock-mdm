-- The database, not the role that finishes it, sets an action's finish time, and an action's identity never changes
-- (ADR 0032 amendment 2026-10-31, PDK-635). The retention round of 00081 deletes finished actions by finished_at:
-- without this, a role with UPDATE on action could finish a started organization action with a backdated finish time,
-- the next round would delete it at once and its use case's own finish would fail without trace; and it could rewrite a
-- started action's started_at so that the outbox reaper closes it as unknown.
-- The 00083 trigger and function are replaced in place and now run on every UPDATE (no WHEN clause), for every role,
-- the owner included:
-- - started -> finished: finished_at is clock_timestamp(), whatever the statement wrote. clock_timestamp(), not now():
--   FinishAction (ActionRunner and the outbox reaper) takes the audit event's occurred_at from the application clock
--   inside the finishing transaction, after it began and before this UPDATE, so now() (the transaction start) would
--   lie just before occurred_at and clock_timestamp() just after it. The retention cutoff is a UTC month start: a
--   finish time before occurred_at could fall into the previous month and delete the row while the index still shows
--   its event; one after it keeps the row at least as long as the index shows its event.
-- - id, code, actor, source, correlation_id and started_at never change. source is the audit source the action started
--   with (00072) and, like the actor, decides the source and subject of the event the reaper writes.
-- - organization_id keeps the 00083 rule: it never changes, except out of the platform pseudo-organization (nil UUID),
--   where organization creation starts its action and finishes it in the new organization.
-- SECURITY INVOKER with a pinned search_path; the function reads nothing but OLD and NEW.
-- Forward-only: there is no Down migration.
-- +goose Up
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION action_organization_immutable() RETURNS trigger
  LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog AS $$
BEGIN
  IF NEW.id IS DISTINCT FROM OLD.id
    OR NEW.code IS DISTINCT FROM OLD.code
    OR NEW.actor IS DISTINCT FROM OLD.actor
    OR NEW.source IS DISTINCT FROM OLD.source
    OR NEW.correlation_id IS DISTINCT FROM OLD.correlation_id
    OR NEW.started_at IS DISTINCT FROM OLD.started_at THEN
    RAISE EXCEPTION 'action: id, code, actor, source, correlation_id and started_at never change'
      USING ERRCODE = 'check_violation', DETAIL = format('action %s', OLD.id);
  END IF;
  IF OLD.organization_id <> '00000000-0000-0000-0000-000000000000'::uuid
    AND NEW.organization_id IS DISTINCT FROM OLD.organization_id THEN
    RAISE EXCEPTION 'action: organization_id never changes, except out of the platform pseudo-organization'
      USING ERRCODE = 'check_violation',
            DETAIL = format('action %s: organization %s -> %s', OLD.id, OLD.organization_id, NEW.organization_id);
  END IF;
  IF OLD.status = 'started' AND NEW.status = 'finished' THEN
    NEW.finished_at := clock_timestamp();
  END IF;
  RETURN NEW;
END $$;
-- +goose StatementEnd
CREATE OR REPLACE TRIGGER action_organization_immutable BEFORE UPDATE ON action
  FOR EACH ROW
  EXECUTE FUNCTION action_organization_immutable();
-- +goose Down
