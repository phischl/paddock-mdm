-- The database, not the role that writes it, bounds an action's times, and a started action changes only by finishing
-- (ADR 0032 amendment 2026-10-31, PDK-635). The retention round of 00081 deletes finished actions by finished_at:
-- without this, a role with UPDATE on action could finish a started organization action with a backdated finish time,
-- the next round would delete it at once and its use case's own finish would fail without trace; it could rewrite a
-- started action's started_at so that the outbox reaper closes it as unknown, or its target, params or organization,
-- which the reaper copies into the event it writes; and a role with INSERT could add an action already expired.
-- The 00083 trigger and function are replaced by action_integrity, which runs before every INSERT and UPDATE, for every
-- role. The owner stays out of scope: it runs the migrations only, bypasses row-level security and may disable the
-- trigger; no service connects as it.
-- - Finish time, on INSERT as finished and on started -> finished: GREATEST(clock_timestamp(),
--   LEAST(finished_at, clock_timestamp() + 5 minutes)), clock_timestamp() for a missing one. The use cases and the
--   reaper take the audit event's occurred_at from the application clock and write it as finished_at; the event is
--   purged from the index by occurred_at, the row by finished_at, at the same UTC month start. Keeping the application
--   time keeps the row at least as long as the index shows its event even when the database clock lags; flooring it at
--   the database time stops a backdated finish, capping it bounds how far into the future a row can be kept; only an
--   application clock more than 5 minutes ahead loses its time to the cap. clock_timestamp(), not now(): the floor is
--   the moment of the finish, not the start of a transaction that may have run for a while.
-- - INSERT as started: finished_at is NULL and started_at lies within 5 minutes of clock_timestamp(), so the reaper
--   never takes a newly inserted action for a stuck one. An application clock more than 5 minutes off the database's
--   fails such an action instead of recording a wrong start.
-- - UPDATE: id, code, actor, source, correlation_id and started_at never change, and an update that leaves the action
--   started is refused, so a started action's target, params, error code and finish time stay as its use case wrote
--   them until it finishes. organization_id changes only out of the platform pseudo-organization (nil UUID) and only on
--   started -> finished; organization creation inserts its started action in the new organization already
--   (Recorder.SetOrganization runs in prepare, before the insert), so no legitimate update moves a started action.
-- - CHECK: an action is finished exactly when it has a finish time. No code path writes another combination.
-- SECURITY INVOKER with a pinned search_path; the function reads nothing but OLD, NEW and the clock.
-- Forward-only: there is no Down migration.
-- +goose Up
DROP TRIGGER action_organization_immutable ON action;
DROP FUNCTION action_organization_immutable();

-- +goose StatementBegin
CREATE FUNCTION action_integrity() RETURNS trigger
  LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog AS $$
DECLARE
  db_now timestamptz := clock_timestamp();
BEGIN
  IF TG_OP = 'INSERT' THEN
    IF NEW.status = 'started' THEN
      IF NEW.finished_at IS NOT NULL
        OR NEW.started_at NOT BETWEEN db_now - interval '5 minutes' AND db_now + interval '5 minutes' THEN
        RAISE EXCEPTION 'action: a started action is inserted without a finish time and with a current start time'
          USING ERRCODE = 'check_violation',
                DETAIL = format('action %s: started_at %s, finished_at %s, database time %s',
                                NEW.id, NEW.started_at, NEW.finished_at, db_now);
      END IF;
    ELSE
      NEW.finished_at := GREATEST(db_now, LEAST(coalesce(NEW.finished_at, db_now), db_now + interval '5 minutes'));
    END IF;
    RETURN NEW;
  END IF;

  IF NEW.id IS DISTINCT FROM OLD.id
    OR NEW.code IS DISTINCT FROM OLD.code
    OR NEW.actor IS DISTINCT FROM OLD.actor
    OR NEW.source IS DISTINCT FROM OLD.source
    OR NEW.correlation_id IS DISTINCT FROM OLD.correlation_id
    OR NEW.started_at IS DISTINCT FROM OLD.started_at THEN
    RAISE EXCEPTION 'action: id, code, actor, source, correlation_id and started_at never change'
      USING ERRCODE = 'check_violation', DETAIL = format('action %s', OLD.id);
  END IF;
  IF NEW.status = 'started' THEN
    RAISE EXCEPTION 'action: a started action changes only by finishing'
      USING ERRCODE = 'check_violation', DETAIL = format('action %s', OLD.id);
  END IF;
  IF NEW.organization_id IS DISTINCT FROM OLD.organization_id
    AND NOT (OLD.organization_id = '00000000-0000-0000-0000-000000000000'::uuid AND OLD.status = 'started') THEN
    RAISE EXCEPTION 'action: organization_id never changes, except out of the platform pseudo-organization on finishing'
      USING ERRCODE = 'check_violation',
            DETAIL = format('action %s: organization %s -> %s', OLD.id, OLD.organization_id, NEW.organization_id);
  END IF;
  IF OLD.status = 'started' THEN
    NEW.finished_at := GREATEST(db_now, LEAST(coalesce(NEW.finished_at, db_now), db_now + interval '5 minutes'));
  END IF;
  RETURN NEW;
END $$;
-- +goose StatementEnd

CREATE TRIGGER action_integrity BEFORE INSERT OR UPDATE ON action
  FOR EACH ROW
  EXECUTE FUNCTION action_integrity();

ALTER TABLE action ADD CONSTRAINT action_finished_at_status CHECK ((status = 'finished') = (finished_at IS NOT NULL));
-- +goose Down
