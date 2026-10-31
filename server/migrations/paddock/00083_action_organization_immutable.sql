-- An action stays in the organization it was started in (ADR 0032 amendment 2026-10-31, PDK-180). The policy of 00082
-- keeps a finished action read-only, but the platform and relay roles may still update every started action: without
-- this trigger they could move an organization's started action into the platform pseudo-organization or another
-- organization, finish it there and take it out of the organization's audit trail. The only move allowed is out of
-- the platform pseudo-organization (nil UUID): organization creation starts its action there and finishes it in the new
-- organization (Recorder.SetOrganization). The trigger holds for every role, the owner included; SECURITY INVOKER with
-- a pinned search_path, the function reads nothing but OLD and NEW.
-- The restrictive policies of 00081 and 00082 named their roles, so a role added later (M9's paddock_notifier) with
-- UPDATE or DELETE on action would not be bound by them. They become TO PUBLIC with the same expressions:
-- - finished_immutable: UPDATE USING status = 'started' WITH CHECK status IN ('started', 'finished'), for every role.
-- - delete_finished replaces worker_delete: every role deletes finished actions only.
-- - platform_delete stays as it is: the platform role, which the internet-facing API holds too, additionally deletes
--   the platform pseudo-organization's actions only. A PUBLIC policy cannot name that role without testing
--   current_user, and the narrower rule needs no generalisation: with delete_finished, a new role gets the worker's
--   limit, never more than the platform role.
-- Each role's effective rule is unchanged: the platform role deletes finished pseudo-organization actions, the worker
-- finished actions of its organization, every role updates started actions only.
-- Forward-only: there is no Down migration.
-- +goose Up
-- +goose StatementBegin
CREATE FUNCTION action_organization_immutable() RETURNS trigger
  LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog AS $$
BEGIN
  RAISE EXCEPTION 'action: organization_id never changes, except out of the platform pseudo-organization'
    USING ERRCODE = 'check_violation',
          DETAIL = format('action %s: organization %s -> %s', OLD.id, OLD.organization_id, NEW.organization_id);
END $$;
-- +goose StatementEnd
CREATE TRIGGER action_organization_immutable BEFORE UPDATE ON action
  FOR EACH ROW
  WHEN (OLD.organization_id <> '00000000-0000-0000-0000-000000000000'::uuid
    AND NEW.organization_id IS DISTINCT FROM OLD.organization_id)
  EXECUTE FUNCTION action_organization_immutable();

DROP POLICY finished_immutable ON action;
CREATE POLICY finished_immutable ON action AS RESTRICTIVE FOR UPDATE TO PUBLIC
  USING (status = 'started')
  WITH CHECK (status IN ('started', 'finished'));

DROP POLICY worker_delete ON action;
CREATE POLICY delete_finished ON action AS RESTRICTIVE FOR DELETE TO PUBLIC
  USING (status = 'finished');
-- +goose Down
