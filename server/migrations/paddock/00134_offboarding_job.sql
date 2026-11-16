-- The organization deletion job (plan M17 decisions 5, 6, 9, 14 and 17, amendment 2026-11-14 c points 2 and 3, ticket
-- PDK-1015). The worker reaches a deleting organization only through db.OrgPool.InOrgOffboarding and gets no table grant
-- here: what it needs beyond its existing rights runs through two SECURITY DEFINER functions that refuse unless the
-- context organization is deleting. The step counts survive a worker restart in offboarding_counts, written by the
-- platform role with the step's checkpoint. Forward-only: there is no Down migration.
-- +goose Up

-- What each step removed so far, keyed by step name; organization.deleted reports the totals (decision 17). A step
-- that fails after partial progress keeps what it counted, so a retry only adds what is left.
ALTER TABLE organization ADD COLUMN offboarding_counts jsonb NOT NULL DEFAULT '{}'::jsonb;

-- Step outbox (decision 9, amendment c point 2): the number of the context organization's unpublished outbox rows. The
-- worker has no SELECT on outbox; the step completes when this returns 0 and never deletes unpublished rows.
-- +goose StatementBegin
CREATE FUNCTION paddock_offboard_outbox_pending() RETURNS bigint
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, public, pg_temp AS $$
DECLARE
  org       uuid := current_setting('paddock.org_id')::uuid;
  org_state text;
  pending   bigint;
BEGIN
  SELECT o.status INTO org_state FROM public.organization o WHERE o.id = org;
  IF org_state IS DISTINCT FROM 'deleting' THEN
    RAISE EXCEPTION 'paddock_offboard_outbox_pending: organization % is not being deleted', org
      USING ERRCODE = 'insufficient_privilege';
  END IF;
  SELECT count(*) INTO pending FROM public.outbox x WHERE x.organization_id = org AND x.published_at IS NULL;
  RETURN pending;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION paddock_offboard_outbox_pending() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION paddock_offboard_outbox_pending() TO paddock_worker;

-- Step sessions (decision 14): revokes every API token of the context organization that is not revoked yet and returns
-- how many. A function instead of a grant on api_token, like the outbox check: the worker never reads token rows.
-- +goose StatementBegin
CREATE FUNCTION paddock_offboard_revoke_api_tokens() RETURNS bigint
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, public, pg_temp AS $$
DECLARE
  org       uuid := current_setting('paddock.org_id')::uuid;
  org_state text;
  revoked   bigint;
BEGIN
  SELECT o.status INTO org_state FROM public.organization o WHERE o.id = org;
  IF org_state IS DISTINCT FROM 'deleting' THEN
    RAISE EXCEPTION 'paddock_offboard_revoke_api_tokens: organization % is not being deleted', org
      USING ERRCODE = 'insufficient_privilege';
  END IF;
  UPDATE public.api_token t SET revoked_at = now() WHERE t.organization_id = org AND t.revoked_at IS NULL;
  GET DIAGNOSTICS revoked = ROW_COUNT;
  RETURN revoked;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION paddock_offboard_revoke_api_tokens() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION paddock_offboard_revoke_api_tokens() TO paddock_worker;

-- +goose Down
