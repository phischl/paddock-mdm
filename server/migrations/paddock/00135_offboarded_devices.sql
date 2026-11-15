-- The hand-over of a deleting organization's devices to offboarded_device (plan M17 decision 15, amendment e point 10,
-- ticket PDK-1016). The worker has no INSERT on device_command and no UPDATE on device; as in 00134 it gets no table
-- grant, only a SECURITY DEFINER function that refuses unless the context organization is deleting. Forward-only: there
-- is no Down migration.
-- +goose Up

-- Locks every device of the context organization that may still contact the server (no reported removal, neither
-- retired nor rejected) and gives each a fresh uninstall (mode leave, reason organization_offboarding) unless its open
-- uninstall can still be acted on: delivered or succeeded, or pending and unexpired. An open Lock or Destroy does not
-- stop the fresh command: it cannot be served once the organization is gone. A constant number of statements,
-- independent of the device count (amendment e point 5). Returns how many devices got a fresh command; the worker then
-- reads the locked devices itself in the same transaction. The organization comes only from the transaction's paddock.org_id (no missing_ok: no context fails closed);
-- every statement is filtered by it, because paddock_owner bypasses RLS.
-- +goose StatementBegin
CREATE FUNCTION paddock_offboard_reissue_uninstalls(p_params jsonb, p_issued_at timestamptz, p_expires_at timestamptz)
  RETURNS bigint
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, public, pg_temp AS $$
DECLARE
  org       uuid := current_setting('paddock.org_id')::uuid;
  org_state text;
  locked    uuid[];
  reissued  bigint;
BEGIN
  SELECT o.status INTO org_state FROM public.organization o WHERE o.id = org;
  IF org_state IS DISTINCT FROM 'deleting' THEN
    RAISE EXCEPTION 'paddock_offboard_reissue_uninstalls: organization % is not being deleted', org
      USING ERRCODE = 'insufficient_privilege';
  END IF;
  locked := ARRAY(
    SELECT d.id FROM public.device d
    WHERE d.organization_id = org AND d.uninstalled_at IS NULL AND d.state NOT IN ('retired', 'rejected')
    ORDER BY d.id FOR NO KEY UPDATE);
  WITH issued AS (
    INSERT INTO public.device_command (id, organization_id, device_id, type, params, status, issued_at, expires_at)
    SELECT uuidv7(), d.organization_id, d.id, 'uninstall', p_params, 'pending', p_issued_at, p_expires_at
    FROM public.device d LEFT JOIN public.device_command c ON c.id = d.uninstall_command_id AND c.organization_id = org
    WHERE d.organization_id = org AND d.id = ANY(locked)
      AND NOT (d.uninstall_requested_at IS NOT NULL AND d.uninstalled_at IS NULL AND c.id IS NOT NULL
        AND (c.status IN ('delivered', 'succeeded') OR (c.status = 'pending' AND c.expires_at > p_issued_at)))
    ORDER BY d.id
    RETURNING id AS cid, device_id AS did
  ), marked AS (
    UPDATE public.device d SET uninstall_requested_at = p_issued_at, uninstall_mode = 'leave', uninstall_command_id = i.cid,
      uninstalled_at = NULL, uninstall_reason = 'organization_offboarding'
    FROM issued i WHERE d.organization_id = org AND d.id = i.did
    RETURNING d.id
  )
  SELECT count(*) INTO reissued FROM marked;
  RETURN reissued;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION paddock_offboard_reissue_uninstalls(jsonb, timestamptz, timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION paddock_offboard_reissue_uninstalls(jsonb, timestamptz, timestamptz) TO paddock_worker;

-- +goose Down
