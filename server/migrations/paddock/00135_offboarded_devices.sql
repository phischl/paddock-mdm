-- The hand-over of a deleting organization's devices to offboarded_device (plan M17 decision 15, amendment e point 10,
-- amendments m and n, ticket PDK-1016). The worker has no INSERT on device_command and no UPDATE on device; as in 00134
-- it gets no table grant, only a SECURITY DEFINER function that refuses unless the context organization is deleting.
-- Forward-only: there is no Down migration.
-- +goose Up

-- A device is handed over with two signed commands, the disarm of the dead man's switch and the uninstall (amendment n
-- point 2): [{"command_id": "<uuid>", "envelope": "<base64 DSSE envelope>"}]. The table was always empty before this
-- migration, since nothing wrote it.
ALTER TABLE offboarded_device
  DROP COLUMN command_id,
  DROP COLUMN command_envelope,
  ADD COLUMN command_envelopes jsonb NOT NULL CHECK (jsonb_typeof(command_envelopes) = 'array');

-- Locks every device of the context organization that may still contact the server (no reported removal, neither
-- retired nor rejected, and approved at least once: a device still pending has no bundle and cannot verify a command,
-- amendment m point 1, ticket PDK-1061; they are only counted, in devices.pending_dropped) and, in a constant number of statements independent of the device count (amendment e point 5):
--   1. gives each a delete_self_lock valid for the retention (amendment n point 1), unless the hand-over already gave
--      it one (a repeated step: only the hand-over issues a disarm living longer than the 30 days of the type);
--   2. replaces a kept uninstall that is still pending but expires more than 30 days before the retention ends by one
--      with the same mode and params, valid for the retention, and cancels the old one (amendment m point 2). The
--      margin keeps the deletion request's own leave (valid delete_after + 365 days, so only the step's delay short of
--      the retention): replacing it would hand a returning device two uninstalls, and the old one may already sit on a
--      device whose delivery mark was dropped while the organization was deleting (amendment f point 2). An
--      administrator's uninstall (7 days) is always replaced while it is still valid; one that has already lapsed is
--      not renewed with its mode (the administrator's intent lapsed with it) and gets a fresh leave in step 3;
--   3. gives a fresh uninstall (mode leave, reason organization_offboarding) to every device without an open uninstall
--      it can still act on (delivered or succeeded, or pending and unexpired: the expiry sweep runs through the gate and
--      stops once the organization is deleting, so a lapsed command can still be pending): also with an open Lock or
--      Destroy, which cannot be served once the organization is gone.
-- The disarm is inserted first, so its UUIDv7 sorts before a fresh uninstall. The leave's params are built here, never
-- taken from the caller (least privilege, as 00134). The counts of every call are added to the organization's
-- offboarding_counts (devices.disarms_issued, devices.uninstalls_reissued; devices.pending_dropped is set, not added) in the same transaction, so a repeated step
-- reports what all its attempts issued; the call returns this call's uninstalls. The organization comes only from the
-- transaction's paddock.org_id (no missing_ok: no context fails closed); every statement is filtered by it, because
-- paddock_owner bypasses RLS.
-- +goose StatementBegin
CREATE FUNCTION paddock_offboard_reissue_uninstalls() RETURNS bigint
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, public, pg_temp AS $$
DECLARE
  org        uuid := current_setting('paddock.org_id')::uuid;
  org_state  text;
  locked     uuid[];
  v_issued   timestamptz := date_trunc('second', now());
  v_expires  timestamptz := date_trunc('second', now()) + interval '365 days';
  disarms    bigint;
  replaced   bigint;
  fresh      bigint;
  dropped    bigint;
BEGIN
  SELECT o.status INTO org_state FROM public.organization o WHERE o.id = org;
  IF org_state IS DISTINCT FROM 'deleting' THEN
    RAISE EXCEPTION 'paddock_offboard_reissue_uninstalls: organization % is not being deleted', org
      USING ERRCODE = 'insufficient_privilege';
  END IF;
  locked := ARRAY(
    SELECT d.id FROM public.device d
    WHERE d.organization_id = org AND d.uninstalled_at IS NULL AND d.state NOT IN ('pending', 'retired', 'rejected')
    ORDER BY d.id FOR NO KEY UPDATE);

  INSERT INTO public.device_command (id, organization_id, device_id, type, params, status, issued_at, expires_at)
  SELECT uuidv7(), org, d.id, 'delete_self_lock', '{}'::jsonb, 'pending', v_issued, v_expires
  FROM public.device d
  WHERE d.organization_id = org AND d.id = ANY(locked)
    AND NOT EXISTS (
      SELECT 1 FROM public.device_command c
      WHERE c.organization_id = org AND c.device_id = d.id AND c.type = 'delete_self_lock'
        AND c.status IN ('pending', 'delivered', 'succeeded') AND c.expires_at > v_issued + interval '31 days')
  ORDER BY d.id;
  GET DIAGNOSTICS disarms = ROW_COUNT;

  WITH stale AS (
    UPDATE public.device_command c SET status = 'cancelled', finished_at = now()
    FROM public.device d
    WHERE d.organization_id = org AND d.id = ANY(locked) AND c.organization_id = org AND c.id = d.uninstall_command_id
      AND d.uninstall_requested_at IS NOT NULL AND c.status = 'pending' AND c.expires_at > v_issued
      AND c.expires_at < v_expires - interval '30 days'
    RETURNING c.device_id, c.params
  ), issued AS (
    INSERT INTO public.device_command (id, organization_id, device_id, type, params, status, issued_at, expires_at)
    SELECT uuidv7(), org, s.device_id, 'uninstall', s.params, 'pending', v_issued, v_expires FROM stale s ORDER BY s.device_id
    RETURNING id AS cid, device_id AS did
  ), marked AS (
    UPDATE public.device d SET uninstall_command_id = i.cid
    FROM issued i WHERE d.organization_id = org AND d.id = i.did
    RETURNING d.id
  )
  SELECT count(*) INTO replaced FROM marked;

  WITH issued AS (
    INSERT INTO public.device_command (id, organization_id, device_id, type, params, status, issued_at, expires_at)
    SELECT uuidv7(), org, d.id, 'uninstall', '{"mode":"leave"}'::jsonb, 'pending', v_issued, v_expires
    FROM public.device d LEFT JOIN public.device_command c ON c.id = d.uninstall_command_id AND c.organization_id = org
    WHERE d.organization_id = org AND d.id = ANY(locked)
      AND NOT (d.uninstall_requested_at IS NOT NULL AND d.uninstalled_at IS NULL AND c.id IS NOT NULL
        AND (c.status IN ('delivered', 'succeeded') OR (c.status = 'pending' AND c.expires_at > v_issued)))
    ORDER BY d.id
    RETURNING id AS cid, device_id AS did
  ), marked AS (
    UPDATE public.device d SET uninstall_requested_at = v_issued, uninstall_mode = 'leave', uninstall_command_id = i.cid,
      uninstalled_at = NULL, uninstall_reason = 'organization_offboarding'
    FROM issued i WHERE d.organization_id = org AND d.id = i.did
    RETURNING d.id
  )
  SELECT count(*) INTO fresh FROM marked;

  SELECT count(*) INTO dropped FROM public.device d WHERE d.organization_id = org AND d.state = 'pending';

  UPDATE public.organization o SET offboarding_counts = o.offboarding_counts
    || jsonb_build_object('devices.pending_dropped', dropped)
    || jsonb_build_object('devices.disarms_issued', coalesce((o.offboarding_counts ->> 'devices.disarms_issued')::bigint, 0) + disarms,
                          'devices.uninstalls_reissued', coalesce((o.offboarding_counts ->> 'devices.uninstalls_reissued')::bigint, 0) + replaced + fresh)
  WHERE o.id = org;
  RETURN replaced + fresh;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION paddock_offboard_reissue_uninstalls() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION paddock_offboard_reissue_uninstalls() TO paddock_worker;

-- +goose Down
