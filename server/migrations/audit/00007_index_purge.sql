-- Index purge (ADR 0032 §3, plan M10 decision 22 and its amendment of 2026-10-30): drops one monthly partition of
-- audit_event once every event in it was recorded more than p_days before the database's now(). Owner-executed like
-- audit_ensure_partition; the writer keeps no DELETE grant. Forward-only: there is no Down migration.
-- +goose Up
-- +goose StatementBegin
CREATE FUNCTION public.audit_purge_partition(p_month date, p_days integer)
  RETURNS TABLE (dropped boolean, events bigint, reason text, cutoff timestamptz, relid bigint)
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public, pg_temp SET TimeZone = 'UTC' AS $$
DECLARE
  start_ts date := date_trunc('month', p_month)::date;
  end_ts   date := (date_trunc('month', p_month) + interval '1 month')::date;
  part     text := format('audit_event_%s', to_char(start_ts, 'YYYY_MM'));
  v_cutoff timestamptz;
  v_relid  oid;
  n        bigint;
  newest   timestamptz;
BEGIN
  -- The writer role may call this directly, so the WORM retention floor (auditwriter.MinRetentionDays) is enforced
  -- here as well, not only in Go: no caller can drop events younger than the bucket's default retention. The cutoff
  -- comes from the database's clock, so a writer whose clock runs ahead cannot trip the floor.
  IF p_days IS NULL OR p_days < 400 THEN
    RAISE EXCEPTION 'audit_purge_partition: % days is below the minimum retention of 400 days', p_days
      USING ERRCODE = '22023';
  END IF;
  v_cutoff := now() - make_interval(days => p_days);
  v_relid := to_regclass(format('public.%I', part))::oid;
  IF v_relid IS NULL THEN
    RETURN QUERY SELECT false, 0::bigint, 'no such partition', v_cutoff, NULL::bigint; RETURN;
  END IF;
  IF end_ts::timestamptz > v_cutoff THEN
    RETURN QUERY SELECT false, 0::bigint, 'month not past the cutoff', v_cutoff, v_relid::bigint; RETURN;
  END IF;
  -- Locked before the count (PDK-140): otherwise a late event committed between the count and the DETACH, which
  -- waits for it, is dropped although it was recorded within the retention. Parent first, as every insert locks it.
  -- recorded_at has no index, so the scan runs under the lock; lock_timeout bounds the wait, the writer's
  -- transaction timeout the scan (sizing note in the plan's amendment of 2026-10-30).
  EXECUTE format('LOCK TABLE ONLY public.audit_event, public.%I IN ACCESS EXCLUSIVE MODE', part);
  EXECUTE format('SELECT count(*), max(recorded_at) FROM public.%I', part) INTO n, newest;
  IF newest IS NOT NULL AND newest >= v_cutoff THEN
    RETURN QUERY SELECT false, n, 'late events still within retention', v_cutoff, v_relid::bigint; RETURN;
  END IF;
  EXECUTE format('ALTER TABLE public.audit_event DETACH PARTITION public.%I', part);
  EXECUTE format('DROP TABLE public.%I', part);
  RETURN QUERY SELECT true, n, 'dropped', v_cutoff, v_relid::bigint;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION public.audit_purge_partition(date, integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.audit_purge_partition(date, integer) TO paddock_audit_writer;
-- +goose Down
