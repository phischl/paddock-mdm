-- Index purge (ADR 0032 §3, plan M10 decision 22 and its amendment of 2026-10-30): drops one monthly partition of
-- audit_event once every event in it was recorded before the cutoff. Owner-executed like audit_ensure_partition; the
-- writer keeps no DELETE grant. Forward-only: there is no Down migration.
-- +goose Up
-- +goose StatementBegin
CREATE FUNCTION public.audit_purge_partition(p_month date, p_cutoff timestamptz)
  RETURNS TABLE (dropped boolean, events bigint, reason text)
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public, pg_temp AS $$
DECLARE
  start_ts date := date_trunc('month', p_month)::date;
  end_ts   date := (date_trunc('month', p_month) + interval '1 month')::date;
  part     text := format('audit_event_%s', to_char(start_ts, 'YYYY_MM'));
  n        bigint;
  newest   timestamptz;
BEGIN
  -- The writer role may call this directly, so the WORM retention floor (auditwriter.MinRetentionDays) is enforced
  -- here as well, not only in Go: no caller can drop events younger than the bucket's default retention.
  IF p_cutoff IS NULL OR p_cutoff > now() - interval '400 days' THEN
    RAISE EXCEPTION 'audit_purge_partition: cutoff % is within the minimum retention of 400 days', p_cutoff
      USING ERRCODE = '22023';
  END IF;
  IF to_regclass(format('public.%I', part)) IS NULL THEN
    RETURN QUERY SELECT false, 0::bigint, 'no such partition'; RETURN;
  END IF;
  IF end_ts::timestamptz > p_cutoff THEN
    RETURN QUERY SELECT false, 0::bigint, 'month not past the cutoff'; RETURN;
  END IF;
  -- Locked before the count (PDK-140): otherwise a late event committed between the count and the DETACH, which
  -- waits for it, is dropped although it was recorded within the retention. Parent first, as every insert locks it.
  -- recorded_at has no index, so the scan runs under the lock; lock_timeout bounds the wait, the writer's
  -- transaction timeout the scan (sizing note in the plan's amendment of 2026-10-30).
  EXECUTE format('LOCK TABLE ONLY public.audit_event, public.%I IN ACCESS EXCLUSIVE MODE', part);
  EXECUTE format('SELECT count(*), max(recorded_at) FROM public.%I', part) INTO n, newest;
  IF newest IS NOT NULL AND newest >= p_cutoff THEN
    RETURN QUERY SELECT false, n, 'late events still within retention'; RETURN;
  END IF;
  EXECUTE format('ALTER TABLE public.audit_event DETACH PARTITION public.%I', part);
  EXECUTE format('DROP TABLE public.%I', part);
  RETURN QUERY SELECT true, n, 'dropped';
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION public.audit_purge_partition(date, timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.audit_purge_partition(date, timestamptz) TO paddock_audit_writer;
-- +goose Down
