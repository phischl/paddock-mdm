-- Index purge (ADR 0032 §3, plan M10 decision 22): drops one monthly partition of audit_event once every event in it
-- was recorded before the cutoff. Owner-executed like audit_ensure_partition; the writer keeps no DELETE grant.
-- Forward-only: there is no Down migration.
-- +goose Up
-- +goose StatementBegin
CREATE FUNCTION audit_purge_partition(p_month date, p_cutoff timestamptz)
  RETURNS TABLE (dropped boolean, events bigint, reason text)
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  start_ts date := date_trunc('month', p_month)::date;
  end_ts   date := (date_trunc('month', p_month) + interval '1 month')::date;
  part     text := format('audit_event_%s', to_char(start_ts, 'YYYY_MM'));
  n        bigint;
  newest   timestamptz;
BEGIN
  IF to_regclass(part) IS NULL THEN
    RETURN QUERY SELECT false, 0::bigint, 'no such partition'; RETURN;
  END IF;
  IF end_ts::timestamptz > p_cutoff THEN
    RETURN QUERY SELECT false, 0::bigint, 'month not past the cutoff'; RETURN;
  END IF;
  -- Locked before the count (PDK-140): otherwise a late event committed between the count and the DETACH, which
  -- waits for it, is dropped although it was recorded within the retention. Parent first, as every insert locks it.
  EXECUTE format('LOCK TABLE ONLY audit_event, %I IN ACCESS EXCLUSIVE MODE', part);
  EXECUTE format('SELECT count(*), max(recorded_at) FROM %I', part) INTO n, newest;
  IF newest IS NOT NULL AND newest >= p_cutoff THEN
    RETURN QUERY SELECT false, n, 'late events still within retention'; RETURN;
  END IF;
  EXECUTE format('ALTER TABLE audit_event DETACH PARTITION %I', part);
  EXECUTE format('DROP TABLE %I', part);
  RETURN QUERY SELECT true, n, 'dropped';
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION audit_purge_partition(date, timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION audit_purge_partition(date, timestamptz) TO paddock_audit_writer;
-- +goose Down
