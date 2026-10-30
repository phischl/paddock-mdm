-- Pins the lookups of audit_ensure_partition of 00001 (PDK-558, found in the PDK-140 review): the old
-- SET search_path = public left pg_temp searched first, so a writer session could shadow audit_event or a partition
-- with a temporary table. With a fixed search_path (pg_temp last) and schema-qualified names nothing can. The body is
-- otherwise unchanged; grants stay with the function. Forward-only: there is no Down migration.
-- +goose Up
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.audit_ensure_partition(p_month date) RETURNS void
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public, pg_temp AS $$
DECLARE
  start_ts date := date_trunc('month', p_month)::date;
  end_ts   date := (date_trunc('month', p_month) + interval '1 month')::date;
  part     text := format('audit_event_%s', to_char(start_ts, 'YYYY_MM'));
BEGIN
  EXECUTE format('CREATE TABLE IF NOT EXISTS public.%I PARTITION OF public.audit_event FOR VALUES FROM (%L) TO (%L)',
                 part, start_ts, end_ts);
END $$;
-- +goose StatementEnd

-- +goose Down
