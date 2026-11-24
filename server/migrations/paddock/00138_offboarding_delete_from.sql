-- The deletion's database step inside the round budget (plan M17 amendment 2026-11-16 q points 5 and 6, ticket
-- PDK-1068). paddock_offboard_delete_batch (00126) starts at the first registered table on every call; on a large
-- organization the step was one unbounded call sequence that held the whole round. paddock_offboard_delete_batch_from
-- starts at a stored position instead, so the step yields between batches when the round's budget is spent and resumes
-- at the table it reached. paddock_offboard_delete_batch stays for compatibility (ADR 0052 decision 4). A straggler row
-- written into an earlier table after the step passed it is caught by paddock_offboard_finalize (00132), whose 40001
-- sends the deletion back to the database step at position NULL. Forward-only: there is no Down migration.
-- +goose Up

-- The database step's position: the delete_order it reached; NULL is the start. Written by the platform role with the
-- batch's count.
ALTER TABLE organization ADD COLUMN offboarding_db_order int;

-- Same owner, search path, organization source, status check and per-table statements as paddock_offboard_delete_batch
-- (00126, whose comment explains the ctid list, the self-reference guard and the re-check that raises 40001). It
-- returns exactly one row: the rows deleted and the delete_order of the table it worked on; (0, NULL) means nothing is
-- left from from_order on. A NULL from_order starts at the first registered table.
-- +goose StatementBegin
CREATE FUNCTION paddock_offboard_delete_batch_from(max_rows int, from_order int)
  RETURNS TABLE (deleted bigint, at_order int)
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, public, pg_temp AS $$
DECLARE
  org       uuid := current_setting('paddock.org_id')::uuid;
  org_state text;
  reg       record;
  guard     text;
  n         bigint;
  remaining boolean;
  deletable boolean := false;
BEGIN
  IF max_rows IS NULL OR max_rows < 1 OR max_rows > 10000 THEN
    RAISE EXCEPTION 'paddock_offboard_delete_batch_from: max_rows must be between 1 and 10000'
      USING ERRCODE = 'invalid_parameter_value';
  END IF;
  SELECT o.status INTO org_state FROM public.organization o WHERE o.id = org;
  IF org_state IS DISTINCT FROM 'deleting' THEN
    RAISE EXCEPTION 'paddock_offboard_delete_batch_from: organization % is not being deleted', org
      USING ERRCODE = 'insufficient_privilege';
  END IF;
  FOR reg IN SELECT r.table_name, r.delete_order, format('public.%I', r.table_name)::regclass AS rel
             FROM public.offboarding_table r
             WHERE from_order IS NULL OR r.delete_order >= from_order
             ORDER BY r.delete_order LOOP
    SELECT coalesce(string_agg(format(' AND NOT EXISTS (SELECT 1 FROM public.%I c WHERE c.ctid <> y.ctid AND %s)',
             reg.table_name,
             (SELECT string_agg(format('c.%I = y.%I', ca.attname, pa.attname), ' AND ' ORDER BY k.ord)
              FROM unnest(con.conkey, con.confkey) WITH ORDINALITY AS k(ck, pk, ord)
              JOIN pg_catalog.pg_attribute ca ON ca.attrelid = con.conrelid AND ca.attnum = k.ck
              JOIN pg_catalog.pg_attribute pa ON pa.attrelid = con.confrelid AND pa.attnum = k.pk)), ''), '')
      INTO guard
      FROM pg_catalog.pg_constraint con
      WHERE con.contype = 'f' AND con.conrelid = reg.rel AND con.confrelid = reg.rel AND con.confdeltype IN ('a', 'r');
    EXECUTE format('WITH d AS (DELETE FROM public.%1$I x WHERE x.ctid = ANY (ARRAY(SELECT y.ctid FROM public.%1$I y '
                   'WHERE y.organization_id = $1%2$s LIMIT $2)) AND x.organization_id = $1 RETURNING 1) '
                   'SELECT count(*) FROM d', reg.table_name, guard)
      INTO n USING org, max_rows;
    IF n > 0 THEN
      deleted := n;
      at_order := reg.delete_order;
      RETURN NEXT;
      RETURN;
    END IF;
    EXECUTE format('SELECT EXISTS (SELECT 1 FROM public.%I WHERE organization_id = $1)', reg.table_name)
      INTO remaining USING org;
    IF remaining THEN
      IF guard <> '' THEN
        EXECUTE format('SELECT EXISTS (SELECT 1 FROM public.%I y WHERE y.organization_id = $1%s)', reg.table_name, guard)
          INTO deletable USING org;
      END IF;
      IF guard = '' OR deletable THEN
        RAISE EXCEPTION 'paddock_offboard_delete_batch_from: rows of % changed during the batch', reg.table_name
          USING ERRCODE = 'serialization_failure';
      END IF;
      RAISE EXCEPTION 'paddock_offboard_delete_batch_from: rows of % remain in a reference cycle', reg.table_name
        USING ERRCODE = 'foreign_key_violation';
    END IF;
  END LOOP;
  deleted := 0;
  at_order := NULL;
  RETURN NEXT;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION paddock_offboard_delete_batch_from(int, int) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION paddock_offboard_delete_batch_from(int, int) TO paddock_worker;

-- +goose Down
