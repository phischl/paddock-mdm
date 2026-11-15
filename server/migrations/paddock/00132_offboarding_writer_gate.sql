-- No writer survives an organization in status deleting (plan M17 amendments 2026-11-14 d and i, 2026-11-15 j, ADR
-- 0052 decision 4, PDK-1038). paddock_offboard_delete_batch (00126) is correct per statement but cannot see a row
-- committed after its re-check, so a final 0 alone does not prove the organization empty. Every organization
-- transaction of the application (db.OrgPool.InOrg, InOrgSnapshot) passes the gate: db keeps a per-process set of
-- inactive organizations, re-read every second through paddock_inactive_organizations, refuses an organization that
-- is deleting or deleted from it, and reads the status in the transaction when the set is older than 5 s (amendment j
-- points 1 to 3). No advisory lock is involved. paddock_offboard_quiesce waits on virtual transaction IDs, as CREATE
-- INDEX CONCURRENTLY does, until every transaction that could have passed the gate on a stale set has ended;
-- paddock_offboard_finalize then re-counts every registered table and writes the tombstone in the same transaction
-- (amendment j's addendum). It needs no statistics grant: pg_locks and the usename and datname columns of
-- pg_stat_activity are readable by every role. Prepared transactions are not used (max_prepared_transactions 0); if
-- two-phase commit is ever enabled, quiesce MUST also wait on pg_prepared_xacts. Only the offboarding job enters
-- without the gate (db.OrgPool.InOrgOffboarding).
-- The plan's file name is 00132 (amendment i: PDK-1026 takes 00131 and merges first). Forward-only: there is no Down
-- migration.
-- +goose Up

-- The gate's set of inactive organizations, polled by every process that opens organization transactions before any
-- organization context exists. It reveals the ID and status of deleting and deleted organizations only, and the
-- database's time of the read.
-- +goose StatementBegin
CREATE FUNCTION paddock_inactive_organizations() RETURNS TABLE (id uuid, status text, checked_at timestamptz)
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public, pg_temp AS
  $$ SELECT o.id, o.status, now() FROM public.organization o WHERE o.status IN ('deleting', 'deleted') $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION paddock_inactive_organizations() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION paddock_inactive_organizations() TO paddock_api, paddock_worker, paddock_compiler,
  paddock_notifier, paddock_escrow_reader, paddock_revocation;

-- The gate's status read runs as the pool's own role. Escrow reader and revocation issuer had no read on organization;
-- they get the ID and status of their own organization only (amendment i point 6). A role that reads no row for its own
-- organization would pass the gate.
GRANT SELECT (id, status) ON organization TO paddock_escrow_reader, paddock_revocation;
CREATE POLICY org_gate_self ON organization FOR SELECT TO paddock_escrow_reader, paddock_revocation
  USING (id = current_setting('paddock.org_id')::uuid);

-- The wait of quiesce: deleting_committed_at is a moment at which the status deleting was certainly committed; the wait
-- set is the virtual transaction IDs of organization-role transactions open at or after deleting_committed_at + 6 s
-- (the gate's 5 s staleness bound plus 1 s of margin), taken once per deletion.
ALTER TABLE organization
  ADD COLUMN deleting_committed_at timestamptz,
  ADD COLUMN offboarding_wait_vxids text[],
  ADD COLUMN offboarding_wait_taken_at timestamptz;

-- Every transaction that could still have passed the gate on a set read before the status change started before the
-- cutoff; a transaction started later reads a set taken after the change (amendment j point 2). The wait set is taken
-- after the cutoff, so it holds every such transaction still open, and it only shrinks: new traffic cannot starve the
-- wait. The first call after the status change stores deleting_committed_at in its own transaction, after the commit of
-- the change. Returns false while waiting; it commits what it stored, so the job keeps it across rounds. The row lock
-- is FOR NO KEY UPDATE: an open writer's foreign-key share lock must not make quiesce block instead of answering.
-- +goose StatementBegin
CREATE FUNCTION paddock_offboard_quiesce() RETURNS boolean
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, public, pg_temp AS $$
DECLARE
  org       uuid := current_setting('paddock.org_id')::uuid;
  org_state text;
  committed timestamptz;
  waiting   text[];
BEGIN
  SELECT o.status, o.deleting_committed_at, o.offboarding_wait_vxids INTO org_state, committed, waiting
  FROM public.organization o WHERE o.id = org FOR NO KEY UPDATE;
  IF org_state IS DISTINCT FROM 'deleting' THEN
    RAISE EXCEPTION 'paddock_offboard_quiesce: organization % is not being deleted', org
      USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF committed IS NULL THEN
    UPDATE public.organization SET deleting_committed_at = now() WHERE id = org;
    RETURN false;
  END IF;
  IF waiting IS NULL THEN
    IF now() < committed + interval '6 seconds' THEN
      RETURN false;
    END IF;
    waiting := ARRAY(
      SELECT l.virtualxid FROM pg_catalog.pg_locks l JOIN pg_catalog.pg_stat_activity a ON a.pid = l.pid
      WHERE l.locktype = 'virtualxid' AND l.granted AND l.pid <> pg_catalog.pg_backend_pid()
        AND a.datname = pg_catalog.current_database()
        AND a.usename IN ('paddock_api', 'paddock_gateway', 'paddock_worker', 'paddock_compiler', 'paddock_notifier',
                          'paddock_escrow_reader', 'paddock_revocation')
      ORDER BY 1);
    UPDATE public.organization SET offboarding_wait_vxids = waiting, offboarding_wait_taken_at = now() WHERE id = org;
  END IF;
  RETURN NOT EXISTS (SELECT 1 FROM pg_catalog.pg_locks l
                     WHERE l.locktype = 'virtualxid' AND l.granted AND l.virtualxid = ANY (waiting));
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION paddock_offboard_quiesce() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION paddock_offboard_quiesce() TO paddock_worker;

-- The tombstone is written in the same transaction as the count, and only once quiesce has nothing left to wait for:
-- every row a transaction that passed the gate could write is committed by then, so the count sees it. EXISTS per
-- table stops at the first row; a remaining row raises the retryable serialization_failure, and the job returns to its
-- database step, keeping the wait set. A call before the wait has ended is a caller error
-- (object_not_in_prerequisite_state). The columns set are those of the query TombstoneOrganization, plus the wait
-- columns.
-- +goose StatementBegin
CREATE FUNCTION paddock_offboard_finalize() RETURNS void
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, public, pg_temp AS $$
DECLARE
  org       uuid := current_setting('paddock.org_id')::uuid;
  org_state text;
  reg       record;
  remaining boolean;
BEGIN
  SELECT o.status INTO org_state FROM public.organization o WHERE o.id = org FOR UPDATE;
  IF org_state IS DISTINCT FROM 'deleting' THEN
    RAISE EXCEPTION 'paddock_offboard_finalize: organization % is not being deleted', org
      USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF NOT public.paddock_offboard_quiesce() THEN
    RAISE EXCEPTION 'paddock_offboard_finalize: organization % still waits for open transactions', org
      USING ERRCODE = 'object_not_in_prerequisite_state';
  END IF;
  FOR reg IN SELECT r.table_name FROM public.offboarding_table r ORDER BY r.delete_order LOOP
    EXECUTE format('SELECT EXISTS (SELECT 1 FROM public.%I WHERE organization_id = $1)', reg.table_name)
      INTO remaining USING org;
    IF remaining THEN
      RAISE EXCEPTION 'paddock_offboard_finalize: rows of % remain', reg.table_name
        USING ERRCODE = 'serialization_failure';
    END IF;
  END LOOP;
  UPDATE public.organization
  SET status = 'deleted', deleted_at = now(), domains = '{}', offboarding_error_code = NULL, idp_ensured_at = NULL,
      idp_ensure_revision = NULL, offboarding_wait_vxids = NULL, offboarding_wait_taken_at = NULL, updated_at = now()
  WHERE id = org;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION paddock_offboard_finalize() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION paddock_offboard_finalize() TO paddock_worker;

-- Rounds skip an organization that is deleting or deleted (amendment d point 4): every one of its transactions would
-- be refused, and a tombstone stays forever. Callers that need these organizations use the platform pool.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION paddock_organization_ids() RETURNS SETOF uuid
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS
  $$ SELECT id FROM organization WHERE status NOT IN ('deleting', 'deleted') ORDER BY id $$;
-- +goose StatementEnd

-- +goose Down
