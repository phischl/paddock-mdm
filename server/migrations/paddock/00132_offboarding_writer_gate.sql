-- No writer survives an organization in status deleting (plan M17 amendments 2026-11-14 d and i, 2026-11-15 j, ADR
-- 0052 decision 4, PDK-1038). paddock_offboard_delete_batch (00126) is correct per statement but cannot see a row
-- committed after its re-check, so a final 0 alone does not prove the organization empty. Every organization
-- transaction of the application (db.OrgPool.InOrg, InOrgSnapshot) passes the gate: db keeps a per-process set of
-- inactive organizations, re-read every second through paddock_inactive_organizations, refuses an organization that
-- is deleting or deleted from it, and reads the status in the transaction when the set is older than 5 s (amendment j
-- points 1 to 3). No advisory lock is involved. paddock_offboard_finalize re-counts every registered table and writes
-- the tombstone in the same transaction. Only the offboarding job enters without the gate (db.OrgPool.InOrgOffboarding).
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

-- The tombstone is written in the same transaction as the count. EXISTS per table stops at the first row; a remaining
-- row raises the retryable serialization_failure, and the job returns to its database step. The columns set are those
-- of the query TombstoneOrganization. Not yet sufficient on its own: the wait for transactions that passed the gate on
-- a set taken before the status change (amendment j's addendum, PR #663) is still to be added before PDK-1038 merges.
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
      idp_ensure_revision = NULL, updated_at = now()
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
