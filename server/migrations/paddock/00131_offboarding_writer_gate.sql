-- No writer survives an organization in status deleting (plan M17 amendment 2026-11-14 d, ADR 0052 decision 4,
-- PDK-1038). paddock_offboard_delete_batch (00126) is correct per statement but cannot see a row committed after its
-- re-check, so a final 0 alone does not prove the organization empty. Every organization transaction of the
-- application (db.OrgPool.InOrg, InOrgSnapshot) now enters through paddock_org_enter, which refuses an organization
-- that is deleting or deleted (SQLSTATE PD001) and otherwise holds the organization's offboarding lock shared until the
-- transaction ends. paddock_offboard_finalize takes the same lock exclusively, so it waits for every transaction that
-- entered before deleting was committed, re-counts every registered table and writes the tombstone in the same
-- transaction. Only the offboarding job enters without the gate (db.OrgPool.InOrgOffboarding). The plan's file name
-- is <next>; 00129 and 00130 are taken by PDK-1014 and PDK-814. Forward-only: there is no Down migration.
-- +goose Up

-- The single SQL derivation of the offboarding lock key; db.OffboardingLockKey is the same in Go (tested). The two
-- halves of the UUID and the namespace "padd obd" are combined by XOR, in the single-bigint key space of the leader
-- locks, whose keys are ASCII constants of the same form. No SET clause: it would stop the planner from inlining the
-- function into every organization transaction; it is not a definer function, and its callers pin the search path.
CREATE FUNCTION paddock_offboarding_lock_key(org uuid) RETURNS bigint
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE AS $$
  SELECT (('x' || substr(h, 1, 16))::bit(64) # ('x' || substr(h, 17, 16))::bit(64) # x'70616464206f6264')::bigint
  FROM (SELECT replace(org::text, '-', '') AS h) k
$$;
REVOKE ALL ON FUNCTION paddock_offboarding_lock_key(uuid) FROM PUBLIC;

-- The status is read before the lock as well: a transaction of an organization that is already deleting must fail at
-- once instead of queueing behind a waiting finalize and holding a pool connection meanwhile. The read after the lock
-- is mandatory (plan M17 amendment f point 4): it closes the race with a deleting committed between the first read and
-- the lock (READ COMMITTED takes a new snapshot per statement; a REPEATABLE READ transaction of InOrgSnapshot is
-- read-only and cannot leave rows behind). The refusal carries the status as DETAIL, which the audit event of the
-- refused action records. An organization without a row passes: RLS still applies, and there is nothing to protect.
-- +goose StatementBegin
CREATE FUNCTION paddock_org_enter() RETURNS void
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, public, pg_temp AS $$
DECLARE
  org       uuid := current_setting('paddock.org_id')::uuid;
  org_state text;
BEGIN
  SELECT o.status INTO org_state FROM public.organization o WHERE o.id = org;
  IF org_state IN ('deleting', 'deleted') THEN
    RAISE EXCEPTION 'paddock_org_enter: organization % is not available', org
      USING ERRCODE = 'PD001', DETAIL = org_state;
  END IF;
  PERFORM pg_catalog.pg_advisory_xact_lock_shared(public.paddock_offboarding_lock_key(org));
  SELECT o.status INTO org_state FROM public.organization o WHERE o.id = org;
  IF org_state IN ('deleting', 'deleted') THEN
    RAISE EXCEPTION 'paddock_org_enter: organization % is not available', org
      USING ERRCODE = 'PD001', DETAIL = org_state;
  END IF;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION paddock_org_enter() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION paddock_org_enter()
  TO paddock_api, paddock_worker, paddock_compiler, paddock_escrow_reader, paddock_revocation, paddock_notifier;

-- The tombstone is written here, under the exclusive lock, so no transaction that entered before deleting can commit
-- a row between the count and the status change. EXISTS per table stops at the first row; a remaining row raises the
-- retryable serialization_failure, and the job returns to its database step. The columns set are those of the query
-- TombstoneOrganization.
-- +goose StatementBegin
CREATE FUNCTION paddock_offboard_finalize() RETURNS void
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, public, pg_temp AS $$
DECLARE
  org       uuid := current_setting('paddock.org_id')::uuid;
  org_state text;
  reg       record;
  remaining boolean;
BEGIN
  PERFORM pg_catalog.pg_advisory_xact_lock(public.paddock_offboarding_lock_key(org));
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
