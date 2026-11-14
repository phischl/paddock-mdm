-- No writer survives an organization in status deleting (plan M17 amendments 2026-11-14 d and i, ADR 0052 decision 4,
-- PDK-1038). paddock_offboard_delete_batch (00126) is correct per statement but cannot see a row committed after its
-- re-check, so a final 0 alone does not prove the organization empty. Every organization transaction of the
-- application (db.OrgPool.InOrg, InOrgSnapshot) holds the organization's offboarding lock shared until it ends and
-- reads the organization's status after taking it; db refuses an organization that is deleting or deleted. The gate is
-- plain SQL sent by db (amendment i): no function of Paddock's own runs per transaction. paddock_offboard_finalize
-- takes the same lock exclusively, waiting at most lock_timeout (1 s, else lock_not_available, 55P03), then re-counts
-- every registered table and writes the tombstone in the same transaction. Only the offboarding job enters without
-- the gate (db.OrgPool.InOrgOffboarding). The plan's file name is 00132 (amendment i: PDK-1026 takes 00131 and merges
-- first). Forward-only: there is no Down migration.
-- +goose Up

-- The single SQL derivation of the offboarding lock key; db.OffboardingLockKey is the same in Go (tested), and db
-- passes the key as a parameter, so this function runs only in finalize. The two halves of the UUID and the namespace
-- "padd obd" are combined by XOR, in the single-bigint key space of the leader locks, whose keys are ASCII constants of
-- the same form.
CREATE FUNCTION paddock_offboarding_lock_key(org uuid) RETURNS bigint
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE AS $$
  SELECT (('x' || substr(h, 1, 16))::bit(64) # ('x' || substr(h, 17, 16))::bit(64) # x'70616464206f6264')::bigint
  FROM (SELECT replace(org::text, '-', '') AS h) k
$$;
REVOKE ALL ON FUNCTION paddock_offboarding_lock_key(uuid) FROM PUBLIC;

-- The gate's status read runs as the pool's own role. Escrow reader and revocation issuer had no read on organization;
-- they get the ID and status of their own organization only (amendment i point 6). A role that reads no row for its own
-- organization would pass the gate.
GRANT SELECT (id, status) ON organization TO paddock_escrow_reader, paddock_revocation;
CREATE POLICY org_gate_self ON organization FOR SELECT TO paddock_escrow_reader, paddock_revocation
  USING (id = current_setting('paddock.org_id')::uuid);

-- The tombstone is written here, under the exclusive lock, so no transaction that entered the organization can commit
-- a row between the count and the status change. The wait for the lock is bounded by lock_timeout (1 s): a waiting
-- exclusive request makes new shared requests queue behind it, so the short holds of refused writers drain and cannot
-- starve finalize, which a pure try-lock lets them do; the bound keeps a long transaction of the organization, or a
-- nested InOrg that waits for an outer one, from holding the queue for longer than that. Not granted in time raises
-- lock_not_available (55P03) and writes nothing; the job stays in its tombstone step and tries again next round
-- (amendment i point 4 as corrected by the architect in PR #658; PDK-1038 fix round 2). EXISTS per table
-- stops at the first row; a remaining row raises the retryable serialization_failure, and the job returns to its
-- database step. The columns set are those of the query TombstoneOrganization.
-- +goose StatementBegin
CREATE FUNCTION paddock_offboard_finalize() RETURNS void
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, public, pg_temp SET lock_timeout = '1s' AS $$
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
