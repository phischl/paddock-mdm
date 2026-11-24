-- Organization offboarding, storage side (plan M17 §6 and decisions 1, 7, 8, 15, 17, 20; ADR 0052 decisions 1, 2
-- and 4). A pending deletion is an active organization with delete_after set; the worker later moves it to deleting
-- and finally leaves a tombstone in status deleted whose slug is free again. The organization's rows are deleted only
-- through paddock_offboard_delete_batch, which works through the registry offboarding_table and refuses unless the
-- organization of the transaction is already deleting. Every future table with organization_id MUST be registered
-- there (architecture §16.2; enforced by TestOffboardingRegistry). Forward-only: there is no Down migration.
-- +goose Up

ALTER TABLE organization DROP CONSTRAINT organization_status_check;
ALTER TABLE organization ADD CONSTRAINT organization_status_check
  CHECK (status IN ('provisioning','active','provisioning_failed','suspended','deleting','deleted'));
ALTER TABLE organization
  ADD COLUMN deletion_requested_at  timestamptz,
  ADD COLUMN deletion_requested_by  text,
  ADD COLUMN deletion_reason        text CHECK (char_length(deletion_reason) BETWEEN 2 AND 500),
  ADD COLUMN delete_after           timestamptz,
  ADD COLUMN offboarding_step       text,
  ADD COLUMN offboarding_error_code text,
  ADD COLUMN deleted_at             timestamptz,
  ADD COLUMN idp_ensured_at         timestamptz,
  ADD COLUMN idp_ensure_revision    text,
  ADD CONSTRAINT organization_deletion_consistent CHECK (
    (delete_after IS NULL) = (deletion_requested_at IS NULL) AND
    (status <> 'deleted' OR deleted_at IS NOT NULL));

-- A tombstone keeps its slug (decision 17), so uniqueness holds only among organizations that are not deleted.
ALTER TABLE organization DROP CONSTRAINT organization_slug_key;
CREATE UNIQUE INDEX organization_slug_live ON organization (slug) WHERE status <> 'deleted';

-- The identity round records its last full Authentik check inside the organization's own context (decision 20); the
-- worker's existing policy on organization already limits it to that row.
GRANT UPDATE (idp_ensured_at, idp_ensure_revision) ON organization TO paddock_worker;

-- No organization data, hence no RLS (RLS lint allow list). Gaps of 10 leave room for later tables.
CREATE TABLE offboarding_table (
  table_name   text PRIMARY KEY,
  delete_order int  NOT NULL UNIQUE
);
GRANT SELECT ON offboarding_table TO paddock_worker;

INSERT INTO offboarding_table (table_name, delete_order) VALUES
  ('action', 10),
  ('agent_update_report', 20),
  ('api_token', 30),
  ('bundle', 40),
  ('compile_warning', 50),
  ('device_alert', 60),
  ('device_bundle_report', 70),
  ('device_diagnostics', 80),
  ('device_disk_conversion', 90),
  ('device_event_dropped', 100),
  ('device_event_gap', 110),
  ('device_event_seen', 120),
  ('device_group_maintenance_window', 130),
  ('device_group_member', 140),
  ('device_identity_key', 150),
  ('device_inventory_ref', 160),
  ('device_login_assignment', 170),
  ('device_login_event', 180),
  ('device_owner', 190),
  ('device_resource_status', 200),
  ('device_software_status', 210),
  ('device_status', 220),
  ('device_user_seen', 230),
  ('escrow_refusal', 240),
  ('escrow_secret', 250),
  ('finding', 260),
  ('installed_software', 270),
  ('inventory_policy_result', 280),
  ('managed_file', 290),
  ('managed_unit', 300),
  ('notification_delivery_event', 310),
  ('notification_destination_state', 320),
  ('notification_pseudonym_key', 330),
  ('notification_pseudonym_lookup', 340),
  ('organization_dms_settings', 350),
  ('organization_login_settings', 360),
  ('organization_managed_file_settings', 370),
  ('organization_mcp_settings', 380),
  ('organization_privacy_settings', 390),
  ('organization_role_member', 400),
  ('organization_role_snapshot', 410),
  ('organization_rollout_settings', 420),
  ('organization_update_settings', 430),
  ('outbox', 440),
  ('package_hold', 450),
  ('profile_assignment', 460),
  ('read_audit_window', 470),
  ('retention_inventory_hold', 480),
  ('revocation_approval', 490),
  ('revocation_freeze', 500),
  ('software_assignment', 510),
  ('software_package', 520),
  ('software_repository', 530),
  ('software_request', 540),
  ('user_group_member', 550),
  ('vulnerability_finding', 560),
  ('vulnerability_summary', 570),
  ('watched_unit', 580),
  ('app_user', 590),
  ('config_rollout', 600),
  ('device_command', 610),
  ('notification_delivery', 620),
  ('permission_profile', 630),
  ('revocation_request', 640),
  ('software_catalog_entry', 650),
  ('user_group', 660),
  ('admin_account', 670),
  ('change_set', 680),
  ('device', 690),
  ('notification_destination', 700),
  ('software_source', 710),
  ('enrollment_token', 720),
  ('device_group', 730);

-- Devices that had not reported their removal when their organization was deleted (decision 15). The rows outlive
-- the organization's data, so the table is deliberately not in offboarding_table; it is platform data like
-- organization and reachable by paddock_platform only.
CREATE TABLE offboarded_device (
  device_id        uuid PRIMARY KEY,
  organization_id  uuid NOT NULL REFERENCES organization(id),
  keys             jsonb NOT NULL CHECK (jsonb_typeof(keys) = 'array'),
  command_id       uuid NOT NULL,
  command_envelope bytea NOT NULL,
  offboarded_at    timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX offboarded_device_offboarded_at_idx ON offboarded_device (offboarded_at);
ALTER TABLE offboarded_device ENABLE ROW LEVEL SECURITY;
ALTER TABLE offboarded_device FORCE ROW LEVEL SECURITY;
CREATE POLICY platform ON offboarded_device TO paddock_platform USING (true) WITH CHECK (true);
GRANT SELECT, INSERT, DELETE ON offboarded_device TO paddock_platform;

-- paddock_owner has BYPASSRLS, so the function filters every statement by the organization itself. The organization
-- comes only from the transaction's paddock.org_id (no missing_ok: no context fails closed), never from an argument.
-- A self-reference without ON DELETE action (change_set.reverts_change_set_id) is checked at the end of each
-- statement, so a batch takes only rows no remaining row of the same table references; a cycle raises instead of
-- reporting 0, which would end the deletion early. A row updated or inserted by another transaction after the
-- batch's snapshot escapes the ctid list (the DELETE follows the new row version, whose ctid is not in it); the
-- fresh re-check after an empty batch turns that into a retryable serialization_failure instead of a premature 0,
-- which the worker would take as "nothing left" and tombstone the organization over its data. The ctid list keeps
-- each batch an index-free TID scan; the organization is re-checked on the deleted rows. The search path has pg_temp
-- last and every table is qualified (as 00034, 00076).
-- +goose StatementBegin
CREATE FUNCTION paddock_offboard_delete_batch(max_rows int) RETURNS bigint
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, public, pg_temp AS $$
DECLARE
  org       uuid := current_setting('paddock.org_id')::uuid;
  org_state text;
  reg       record;
  guard     text;
  deleted   bigint;
  remaining boolean;
  deletable boolean := false;
BEGIN
  IF max_rows IS NULL OR max_rows < 1 OR max_rows > 10000 THEN
    RAISE EXCEPTION 'paddock_offboard_delete_batch: max_rows must be between 1 and 10000'
      USING ERRCODE = 'invalid_parameter_value';
  END IF;
  SELECT o.status INTO org_state FROM public.organization o WHERE o.id = org;
  IF org_state IS DISTINCT FROM 'deleting' THEN
    RAISE EXCEPTION 'paddock_offboard_delete_batch: organization % is not being deleted', org
      USING ERRCODE = 'insufficient_privilege';
  END IF;
  FOR reg IN SELECT r.table_name, format('public.%I', r.table_name)::regclass AS rel
             FROM public.offboarding_table r ORDER BY r.delete_order LOOP
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
      INTO deleted USING org, max_rows;
    IF deleted > 0 THEN
      RETURN deleted;
    END IF;
    EXECUTE format('SELECT EXISTS (SELECT 1 FROM public.%I WHERE organization_id = $1)', reg.table_name)
      INTO remaining USING org;
    IF remaining THEN
      IF guard <> '' THEN
        EXECUTE format('SELECT EXISTS (SELECT 1 FROM public.%I y WHERE y.organization_id = $1%s)', reg.table_name, guard)
          INTO deletable USING org;
      END IF;
      IF guard = '' OR deletable THEN
        RAISE EXCEPTION 'paddock_offboard_delete_batch: rows of % changed during the batch', reg.table_name
          USING ERRCODE = 'serialization_failure';
      END IF;
      RAISE EXCEPTION 'paddock_offboard_delete_batch: rows of % remain in a reference cycle', reg.table_name
        USING ERRCODE = 'foreign_key_violation';
    END IF;
  END LOOP;
  RETURN 0;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION paddock_offboard_delete_batch(int) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION paddock_offboard_delete_batch(int) TO paddock_worker;

-- +goose Down
