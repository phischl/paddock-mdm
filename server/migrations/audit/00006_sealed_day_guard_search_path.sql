-- Pins the lookups of the sealed-day trigger function of 00005 (PDK-422 review): with a fixed search_path and a
-- schema-qualified manifest table, no temporary or other schema's table can shadow audit_manifest. The body is
-- otherwise unchanged. Forward-only: there is no Down migration.
-- +goose Up
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION audit_object_day_unsealed() RETURNS trigger LANGUAGE plpgsql
  SET search_path = pg_catalog, public, pg_temp AS $$
BEGIN
  PERFORM pg_advisory_xact_lock_shared(hashtext('audit-day'), hashtext(NEW.organization_id::text));
  IF EXISTS (SELECT 1 FROM public.audit_manifest m WHERE m.organization_id = NEW.organization_id AND m.day >= NEW.day) THEN
    RAISE EXCEPTION 'audit day % of organization % is already sealed', NEW.day, NEW.organization_id
      USING ERRCODE = 'PA422';
  END IF;
  RETURN NEW;
END $$;
-- +goose StatementEnd

-- +goose Down
