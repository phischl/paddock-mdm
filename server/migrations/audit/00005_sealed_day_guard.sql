-- A sealed day receives no further objects (ADR 0010 amendment 2026-10-25, PDK-422). The writer files an object
-- under the first unsealed day; this trigger is the fail-closed invariant behind that rule. It takes the
-- organization's audit-day lock shared, the sealer takes it exclusively before it lists a day's objects: an object
-- inserted first is committed before the sealer lists the day, a manifest committed first is seen here and the insert
-- fails with SQLSTATE PA422, which the writer retries in a new transaction. Forward-only: there is no Down migration.
-- +goose Up
-- +goose StatementBegin
CREATE FUNCTION audit_object_day_unsealed() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  PERFORM pg_advisory_xact_lock_shared(hashtext('audit-day'), hashtext(NEW.organization_id::text));
  IF EXISTS (SELECT 1 FROM audit_manifest m WHERE m.organization_id = NEW.organization_id AND m.day >= NEW.day) THEN
    RAISE EXCEPTION 'audit day % of organization % is already sealed', NEW.day, NEW.organization_id
      USING ERRCODE = 'PA422';
  END IF;
  RETURN NEW;
END $$;
-- +goose StatementEnd
CREATE TRIGGER audit_object_day_unsealed BEFORE INSERT ON audit_object
  FOR EACH ROW EXECUTE FUNCTION audit_object_day_unsealed();

-- +goose Down
