-- server/migrations/paddock/00074_privacy_settings.sql
-- Privacy settings of an organization (ADR 0032 §2, plan M10 decision 7). Forward-only: there is no Down migration.
-- +goose Up
CREATE TABLE organization_privacy_settings (
  organization_id uuid PRIMARY KEY REFERENCES organization(id),
  retired_inventory_days int NOT NULL DEFAULT 30 CHECK (retired_inventory_days BETWEEN 1 AND 365),
  audit_search_recorded boolean NOT NULL DEFAULT false,
  inventory_view_recorded boolean NOT NULL DEFAULT false,
  updated_at timestamptz NOT NULL DEFAULT now(),
  updated_by uuid
);
INSERT INTO organization_privacy_settings (organization_id) SELECT id FROM organization;
-- +goose StatementBegin
CREATE FUNCTION organization_privacy_settings_default() RETURNS trigger
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
  INSERT INTO organization_privacy_settings (organization_id) VALUES (NEW.id) ON CONFLICT DO NOTHING;
  RETURN NULL;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION organization_privacy_settings_default() FROM PUBLIC;
CREATE TRIGGER organization_privacy_settings_default AFTER INSERT ON organization
  FOR EACH ROW EXECUTE FUNCTION organization_privacy_settings_default();
ALTER TABLE organization_privacy_settings ENABLE ROW LEVEL SECURITY;
ALTER TABLE organization_privacy_settings FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON organization_privacy_settings TO paddock_api, paddock_worker
  USING (organization_id = current_setting('paddock.org_id')::uuid)
  WITH CHECK (organization_id = current_setting('paddock.org_id')::uuid);
GRANT SELECT, INSERT, UPDATE ON organization_privacy_settings TO paddock_api;
GRANT SELECT ON organization_privacy_settings TO paddock_worker;
-- +goose Down
