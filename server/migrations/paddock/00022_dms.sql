-- Dead man's switch (plan M4c decisions 15 and 17). Forward-only: there is no Down migration.
-- organization_dms_settings: whether the switch is on, its period and the warning lead times; the api writes it
-- (step-up to enable), the compiler renders it into v2 bundles, the revocation-issuer keeps one self-lock token per
-- active device while it is on, the worker marks devices silent past the period as presumed self-locked.
-- +goose Up

CREATE TABLE organization_dms_settings (
  organization_id uuid PRIMARY KEY REFERENCES organization(id),
  enabled boolean NOT NULL DEFAULT false,
  period_days int NOT NULL DEFAULT 30 CHECK (period_days BETWEEN 7 AND 365),
  warn_days int[] NOT NULL DEFAULT '{3,1}' CHECK (cardinality(warn_days) <= 5),
  updated_at timestamptz NOT NULL DEFAULT now(),
  updated_by uuid
);
ALTER TABLE organization_dms_settings ENABLE ROW LEVEL SECURITY;
ALTER TABLE organization_dms_settings FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON organization_dms_settings TO paddock_api, paddock_compiler, paddock_worker, paddock_revocation
  USING (organization_id = current_setting('paddock.org_id')::uuid)
  WITH CHECK (organization_id = current_setting('paddock.org_id')::uuid);
GRANT SELECT, INSERT, UPDATE ON organization_dms_settings TO paddock_api;
GRANT SELECT ON organization_dms_settings TO paddock_compiler, paddock_worker, paddock_revocation;

-- When the worker found the device silent past the period while the switch was on; cleared at its next contact.
ALTER TABLE device_status ADD COLUMN presumed_self_locked_at timestamptz;

-- +goose Down
