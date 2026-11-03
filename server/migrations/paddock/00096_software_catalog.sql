-- Software catalog (plan M13a decisions 7 to 9, §6.5, amendment 2026-10-31 R1, PDK-409): the applications an
-- organization manages and their assignments to the organization or a device group with an intent. An entry's source
-- (NULL = the distribution's own repositories) and an assignment's entry and group are organization-bound foreign keys,
-- so a row cannot point into another organization. UNIQUE (organization_id, id) on the entry is the target of the
-- assignment's composite key (the plan's DDL omits it). The api writes both tables, the compiler renders them into the
-- bundles. The plan names this file 00069; that number was taken. Forward-only: there is no Down migration.
-- +goose Up

CREATE TABLE software_catalog_entry (
  id uuid PRIMARY KEY,
  organization_id uuid NOT NULL REFERENCES organization(id),
  name text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 100),
  description text NOT NULL DEFAULT '' CHECK (char_length(description) <= 1000),
  category text NOT NULL DEFAULT '' CHECK (char_length(category) <= 64),
  source_id uuid REFERENCES software_source(id) ON DELETE RESTRICT,
  packages jsonb NOT NULL,
  icon bytea CHECK (icon IS NULL OR octet_length(icon) <= 65536),
  created_by uuid,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (organization_id, name),
  UNIQUE (organization_id, id),
  FOREIGN KEY (organization_id, source_id) REFERENCES software_source (organization_id, id)
);
CREATE INDEX software_catalog_entry_source_idx ON software_catalog_entry (source_id) WHERE source_id IS NOT NULL;

CREATE TABLE software_assignment (
  id uuid PRIMARY KEY,
  organization_id uuid NOT NULL REFERENCES organization(id),
  catalog_entry_id uuid NOT NULL REFERENCES software_catalog_entry(id) ON DELETE CASCADE,
  device_group_id uuid REFERENCES device_group(id) ON DELETE CASCADE,
  intent text NOT NULL CHECK (intent IN ('required', 'uninstall', 'hold', 'forbid')),
  update_rule text NOT NULL DEFAULT 'latest' CHECK (update_rule IN ('latest', 'pinned')),
  version text CHECK (version ~ '^[A-Za-z0-9.+:~-]+$' AND char_length(version) <= 128),
  reason text NOT NULL DEFAULT '' CHECK (char_length(reason) <= 500),
  created_by uuid,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE NULLS NOT DISTINCT (organization_id, catalog_entry_id, device_group_id),
  FOREIGN KEY (organization_id, catalog_entry_id) REFERENCES software_catalog_entry (organization_id, id) ON DELETE CASCADE,
  FOREIGN KEY (organization_id, device_group_id) REFERENCES device_group (organization_id, id) ON DELETE CASCADE,
  CHECK ((intent = 'required' AND update_rule = 'pinned' AND version IS NOT NULL)
      OR (intent = 'required' AND update_rule = 'latest' AND version IS NULL)
      OR (intent = 'hold' AND update_rule = 'latest')
      OR (intent IN ('uninstall', 'forbid') AND update_rule = 'latest' AND version IS NULL))
);
CREATE INDEX software_assignment_group_idx ON software_assignment (device_group_id) WHERE device_group_id IS NOT NULL;

ALTER TABLE software_catalog_entry ENABLE ROW LEVEL SECURITY;
ALTER TABLE software_catalog_entry FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON software_catalog_entry TO paddock_api, paddock_compiler
  USING (organization_id = current_setting('paddock.org_id')::uuid)
  WITH CHECK (organization_id = current_setting('paddock.org_id')::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON software_catalog_entry TO paddock_api;
GRANT SELECT ON software_catalog_entry TO paddock_compiler;

ALTER TABLE software_assignment ENABLE ROW LEVEL SECURITY;
ALTER TABLE software_assignment FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON software_assignment TO paddock_api, paddock_compiler
  USING (organization_id = current_setting('paddock.org_id')::uuid)
  WITH CHECK (organization_id = current_setting('paddock.org_id')::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON software_assignment TO paddock_api;
GRANT SELECT ON software_assignment TO paddock_compiler;

-- +goose Down
