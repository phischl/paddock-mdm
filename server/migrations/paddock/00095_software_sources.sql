-- Software sources (plan M13a decision 1, §6.5, amendment 2026-10-31 R1 and R6.5, PDK-408): the third-party APT
-- repositories of an organization, each with its own signing key (ASCII-armored OpenPGP public key) and the key's
-- fingerprint. weak_key records an accepted RSA key of 2048 to 3071 bits. The api writes the table, the compiler
-- renders it into the software resource of the bundles. UNIQUE (organization_id, id) is the target of the
-- organization-bound foreign key of the catalog entries (00096). The plan names this file 00068; that number was
-- taken. Forward-only: there is no Down migration.
-- +goose Up

CREATE TABLE software_source (
  id uuid PRIMARY KEY,
  organization_id uuid NOT NULL REFERENCES organization(id),
  slug text NOT NULL CHECK (slug ~ '^[a-z0-9][a-z0-9-]{1,40}$'),
  name text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 100),
  uris text[] NOT NULL CHECK (cardinality(uris) BETWEEN 1 AND 4),
  suites text[] NOT NULL CHECK (cardinality(suites) BETWEEN 1 AND 8),
  components text[] NOT NULL DEFAULT '{}' CHECK (cardinality(components) <= 8),
  architectures text[] NOT NULL DEFAULT '{}' CHECK (cardinality(architectures) <= 2),
  signing_key text NOT NULL CHECK (octet_length(signing_key) <= 65536),
  fingerprint text NOT NULL CHECK (fingerprint ~ '^[0-9A-F]{40}$'),
  weak_key boolean NOT NULL DEFAULT false,
  created_by uuid,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (organization_id, slug),
  UNIQUE (organization_id, name),
  UNIQUE (organization_id, id)
);
CREATE INDEX software_source_org_created_idx ON software_source (organization_id, created_at);
ALTER TABLE software_source ENABLE ROW LEVEL SECURITY;
ALTER TABLE software_source FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON software_source TO paddock_api, paddock_compiler
  USING (organization_id = current_setting('paddock.org_id')::uuid)
  WITH CHECK (organization_id = current_setting('paddock.org_id')::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON software_source TO paddock_api;
GRANT SELECT ON software_source TO paddock_compiler;

-- +goose Down
