-- Packages stored in Paddock (plan M13c decisions 11, 12, 14 and 15, ADR 0050, PDK-812): one APT repository per
-- organization and the .deb packages an organization administrator uploaded into it. software_repository holds the
-- basic-auth credential of the repository (the secret Transit-wrapped under software-repo-credential for the compiler,
-- which renders it into the bundles, and its SHA-256, against which the api checks requests; the previous hash stays
-- valid until previous_credential_expires_at, 24 hours after a rotation, §3.8 L6) and the signing key. The signing
-- columns are NULL until the worker generates the key on first use (ADR 0050 decision 3, PDK-813; M13c amendment
-- 2026-11-09 (PDK-812)): all three are set or none is, and until then uploads are refused and nothing is published
-- (A10-21). rebuild_requested_at queues the worker's rebuild. software_package rows name the objects below
-- apt/<organization_id>/pool/ of the bundles bucket. A source gains the kind paddock, the system source of the
-- repository that the worker maintains (PDK-813); it has the shape of an apt source. The plan names this file 00112;
-- that number was taken. Forward-only: there is no Down migration.
-- +goose Up
CREATE TABLE software_repository (
  organization_id uuid PRIMARY KEY REFERENCES organization(id),
  signing_public_key text CHECK (octet_length(signing_public_key) <= 65536),
  signing_fingerprint text CHECK (signing_fingerprint IS NULL OR signing_fingerprint ~ '^[0-9A-F]{40}$'),
  signing_private_ciphertext text,
  previous_public_key text,
  previous_fingerprint text CHECK (previous_fingerprint IS NULL OR previous_fingerprint ~ '^[0-9A-F]{40}$'),
  previous_retired_at timestamptz,
  credential_ciphertext text NOT NULL,
  credential_sha256 bytea NOT NULL CHECK (octet_length(credential_sha256) = 32),
  previous_credential_sha256 bytea CHECK (octet_length(previous_credential_sha256) = 32),
  previous_credential_expires_at timestamptz,
  credential_rotated_at timestamptz NOT NULL DEFAULT now(),
  generation bigint NOT NULL DEFAULT 0,
  rebuild_requested_at timestamptz,
  last_built_at timestamptz,
  last_error text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT software_repository_signing_complete CHECK (
    (signing_public_key IS NULL) = (signing_fingerprint IS NULL)
    AND (signing_public_key IS NULL) = (signing_private_ciphertext IS NULL)),
  CONSTRAINT software_repository_previous_credential CHECK (
    (previous_credential_sha256 IS NULL) = (previous_credential_expires_at IS NULL))
);
ALTER TABLE software_repository ENABLE ROW LEVEL SECURITY;
ALTER TABLE software_repository FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON software_repository TO paddock_api, paddock_worker, paddock_compiler
  USING (organization_id = current_setting('paddock.org_id')::uuid)
  WITH CHECK (organization_id = current_setting('paddock.org_id')::uuid);
GRANT SELECT, INSERT, UPDATE ON software_repository TO paddock_api;
GRANT SELECT, UPDATE ON software_repository TO paddock_worker;
GRANT SELECT ON software_repository TO paddock_compiler;

CREATE TABLE software_package (
  id uuid PRIMARY KEY,
  organization_id uuid NOT NULL REFERENCES organization(id),
  package text NOT NULL CHECK (package ~ '^[a-z0-9][a-z0-9+.-]{1,127}$'),
  version text NOT NULL CHECK (version ~ '^[A-Za-z0-9.+:~-]+$' AND char_length(version) <= 128),
  architecture text NOT NULL CHECK (architecture IN ('amd64', 'arm64', 'all')),
  size bigint NOT NULL CHECK (size BETWEEN 1 AND 268435456),
  sha256 text NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
  object_key text NOT NULL,
  control jsonb NOT NULL,
  uploaded_by text NOT NULL CHECK (char_length(uploaded_by) BETWEEN 1 AND 256),
  uploaded_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (organization_id, package, version, architecture),
  -- The file name drops a version's epoch, as Debian does, so two versions that differ in the epoch alone would
  -- share one object.
  UNIQUE (organization_id, object_key)
);
CREATE INDEX software_package_org_uploaded_idx ON software_package (organization_id, uploaded_at DESC, id);
ALTER TABLE software_package ENABLE ROW LEVEL SECURITY;
ALTER TABLE software_package FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON software_package TO paddock_api, paddock_worker, paddock_compiler
  USING (organization_id = current_setting('paddock.org_id')::uuid)
  WITH CHECK (organization_id = current_setting('paddock.org_id')::uuid);
GRANT SELECT, INSERT, DELETE ON software_package TO paddock_api;
GRANT SELECT ON software_package TO paddock_worker, paddock_compiler;

ALTER TABLE software_source DROP CONSTRAINT software_source_kind_check;
ALTER TABLE software_source ADD CONSTRAINT software_source_kind_check CHECK (kind IN ('apt', 'flatpak', 'paddock'));
ALTER TABLE software_source DROP CONSTRAINT software_source_kind_shape;
ALTER TABLE software_source ADD CONSTRAINT software_source_kind_shape CHECK (
  (kind IN ('apt', 'paddock') AND cardinality(suites) BETWEEN 1 AND 8)
  OR (kind = 'flatpak' AND cardinality(uris) = 1 AND cardinality(suites) = 0 AND cardinality(components) = 0
    AND cardinality(architectures) = 0));
CREATE UNIQUE INDEX software_source_one_paddock_idx ON software_source (organization_id) WHERE kind = 'paddock';

-- +goose Down
