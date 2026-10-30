-- Evidence exports and the published signing keys (ADR 0032 §5, plan M10 decisions 28–36). The reader role may
-- insert export requests and read manifests, objects and exports of its organization; it keeps no UPDATE or DELETE.
-- Forward-only: there is no Down migration.
-- +goose Up
CREATE TABLE audit_export (
  id uuid PRIMARY KEY,
  organization_id uuid NOT NULL,
  status text NOT NULL CHECK (status IN ('pending','running','ready','failed','expired')),
  from_day date NOT NULL,
  to_day date NOT NULL CHECK (to_day >= from_day),
  purpose text NOT NULL CHECK (char_length(purpose) BETWEEN 1 AND 500),
  requested_by jsonb NOT NULL,
  requested_at timestamptz NOT NULL DEFAULT now(),
  started_at timestamptz,
  ready_at timestamptz,
  expires_at timestamptz,
  event_count bigint,
  object_count int,
  size bigint,
  package_sha256 bytea,
  verify_ok boolean,
  verify_problems jsonb,
  signature text,
  key_version int,
  error text,
  correlation_id text NOT NULL
);
CREATE INDEX audit_export_org_requested_idx ON audit_export (organization_id, requested_at DESC);
CREATE INDEX audit_export_pending_idx ON audit_export (requested_at) WHERE status = 'pending';
CREATE INDEX audit_export_expiry_idx ON audit_export (expires_at) WHERE status = 'ready';

CREATE TABLE audit_export_chunk (
  export_id uuid NOT NULL REFERENCES audit_export(id) ON DELETE CASCADE,
  organization_id uuid NOT NULL,
  seq int NOT NULL,
  data bytea NOT NULL,
  PRIMARY KEY (export_id, seq)
);
ALTER TABLE audit_export_chunk ALTER COLUMN data SET STORAGE EXTERNAL;

CREATE TABLE audit_signing_key (
  key_version int PRIMARY KEY,
  public_key bytea NOT NULL CHECK (octet_length(public_key) = 32),
  first_seen_at timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE audit_export ENABLE ROW LEVEL SECURITY; ALTER TABLE audit_export FORCE ROW LEVEL SECURITY;
-- The reader only requests exports: a row it inserts is pending and carries none of the builder's columns, so no SQL
-- path running as the reader can present an export as built or verified (plan M10, amendment 2026-10-30 for PDK-142).
CREATE POLICY reader ON audit_export TO paddock_audit_reader
  USING (organization_id = current_setting('paddock.org_id')::uuid)
  WITH CHECK (organization_id = current_setting('paddock.org_id')::uuid AND status = 'pending'
    AND started_at IS NULL AND ready_at IS NULL AND expires_at IS NULL AND event_count IS NULL
    AND object_count IS NULL AND size IS NULL AND package_sha256 IS NULL AND verify_ok IS NULL
    AND verify_problems IS NULL AND signature IS NULL AND key_version IS NULL AND error IS NULL);
CREATE POLICY writer ON audit_export TO paddock_audit_writer USING (true) WITH CHECK (true);
ALTER TABLE audit_export_chunk ENABLE ROW LEVEL SECURITY; ALTER TABLE audit_export_chunk FORCE ROW LEVEL SECURITY;
CREATE POLICY reader ON audit_export_chunk TO paddock_audit_reader
  USING (organization_id = current_setting('paddock.org_id')::uuid);
CREATE POLICY writer ON audit_export_chunk TO paddock_audit_writer USING (true) WITH CHECK (true);
-- The reader policies on audit_manifest (and audit_verification_run) come from M8b (ADR 0030). audit_object gets its
-- reader policy here unless an earlier migration created one under the same name.
-- +goose StatementBegin
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'audit_object' AND policyname = 'reader') THEN
    CREATE POLICY reader ON audit_object TO paddock_audit_reader
      USING (organization_id = current_setting('paddock.org_id')::uuid);
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'audit_manifest' AND policyname = 'reader') THEN
    CREATE POLICY reader ON audit_manifest TO paddock_audit_reader
      USING (organization_id = current_setting('paddock.org_id')::uuid);
  END IF;
END $$;
-- +goose StatementEnd

GRANT SELECT, INSERT ON audit_export TO paddock_audit_reader;
GRANT SELECT ON audit_export_chunk, audit_object, audit_manifest, audit_signing_key TO paddock_audit_reader;
GRANT SELECT, INSERT, UPDATE, DELETE ON audit_export, audit_export_chunk TO paddock_audit_writer;
GRANT SELECT, INSERT ON audit_signing_key TO paddock_audit_writer;
-- +goose Down
