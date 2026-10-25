-- Chain verification runs and reader-visible chain status (plan M8b decision 24, ADR 0010 amendment 2026-10-15).
-- Every run of the nightly cycle, its random sample day and `paddock-server audit verify` is one row; event_id is
-- the audit.chain_verified / audit.chain_verification_failed event written before the row. Forward-only: there is no
-- Down migration.
-- +goose Up
CREATE TABLE audit_verification_run (
  id              uuid PRIMARY KEY,
  organization_id uuid NOT NULL,
  trigger         text NOT NULL CHECK (trigger IN ('nightly','sample','cli')),
  from_day        date NOT NULL,
  to_day          date NOT NULL,
  started_at      timestamptz NOT NULL,
  finished_at     timestamptz NOT NULL,
  days            int NOT NULL,
  objects         int NOT NULL,
  ok              boolean NOT NULL,
  problems        jsonb NOT NULL DEFAULT '[]',
  event_id        uuid NOT NULL
);
CREATE INDEX audit_verification_run_org_started_idx ON audit_verification_run (organization_id, started_at DESC);
-- The writer's scrape-time run counts and its last nightly run (amendment 2026-10-25 to plan M8b decision 27) read
-- these instead of the whole table, which grows by two rows per organization and night.
CREATE INDEX audit_verification_run_trigger_ok_idx ON audit_verification_run (trigger, ok);
CREATE INDEX audit_verification_run_trigger_finished_idx ON audit_verification_run (trigger, finished_at DESC);

ALTER TABLE audit_verification_run ENABLE ROW LEVEL SECURITY; ALTER TABLE audit_verification_run FORCE ROW LEVEL SECURITY;
CREATE POLICY reader ON audit_verification_run TO paddock_audit_reader
  USING (organization_id = current_setting('paddock.org_id')::uuid);
CREATE POLICY writer ON audit_verification_run TO paddock_audit_writer USING (true) WITH CHECK (true);
CREATE POLICY reader ON audit_manifest TO paddock_audit_reader
  USING (organization_id = current_setting('paddock.org_id')::uuid);

GRANT SELECT ON audit_verification_run, audit_manifest TO paddock_audit_reader;
GRANT SELECT, INSERT ON audit_verification_run TO paddock_audit_writer;
-- No UPDATE or DELETE grant to any non-owner role.

-- +goose Down
