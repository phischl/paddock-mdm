-- Commit sequence of the audit index (plan M9 decision 1, ADR 0031 decision 2): every event gets a contiguous
-- per-organization commit_seq in the order the writer committed it, so outbound consumers read the index in commit
-- order and detect loss. The backfill numbers existing rows in (recorded_at, event_id) order. Forward-only: there
-- is no Down migration.
-- +goose Up
ALTER TABLE audit_event ADD COLUMN commit_seq bigint;
-- Migrations run as audit_owner, which has no policy on audit_event: under FORCE the backfill would see no rows. The
-- exemption lasts only for this migration's transaction.
ALTER TABLE audit_event NO FORCE ROW LEVEL SECURITY;
UPDATE audit_event e SET commit_seq = s.rn
FROM (SELECT event_id, occurred_at,
             row_number() OVER (PARTITION BY organization_id ORDER BY recorded_at, event_id) AS rn
      FROM audit_event) s
WHERE e.event_id = s.event_id AND e.occurred_at = s.occurred_at;
ALTER TABLE audit_event ALTER COLUMN commit_seq SET NOT NULL;
-- A unique index on (organization_id, commit_seq) is impossible on a table partitioned by occurred_at; the writer's
-- row lock on audit_org_seq guarantees uniqueness.
CREATE INDEX audit_event_org_commit_seq_idx ON audit_event (organization_id, commit_seq);

-- The only source of the next number after this backfill (amendment B1.3): it is never recomputed from audit_event,
-- whose old partitions the index retention drops.
CREATE TABLE audit_org_seq (
  organization_id uuid PRIMARY KEY,
  last_seq        bigint NOT NULL
);
INSERT INTO audit_org_seq SELECT organization_id, max(commit_seq) FROM audit_event GROUP BY organization_id;
ALTER TABLE audit_event FORCE ROW LEVEL SECURITY;

ALTER TABLE audit_org_seq ENABLE ROW LEVEL SECURITY; ALTER TABLE audit_org_seq FORCE ROW LEVEL SECURITY;
CREATE POLICY writer ON audit_org_seq TO paddock_audit_writer USING (true) WITH CHECK (true);
GRANT SELECT, INSERT, UPDATE ON audit_org_seq TO paddock_audit_writer;
-- No grant to paddock_audit_reader.

-- +goose Down
