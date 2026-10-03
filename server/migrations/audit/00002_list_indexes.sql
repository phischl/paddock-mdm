-- Search and filter indexes of the audit log list (ADR 0018, plan M0.2 decision 7). Forward-only: there is no Down
-- migration. pg_trgm is a trusted extension: audit_owner creates it as owner of the database. Indexes on the
-- partitioned parent cascade to every existing and future partition.
-- +goose Up
CREATE EXTENSION IF NOT EXISTS pg_trgm;
CREATE INDEX audit_event_code_trgm_idx ON audit_event USING gin (code gin_trgm_ops);
CREATE INDEX audit_event_actor_display_trgm_idx ON audit_event USING gin ((actor->>'display') gin_trgm_ops);
CREATE INDEX audit_event_target_display_trgm_idx ON audit_event USING gin ((target->>'display') gin_trgm_ops);
CREATE INDEX audit_event_org_code_idx ON audit_event (organization_id, code);
CREATE INDEX audit_event_org_outcome_idx ON audit_event (organization_id, outcome);

-- +goose Down
