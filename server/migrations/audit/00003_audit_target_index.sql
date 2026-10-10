-- The target_id filter of the audit log list (plan M7c decision 31): events of one target, newest first. Indexes on
-- the partitioned parent cascade to every existing and future partition. Forward-only: there is no Down migration.
-- +goose Up
CREATE INDEX audit_event_org_target_idx ON audit_event (organization_id, (target->>'id'), occurred_at DESC);

-- +goose Down
