-- server/migrations/paddock/00075_retention_grants.sql
-- The worker's retention round deletes device_user_seen rows older than app.SeenWindow (ADR 0032, plan M10
-- decision 11), in batches that each find their rows through the index below instead of scanning the table (plan M10
-- amendment 2026-10-30). device_login_event already has device_login_event_org_at_idx (00054). Forward-only: there
-- is no Down migration.
-- +goose Up
GRANT DELETE ON device_user_seen TO paddock_worker;
CREATE INDEX device_user_seen_org_last_seen_idx ON device_user_seen (organization_id, last_seen_at);
-- +goose Down
