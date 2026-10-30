-- server/migrations/paddock/00075_retention_grants.sql
-- The worker's retention round deletes device_user_seen rows older than app.SeenWindow (ADR 0032, plan M10
-- decision 11). Forward-only: there is no Down migration.
-- +goose Up
GRANT DELETE ON device_user_seen TO paddock_worker;
-- +goose Down
