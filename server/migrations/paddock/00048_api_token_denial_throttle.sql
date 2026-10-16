-- A token refused because its creator is disabled or lost the needed role is recorded at most once per window
-- (PDK-184): a CI pipeline that keeps calling with such a token must not flood the audit trail. Forward-only: there is
-- no Down migration.
-- +goose Up
ALTER TABLE api_token ADD COLUMN creator_inactive_recorded_at timestamptz;
