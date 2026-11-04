-- The upgrade check (plan M16 decision 4, amendment 2026-11-04) compares the database's applied migration with the
-- binary's newest one, so a downgrade is refused before anything changes. goose_db_version belongs to the migration
-- owner; the platform pool may read it, nothing more. Forward-only: there is no Down migration.
-- +goose Up
GRANT SELECT ON goose_db_version TO paddock_platform;

-- +goose Down
