-- Bundle schema negotiation (plan M3a decision 14a, architecture §21). Forward-only: there is no Down migration.
-- schema_version records which schema a bundle was rendered in, so the compiler can recompile devices whose agent
-- started (or stopped) reporting schema 2 since their last bundle.
-- +goose Up

ALTER TABLE bundle ADD COLUMN schema_version int NOT NULL DEFAULT 1;

-- +goose Down
