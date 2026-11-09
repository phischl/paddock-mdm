-- Catalog icons of a bundle (PDK-935, architect decision A10-14): the hex SHA-256 of each catalog entry icon the
-- bundle names, by entry ID. The compiler writes the icons content-addressed to the bundles bucket together with the
-- bundle and mirrors this map into the bundle pointer bp:<device>, where the gateway resolves GET
-- /v1/catalog/{entry_id}/icon; the reconcile loop restores the pointer, icons included, from the latest bundle row.
-- Forward-only: there is no Down migration.
-- +goose Up
ALTER TABLE bundle ADD COLUMN icons jsonb NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(icons) = 'object');
