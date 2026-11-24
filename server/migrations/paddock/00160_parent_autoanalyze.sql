-- Earlier autoanalyze for the parent tables of the organization foreign keys (ADR 0055 amendment 2026-11-16 (4)
-- decision 17, alpha.11 mitigation until the key tables of PDK-1095). PostgreSQL's foreign-key check on
-- (organization_id, id) reads a whole organization per checked row while that organization is missing from the
-- statistics of the parent table. With the default trigger (50 rows + 10 %), 10 000 new devices next to 100 000
-- existing ones never start an autoanalyze; with 1 % it ran 58 s after the burst and the check fell from 2 065 to 6
-- buffers (PostgreSQL 18.6). Storage parameters live in pg_class, so a pgBackRest restore keeps them.
-- Forward-only: there is no Down migration.
-- +goose Up
ALTER TABLE device SET (autovacuum_analyze_scale_factor = 0.01, autovacuum_analyze_threshold = 50);
ALTER TABLE app_user SET (autovacuum_analyze_scale_factor = 0.01, autovacuum_analyze_threshold = 50);
ALTER TABLE user_group SET (autovacuum_analyze_scale_factor = 0.01, autovacuum_analyze_threshold = 50);

-- +goose Down
