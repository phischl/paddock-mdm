-- Software assignments roll out in waves (PDK-808, plan M13c decision 3, ADR 0033 amendment 2026-11-05): the worker
-- evaluates a rollout against the failed software status of its staged catalog entries, which the stored plan names
-- by their natural key, the entry name. The worker could read only id and organization_id of an entry (00098); it now
-- also reads the name to resolve them. Nothing else of the catalog is granted. The plan's stats function does not
-- exist since 00094; the failure join lives in the query of the rollout reports instead.
-- staged_assignments records, per staged software assignment key, the row ID, the catalog entry and the target of the
-- assignment when the rollout started. The compiler matches live rows and before items by these IDs: a username comes
-- from identity sync and can change while the rollout runs, so a key's names would no longer find its row. NULL for a
-- rollout that stages no assignments. The compiler already reads config_rollout in full (00093).
-- Forward-only: there is no Down migration.
-- +goose Up
GRANT SELECT (name) ON software_catalog_entry TO paddock_worker;
ALTER TABLE config_rollout ADD COLUMN staged_assignments jsonb;
