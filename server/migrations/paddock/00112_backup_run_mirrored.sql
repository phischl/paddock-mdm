-- A backup run is recorded in two phases (decisions-alpha9 items 78 and 79; plan M15, note 2026-11-07 b): the row and
-- the answered request right after the local step, so that `backup now --wait` and restore plans see a finished backup
-- at once; the targets and the run's audit event after the round's mirror. mirrored_at marks the second phase; a
-- finished run without it gets its event from the next round's mirror. The default marks every existing run, and every
-- run an older backup role still writes during an upgrade (it records its event itself), as mirrored; the new role
-- writes NULL in phase 1. Forward-only: there is no Down migration.
-- +goose Up

ALTER TABLE backup_run ADD COLUMN mirrored_at timestamptz DEFAULT now();
CREATE INDEX backup_run_unmirrored_idx ON backup_run (finished_at) WHERE state = 'finished' AND mirrored_at IS NULL;
