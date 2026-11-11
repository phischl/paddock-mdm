-- The end of a denial's re-request lock (architect decision A10-27, PDK-993). The compiler's reconcile recompiles a
-- device once a lock of one of its denials ends, so the bundle no longer names the denial. An unchanged recompile writes
-- no bundle, and a render before a lock's end can publish after it, so the bundle's age cannot tell whether the lock
-- end is reflected: every compile records its render time in denial_lock_checked_at for each device whose bundle_seq is
-- still the one it left (committed, unchanged or blocked), and the reconcile selects only locks that ended after it.
-- The partial index serves both denial queries, which read only denied requests by decision time. Forward-only: there
-- is no Down migration.
-- +goose Up
ALTER TABLE device ADD COLUMN denial_lock_checked_at timestamptz;
GRANT UPDATE (denial_lock_checked_at) ON device TO paddock_compiler;
CREATE INDEX software_request_denied_idx ON software_request (organization_id, decided_at) WHERE state = 'denied';

-- +goose Down
