-- The end of a denial's re-request lock (architect decision A10-27, PDK-993 fix round 1). The compiler's reconcile
-- recompiles a device once a lock of one of its denials ends, so the bundle no longer names the denial. An unchanged
-- recompile writes no bundle, so the bundle's age alone cannot tell that the lock end was handled: the compiler
-- records in denial_lock_checked_at when it recompiled the device for that reason, and selects only locks that ended
-- after it. The partial index serves both denial queries, which read only denied requests by decision time.
-- Forward-only: there is no Down migration.
-- +goose Up
ALTER TABLE device ADD COLUMN denial_lock_checked_at timestamptz;
GRANT UPDATE (denial_lock_checked_at) ON device TO paddock_compiler;
CREATE INDEX software_request_denied_idx ON software_request (organization_id, decided_at) WHERE state = 'denied';

-- +goose Down
