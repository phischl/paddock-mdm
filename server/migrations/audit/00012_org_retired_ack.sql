-- The audit writer's acknowledgement of a retired organization (plan M17 amendment 2026-11-15 o points 5 and 6): after
-- the final verification is recorded, the writer publishes it to the worker on paddock.offboarding with publisher
-- confirms. ack_published_at stays NULL until the broker confirmed; the writer republishes such rows at start and every
-- five minutes. The final verification is recorded as a run of its own trigger, final, so that a failed final outcome
-- reaches paddock_audit_verify_runs_total and its alert (main's condition on amendment o). Forward-only: there is no
-- Down migration.
-- +goose Up
ALTER TABLE audit_org_retired ADD COLUMN ack_published_at timestamptz;

ALTER TABLE audit_verification_run DROP CONSTRAINT audit_verification_run_trigger_check;
ALTER TABLE audit_verification_run ADD CONSTRAINT audit_verification_run_trigger_check
  CHECK (trigger IN ('nightly','sample','cli','final'));

-- +goose Down
