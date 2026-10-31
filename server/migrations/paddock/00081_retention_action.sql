-- The worker's retention round deletes finished actions PADDOCK_AUDIT_INDEX_RETENTION_DAYS after they finished, never
-- ahead of the audit index (ADR 0032 amendment 2026-10-31, PDK-180): the organizations' rows through the worker's
-- organization pool, the platform pseudo-organization's rows through its platform pool. Started actions are the outbox
-- reaper's input and are never deleted. The partial index lets every batch find its rows without scanning the table
-- (plan M10 amendment 2026-10-30).
-- The restrictive policies hold the same limits in the database, not only in the use case's queries: the platform role
-- is also the internet-facing API's role and may delete finished platform pseudo-organization actions only, never an
-- organization's and never a started one; the worker may delete finished actions only. They narrow DELETE alone, the
-- permissive policies keep governing every other command.
-- Forward-only: there is no Down migration.
-- +goose Up
GRANT DELETE ON action TO paddock_worker, paddock_platform;
CREATE POLICY platform_delete ON action AS RESTRICTIVE FOR DELETE TO paddock_platform
  USING (organization_id = '00000000-0000-0000-0000-000000000000'::uuid AND status = 'finished');
CREATE POLICY worker_delete ON action AS RESTRICTIVE FOR DELETE TO paddock_worker
  USING (status = 'finished');
CREATE INDEX action_org_finished_idx ON action (organization_id, finished_at) WHERE status = 'finished';
-- +goose Down
