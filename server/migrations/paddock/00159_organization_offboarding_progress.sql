-- Every deletion step whose work grows with the organization yields to the other organizations (plan M17 amendment
-- 2026-11-16 s points 1.2 and 3, ticket PDK-1087). offboarding_cursor is the resume position of the current step, in
-- the step's own terms: the last device ID or Fleet host ID of the page it finished; NULL means the step has not
-- started. CompleteOrganizationOffboardingStep clears it. offboarding_failures_recorded lists the error codes whose
-- organization.deletion_step_failed this deletion has recorded: one event per code per deletion (main §32). The
-- backfill counts the stored code of a deletion that is running now as recorded, so the upgrade records it no second
-- time. Written by the platform role, like the other offboarding columns. Forward-only: there is no Down migration.
-- +goose Up
ALTER TABLE organization
  ADD COLUMN offboarding_cursor text,
  ADD COLUMN offboarding_failures_recorded text[] NOT NULL DEFAULT '{}';

UPDATE organization SET offboarding_failures_recorded = ARRAY[offboarding_error_code]
WHERE offboarding_error_code IS NOT NULL;

-- +goose Down
