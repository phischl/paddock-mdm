-- The one-time seed of the second-factor enrolment at sign-in (ADR 0053 decision 4 as amended, plan M12h-2 decision 7):
-- one row. first_attempt_at is when the worker first tried the seed; only accounts the identity provider created
-- before it are ever marked, so a seed repeated after a failed attempt never marks an administrator added after the
-- upgrade. seeded_at records the completed seed; while it is set the seed never runs again. Platform data without
-- organization_id (not in offboarding_table); RLS enabled and forced with a policy for paddock_platform only, so no
-- other role reads or writes it even with a grant. Forward-only: there is no Down migration.
-- +goose Up
CREATE TABLE platform_mfa_enrolment (
  id               boolean PRIMARY KEY DEFAULT true CHECK (id),
  first_attempt_at timestamptz NOT NULL,
  seeded_at        timestamptz CHECK (seeded_at >= first_attempt_at)
);
ALTER TABLE platform_mfa_enrolment ENABLE ROW LEVEL SECURITY;
ALTER TABLE platform_mfa_enrolment FORCE ROW LEVEL SECURITY;
CREATE POLICY platform ON platform_mfa_enrolment TO paddock_platform USING (true) WITH CHECK (true);
GRANT SELECT, INSERT, UPDATE ON platform_mfa_enrolment TO paddock_platform;
