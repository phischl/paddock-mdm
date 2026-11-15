-- Step audit_final of an organization's deletion (plan M17 decision 16, amendment 2026-11-15 o points 1 and 6, ticket
-- PDK-1017). The worker gets no connection to the audit database: it records organization.audit_retirement_requested
-- through ActionRunner once (audit_retirement_requested_at is that claim and the start of the wait), and the audit
-- writer's acknowledgement on paddock.offboarding sets the final verification's time and outcome, through the platform
-- role, only while the organization is deleting. The step completes once audit_final_verified_at is set; the outcome
-- is carried into organization.deleted and shown to platform administrators. Forward-only: there is no Down migration.
-- +goose Up
ALTER TABLE organization
  ADD COLUMN audit_retirement_requested_at timestamptz,
  ADD COLUMN audit_final_verified_at       timestamptz,
  ADD COLUMN audit_final_outcome           text CHECK (audit_final_outcome IN ('verified', 'failed')),
  ADD CONSTRAINT organization_audit_final_consistent CHECK (
    (audit_final_verified_at IS NULL) = (audit_final_outcome IS NULL) AND
    (audit_final_verified_at IS NULL OR status IN ('deleting', 'deleted')) AND
    (audit_retirement_requested_at IS NULL OR status IN ('deleting', 'deleted')));

-- +goose Down
