-- Update now (ADR 0037 decision 2, plan M8d decision 25, PDK-226): an administrator asks one device to install the
-- offered agent release at its next check-in, outside its rollout wave and regardless of its update policy. The
-- request is cleared by the device's report for that version or after 24 hours. device_status.arch is the
-- architecture of the last check-in, so that a request for a release without an artifact for it is refused.
-- Forward-only: there is no Down migration.
-- +goose Up
ALTER TABLE device
  ADD COLUMN agent_update_requested_version text,
  ADD COLUMN agent_update_requested_at timestamptz;
ALTER TABLE device_status ADD COLUMN arch text NOT NULL DEFAULT '';

-- +goose Down
