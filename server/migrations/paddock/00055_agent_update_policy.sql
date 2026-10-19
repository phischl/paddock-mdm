-- Agent update policy of an organization (ADR 0037 decision 1, plan M8d decision 21, PDK-225): automatic follows the
-- platform's rollout waves, manual installs an agent release only on an administrator's request per device. Device
-- groups override it (device_group.agent_update_policy, migration 00053). Forward-only: there is no Down migration.
-- +goose Up
ALTER TABLE organization_update_settings
  ADD COLUMN agent_update_policy text NOT NULL DEFAULT 'automatic' CHECK (agent_update_policy IN ('automatic','manual'));

-- +goose Down
