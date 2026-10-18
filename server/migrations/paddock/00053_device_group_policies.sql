-- Policy overrides of a device group (ADR 0037 decisions 1 and 8, ADR 0038 decision 2; plan M8d decision 10,
-- PDK-222): contact thresholds (hours; both or none, critical above warning), the agent update policy and the disk
-- unlock mode. NULL means "the organization's setting". A device in several groups takes the most lenient thresholds
-- and the stricter policy (the use cases resolve it). Forward-only: there is no Down migration.
-- +goose Up
ALTER TABLE device_group
  ADD COLUMN staleness_warning_h int CHECK (staleness_warning_h BETWEEN 1 AND 720),
  ADD COLUMN staleness_critical_h int CHECK (staleness_critical_h <= 2160),
  ADD COLUMN agent_update_policy text CHECK (agent_update_policy IN ('automatic','manual')),
  ADD COLUMN disk_unlock_mode text CHECK (disk_unlock_mode IN ('tpm_pin','tpm_only')),
  ADD CONSTRAINT device_group_staleness_pair CHECK ((staleness_warning_h IS NULL) = (staleness_critical_h IS NULL)),
  ADD CONSTRAINT device_group_staleness_order CHECK (staleness_critical_h IS NULL OR staleness_critical_h > staleness_warning_h);

-- +goose Down
