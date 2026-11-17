-- When the inventory system stored the first failing evaluation of the current failure of a policy, in its own clock
-- (Fleet's policy_updated_at of the host); NULL while the policy passes or the time is unknown (plan M5a amendment
-- 2026-11-16 b, D3). The mutual watch reports an agent absent from evaluations 15 minutes apart while the device
-- checks in. Forward-only: there is no Down migration.
-- +goose Up
ALTER TABLE inventory_policy_result ADD COLUMN failing_since timestamptz;

-- +goose Down
