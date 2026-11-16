-- When the host last evaluated its policies, as the inventory system reports it (plan M5a amendment 2026-11-16, A3,
-- ADR 0056): the agent binary policy reports a failure only from an evaluation made at least 2 minutes after the
-- worker applied the current definition. NULL until the next sync of the host. Forward-only: there is no Down
-- migration.
-- +goose Up
ALTER TABLE device_inventory_ref ADD COLUMN policy_updated_at timestamptz;

-- +goose Down
