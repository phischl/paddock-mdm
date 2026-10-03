-- Indexes for the sortable list columns (ADR 0018, plan M0.2 decision 7). Forward-only: there is no Down migration.
-- device_group (organization_id, name) is covered by its unique constraint.
-- +goose Up
CREATE INDEX device_group_org_created_idx ON device_group (organization_id, created_at);
CREATE INDEX device_group_org_updated_idx ON device_group (organization_id, updated_at);
CREATE INDEX organization_created_idx ON organization (created_at);

-- +goose Down
