-- Managed local administrator (plan M4a decision 13): account name and rotation settings of an organization.
-- Forward-only: there is no Down migration.
-- +goose Up

ALTER TABLE organization_login_settings
  ADD COLUMN local_admin_username text NOT NULL DEFAULT 'paddock-admin'
    CHECK (local_admin_username ~ '^[a-z_][a-z0-9_-]{0,31}$'),
  ADD COLUMN local_admin_rotation_days int NOT NULL DEFAULT 30 CHECK (local_admin_rotation_days BETWEEN 1 AND 365),
  ADD COLUMN rotate_after_reveal_hours int CHECK (rotate_after_reveal_hours BETWEEN 1 AND 168);

-- +goose Down
