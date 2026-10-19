-- Login history since its switch-on (plan M8d decision 16, PDK-223 review 1 finding 13): the moment an organization
-- switched its login history on, so that sessions which started before the opt-in are not stored. NULL while the
-- history is off; an organization that switched it on before this migration keeps NULL (no cutoff). Forward-only:
-- there is no Down migration.
-- +goose Up
ALTER TABLE organization_login_settings ADD COLUMN login_history_enabled_at timestamptz;

-- +goose Down
