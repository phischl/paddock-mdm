-- Portal theme preference on the account (plan M7c decision 1, ADR 0023): system follows prefers-color-scheme,
-- light and dark are explicit choices. Forward-only: there is no Down migration. Number 00036 is M7a's.
-- +goose Up

ALTER TABLE admin_account  ADD COLUMN theme text NOT NULL DEFAULT 'system' CHECK (theme IN ('system', 'light', 'dark'));
ALTER TABLE platform_admin ADD COLUMN theme text NOT NULL DEFAULT 'system' CHECK (theme IN ('system', 'light', 'dark'));

-- +goose Down
