-- Login notice (plan M4a decision 19): shown at the login screen, on text consoles and before SSH logins of every
-- device of the organization. Forward-only: there is no Down migration. An empty text removes the notice.
-- +goose Up

ALTER TABLE organization_login_settings
  ADD COLUMN notice_text text NOT NULL
    DEFAULT 'This device is managed by your organization. Use it only as permitted by the acceptable-use policy. Logins and administrative actions on this device are logged.'
    CHECK (char_length(notice_text) <= 2000);

-- +goose Down
