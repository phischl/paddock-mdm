-- IP allow list of the administrative surfaces (plan M7a decision 10). Forward-only: there is no Down migration.
-- Platform data (no organization; role paddock_platform only): enforced by every api replica before sessions and
-- tokens, managed by platform administrators in the portal or by paddock-server admin allowlist on the host.
-- +goose Up

CREATE TABLE ip_allowlist_entry (
  id         uuid PRIMARY KEY,
  cidr       cidr NOT NULL UNIQUE,
  label      text NOT NULL CHECK (char_length(label) BETWEEN 1 AND 64),
  created_by text NOT NULL,              -- display name of the platform administrator, or "paddock-server admin"
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ip_allowlist_entry_created_idx ON ip_allowlist_entry (created_at);
GRANT SELECT, INSERT, UPDATE, DELETE ON ip_allowlist_entry TO paddock_platform;
