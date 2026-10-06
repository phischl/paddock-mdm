-- Debian packages of agent releases (plan M4b decision 1). Forward-only: there is no Down migration. The packages
-- paddock-agent and paddock-supervisor of a release are stored in paddock-agent-artifacts under
-- packages/<version>/<name>_<version>_<arch>.deb, which is public-read (packages carry no secrets); the Paddock
-- autoinstall downloads them and checks their SHA-256. Platform data like the release itself.
-- +goose Up

CREATE TABLE agent_package (
  version text NOT NULL REFERENCES agent_release(version),
  name text NOT NULL CHECK (name IN ('paddock-agent','paddock-supervisor')),
  arch text NOT NULL CHECK (arch IN ('amd64','arm64')),
  sha256 text NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'), size bigint NOT NULL CHECK (size > 0),
  minisig text NOT NULL,      -- standard base64 of the .minisig file of the package
  object_key text NOT NULL,   -- packages/<version>/<name>_<version>_<arch>.deb in paddock-agent-artifacts
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (version, name, arch)
);

GRANT SELECT, INSERT, UPDATE ON agent_package TO paddock_platform;

-- +goose Down
