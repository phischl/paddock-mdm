-- The self-service app package of agent releases (plan M13b, amendment 2026-11-11; ADR 0043 amendment 2026-11-11).
-- A release may carry paddock-self-service, architecture-independent (arch all) and signed with the agent release key,
-- stored at packages/<version>/paddock-self-service_<version>_all.deb. The name and the architecture are valid only
-- together, so `all` never becomes an agent architecture and the self-service app never one of a specific
-- architecture. Neither the autoinstall nor the agent update installs it. Forward-only: there is no Down migration.
-- +goose Up

ALTER TABLE agent_package DROP CONSTRAINT agent_package_name_check;
ALTER TABLE agent_package ADD CONSTRAINT agent_package_name_check
  CHECK (name IN ('paddock-agent','paddock-supervisor','paddock-revoke','fleet-osquery','paddock-self-service'));
ALTER TABLE agent_package DROP CONSTRAINT agent_package_arch_check;
ALTER TABLE agent_package ADD CONSTRAINT agent_package_arch_check
  CHECK (CASE WHEN name = 'paddock-self-service' THEN arch = 'all' ELSE arch IN ('amd64','arm64') END);

-- +goose Down
