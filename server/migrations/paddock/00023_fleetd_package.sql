-- The fleetd package of agent releases (plan M5a decision 3). Forward-only: there is no Down migration.
-- A release may carry fleet-osquery, built with `fleetctl package` and signed with the agent release key; its file is
-- named after the fleetd version (package_version), packages/<version>/fleet-osquery_<package_version>_<arch>.deb.
-- The agent installs it from the bundle's inventory section, never the Paddock autoinstall.
-- paddock_fleetd_package lets the compiler (organization scope) read the package of the newest published release that
-- has one for an architecture and whose rollout is not halted.
-- +goose Up

ALTER TABLE agent_package DROP CONSTRAINT agent_package_name_check;
ALTER TABLE agent_package ADD CONSTRAINT agent_package_name_check
  CHECK (name IN ('paddock-agent','paddock-supervisor','paddock-revoke','fleet-osquery'));
ALTER TABLE agent_package ADD COLUMN package_version text
  CHECK (package_version ~ '^[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}$');
ALTER TABLE agent_package ADD CONSTRAINT agent_package_version_check
  CHECK ((name = 'fleet-osquery') = (package_version IS NOT NULL));

CREATE OR REPLACE FUNCTION paddock_install_packages(package_arch text)
  RETURNS TABLE (version text, name text, sha256 text, object_key text)
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS
  $$ WITH release AS (
       SELECT r.version FROM agent_release r
       WHERE r.status = 'published'
         AND (SELECT count(DISTINCT p.name) FROM agent_package p
              WHERE p.version = r.version AND p.arch = package_arch
                AND p.name IN ('paddock-agent','paddock-supervisor')) = 2
         AND NOT EXISTS (SELECT 1 FROM agent_rollout ro WHERE ro.version = r.version AND ro.status = 'halted')
       ORDER BY r.published_at DESC, r.version DESC
       LIMIT 1)
     SELECT p.version, p.name, p.sha256, p.object_key FROM agent_package p JOIN release USING (version)
     WHERE p.arch = package_arch AND p.name IN ('paddock-agent','paddock-supervisor','paddock-revoke')
     ORDER BY p.name DESC $$;

CREATE FUNCTION paddock_fleetd_package(package_arch text)
  RETURNS TABLE (package_version text, sha256 text, object_key text)
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS
  $$ SELECT p.package_version, p.sha256, p.object_key
     FROM agent_package p JOIN agent_release r USING (version)
     WHERE p.name = 'fleet-osquery' AND p.arch = package_arch AND r.status = 'published'
       AND NOT EXISTS (SELECT 1 FROM agent_rollout ro WHERE ro.version = r.version AND ro.status = 'halted')
     ORDER BY r.published_at DESC, r.version DESC
     LIMIT 1 $$;
REVOKE ALL ON FUNCTION paddock_fleetd_package(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION paddock_fleetd_package(text) TO paddock_compiler;

-- +goose Down
