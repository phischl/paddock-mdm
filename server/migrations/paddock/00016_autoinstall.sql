-- Paddock autoinstall (plan M4b decisions 2 and 4). Forward-only: there is no Down migration.
-- boot_pin_min_length is the shortest boot PIN the first-boot disk setup accepts; it is embedded in generated
-- autoinstalls only, never in bundles. paddock_install_packages lets the api (organization scope) read the public
-- packages of the newest published release that has both of them for an architecture and whose rollout is not
-- halted; nothing but those package facts leaves the platform data.
-- +goose Up

ALTER TABLE organization_login_settings
  ADD COLUMN boot_pin_min_length int NOT NULL DEFAULT 8 CHECK (boot_pin_min_length BETWEEN 6 AND 32);

CREATE FUNCTION paddock_install_packages(package_arch text)
  RETURNS TABLE (version text, name text, sha256 text, object_key text)
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS
  $$ WITH release AS (
       SELECT r.version FROM agent_release r
       WHERE r.status = 'published'
         AND (SELECT count(DISTINCT p.name) FROM agent_package p WHERE p.version = r.version AND p.arch = package_arch) = 2
         AND NOT EXISTS (SELECT 1 FROM agent_rollout ro WHERE ro.version = r.version AND ro.status = 'halted')
       ORDER BY r.published_at DESC, r.version DESC
       LIMIT 1)
     SELECT p.version, p.name, p.sha256, p.object_key FROM agent_package p JOIN release USING (version)
     WHERE p.arch = package_arch ORDER BY p.name DESC $$;
REVOKE ALL ON FUNCTION paddock_install_packages(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION paddock_install_packages(text) TO paddock_api;

-- +goose Down
