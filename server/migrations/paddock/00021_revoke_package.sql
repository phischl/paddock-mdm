-- The paddock-revoke package (plan M4c decision 4). Forward-only: there is no Down migration.
-- A release may carry paddock-revoke, signed with the revocation release key; the Paddock autoinstall installs the
-- newest published release that has paddock-agent and paddock-supervisor, together with its paddock-revoke if it
-- has one.
-- +goose Up

ALTER TABLE agent_package DROP CONSTRAINT agent_package_name_check;
ALTER TABLE agent_package ADD CONSTRAINT agent_package_name_check
  CHECK (name IN ('paddock-agent','paddock-supervisor','paddock-revoke'));

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
     WHERE p.arch = package_arch ORDER BY p.name DESC $$;

-- +goose Down
