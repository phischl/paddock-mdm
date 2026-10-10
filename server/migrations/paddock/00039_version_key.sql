-- Agent versions compare by SemVer 2.0.0 precedence, not as text (PDK-025): "agent outdated" means older than the
-- current release, the release list sorts 0.2.0 before 0.10.0, and the newest-release tie-breakers order by version.
-- Forward-only: there is no Down migration. The versions 00036 to 00038 are not used on this branch.
-- +goose Up

-- paddock_version_key maps a semantic version to text whose byte order (COLLATE "C") is its precedence, the order of
-- pkg/semver.Compare (a test keeps both equal); NULL for anything that is no semantic version. Build metadata is
-- ignored. Every identifier gets a marker, numeric ones (those Compare parses as uint64) '0' and 20 zero-padded
-- digits, alphanumeric ones '1' and the identifier. '#' separates identifiers and '!' ends a list: both sort below
-- every identifier character, so a shorter list ranks lower. After the core, '~' (a release) sorts above '-'
-- followed by the pre-release identifiers.
-- +goose StatementBegin
CREATE FUNCTION paddock_version_key(v text) RETURNS text LANGUAGE plpgsql IMMUTABLE STRICT PARALLEL SAFE AS $$
DECLARE
  parts text[];
  id text;
  digits text;
  ids text[];
  key text := '';
BEGIN
  IF v !~ '^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$' THEN
    RETURN NULL;
  END IF;
  v := split_part(v, '+', 1);
  parts := ARRAY[split_part(v, '-', 1), substr(v, length(split_part(v, '-', 1)) + 2)];
  FOR n IN 1 .. 2 LOOP
    IF n = 2 THEN
      IF parts[2] = '' THEN
        RETURN key || '~';
      END IF;
      key := key || '-';
    END IF;
    ids := ARRAY[]::text[];
    FOREACH id IN ARRAY string_to_array(parts[n], '.') LOOP
      digits := CASE WHEN id ~ '^[0-9]+$' THEN coalesce(nullif(ltrim(id, '0'), ''), '0') END;
      IF length(digits) < 20 OR (length(digits) = 20 AND digits <= '18446744073709551615') THEN
        ids := ids || ('0' || lpad(digits, 20, '0'));
      ELSE
        ids := ids || ('1' || id);
      END IF;
    END LOOP;
    key := key || array_to_string(ids, '#') || '!';
  END LOOP;
  RETURN key;
END $$;
-- +goose StatementEnd

-- The key is computed when a release is uploaded (inserted) and for every existing release.
ALTER TABLE agent_release
  ADD COLUMN version_key text COLLATE "C" GENERATED ALWAYS AS (paddock_version_key(version)) STORED NOT NULL;

-- The current release: the most recently completed rollout; the higher version wins a tie.
CREATE OR REPLACE FUNCTION paddock_current_agent_version() RETURNS text
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, pg_temp AS
  $$ SELECT ro.version FROM agent_rollout ro JOIN agent_release r USING (version) WHERE ro.status = 'completed'
     ORDER BY ro.updated_at DESC, r.version_key DESC LIMIT 1 $$;

CREATE OR REPLACE FUNCTION paddock_install_packages(package_arch text)
  RETURNS TABLE (version text, name text, sha256 text, object_key text)
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, pg_temp AS
  $$ WITH release AS (
       SELECT r.version FROM agent_release r
       WHERE r.status = 'published'
         AND (SELECT count(DISTINCT p.name) FROM agent_package p
              WHERE p.version = r.version AND p.arch = package_arch
                AND p.name IN ('paddock-agent','paddock-supervisor')) = 2
         AND NOT EXISTS (SELECT 1 FROM agent_rollout ro WHERE ro.version = r.version AND ro.status = 'halted')
       ORDER BY r.published_at DESC, r.version_key DESC
       LIMIT 1)
     SELECT p.version, p.name, p.sha256, p.object_key FROM agent_package p JOIN release USING (version)
     WHERE p.arch = package_arch AND p.name IN ('paddock-agent','paddock-supervisor','paddock-revoke')
     ORDER BY p.name DESC $$;

CREATE OR REPLACE FUNCTION paddock_fleetd_package(package_arch text)
  RETURNS TABLE (package_version text, sha256 text, object_key text)
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, pg_temp AS
  $$ SELECT p.package_version, p.sha256, p.object_key
     FROM agent_package p JOIN agent_release r USING (version)
     WHERE p.name = 'fleet-osquery' AND p.arch = package_arch AND r.status = 'published'
       AND NOT EXISTS (SELECT 1 FROM agent_rollout ro WHERE ro.version = r.version AND ro.status = 'halted')
     ORDER BY r.published_at DESC, r.version_key DESC
     LIMIT 1 $$;

-- agent_outdated: the device's agent is older than the current release, or reports no semantic version (the
-- supervisor lets any signed release replace such an agent). A device on a newer agent is not outdated.
CREATE OR REPLACE VIEW attention_condition WITH (security_invoker = true) AS
  SELECT a.kind, d.id AS device_id, d.hostname, a.raised_at AS since, ''::text AS detail, (a.kind || ':' || a.id::text)::text AS id
  FROM device_alert a JOIN device d ON d.id = a.device_id
  WHERE a.cleared_at IS NULL AND d.state = 'active'
  UNION ALL
  SELECT 'presumed_lost', d.id, d.hostname, s.presumed_lost_at, '', 'presumed_lost:' || d.id::text
  FROM device d JOIN device_status s ON s.device_id = d.id
  WHERE d.state = 'active' AND s.presumed_lost_at IS NOT NULL
  UNION ALL
  SELECT 'quarantined', d.id, d.hostname, d.state_changed_at, '', 'quarantined:' || d.id::text
  FROM device d WHERE d.state = 'quarantined'
  UNION ALL
  SELECT 'disk_not_compliant', d.id, d.hostname, coalesce(s.last_contact_at, d.state_changed_at), s.health -> 'disk' ->> 'state',
    'disk_not_compliant:' || d.id::text
  FROM device d JOIN device_status s ON s.device_id = d.id
  WHERE d.state = 'active' AND s.health -> 'disk' ->> 'state' IS NOT NULL AND s.health -> 'disk' ->> 'state' <> 'compliant'
  UNION ALL
  SELECT 'agent_outdated', d.id, d.hostname, coalesce(s.last_contact_at, d.state_changed_at), s.agent_version,
    'agent_outdated:' || d.id::text
  FROM device d JOIN device_status s ON s.device_id = d.id
  CROSS JOIN (SELECT paddock_version_key(paddock_current_agent_version()) COLLATE "C" AS version_key) r
  WHERE d.state = 'active' AND r.version_key IS NOT NULL AND s.agent_version IS NOT NULL
    AND coalesce(paddock_version_key(s.agent_version) COLLATE "C" < r.version_key, true)
  UNION ALL
  SELECT replace(s.login_state -> area.name ->> 'type', '.', '_'), d.id, d.hostname,
    coalesce((s.login_state -> area.name ->> 'occurred_at')::timestamptz, d.state_changed_at), coalesce(s.login_state -> area.name -> 'params' ->> 'stage', ''),
    area.name || '_apply_failed:' || d.id::text
  FROM device d JOIN device_status s ON s.device_id = d.id
  CROSS JOIN (VALUES ('login'), ('sudo')) AS area(name)
  WHERE d.state = 'active' AND s.login_state -> area.name ->> 'type' IN ('login.apply_failed', 'sudo.apply_failed')
  UNION ALL
  SELECT CASE WHEN r.status = 'expired' THEN 'revocation_expired' ELSE 'revocation_pending' END, d.id, d.hostname,
    CASE WHEN r.status = 'expired' THEN coalesce(r.finished_at, r.requested_at) ELSE r.requested_at END, r.action || ':' || r.status,
    'revocation:' || r.id::text
  FROM revocation_request r JOIN device d ON d.id = r.device_id
  WHERE r.action IN ('lock', 'destroy')
    AND (r.status IN ('requested', 'approved', 'issued', 'delivered')
         OR (r.status = 'expired' AND coalesce(r.finished_at, r.requested_at) > now() - interval '30 days'));

-- +goose Down
