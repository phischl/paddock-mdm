-- Vulnerability severity from Ubuntu's OSV data (ADR 0020, plan M5c decisions 1 and 2). Forward-only: there is no Down
-- migration.
-- osv_ubuntu holds Ubuntu's priority, fixed version and CVSS vector per CVE, release and source package;
-- osv_ubuntu_binary maps the binary packages a source package builds, as the records list them, because Fleet reports
-- binary package names (openssh-client) and no source package. Both are platform data without organization data,
-- written by the worker's platform pool (osv-sync, paddock-server osv import). The worker enriches the organizations'
-- findings through paddock_osv_match. osv_sync_state is the state of the download (ETag, last success, stale alert).
-- +goose Up

CREATE TABLE osv_ubuntu (
  cve text NOT NULL,
  release text NOT NULL CHECK (release ~ '^[0-9]{2}\.[0-9]{2}$'),
  package text NOT NULL,
  priority text NOT NULL DEFAULT '',
  fixed_version text,
  cvss_vector text,
  modified timestamptz,
  PRIMARY KEY (cve, release, package)
);

CREATE TABLE osv_ubuntu_binary (
  release text NOT NULL,
  binary_name text NOT NULL,
  package text NOT NULL,
  PRIMARY KEY (release, binary_name, package)
);

CREATE TABLE osv_sync_state (
  source text PRIMARY KEY CHECK (source = 'ubuntu'),
  etag text NOT NULL DEFAULT '',
  -- data_version counts the successful imports; the worker enriches the findings again when it changed.
  data_version bigint NOT NULL DEFAULT 0,
  entries int NOT NULL DEFAULT 0,
  last_success_at timestamptz,
  last_attempt_at timestamptz,
  last_error text NOT NULL DEFAULT '',
  stale_alerted_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);
INSERT INTO osv_sync_state (source) VALUES ('ubuntu');

GRANT SELECT, INSERT, DELETE ON osv_ubuntu, osv_ubuntu_binary TO paddock_platform;
GRANT SELECT, UPDATE ON osv_sync_state TO paddock_platform;

ALTER TABLE vulnerability_finding ADD COLUMN cvss_vector text;

-- paddock_osv_match returns Ubuntu's data of a CVE in a release for a package as the inventory system names it: the
-- package as a source package first, then the source packages that build it as a binary package; of several, the
-- highest priority. Severity is the priority on Paddock's scale: negligible is low, untriaged and unknown values are
-- NULL.
CREATE FUNCTION paddock_osv_match(rel text, cve_id text, pkg text)
  RETURNS TABLE (severity text, fixed_version text, cvss_vector text)
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS
  $$ SELECT CASE o.priority WHEN 'critical' THEN 'critical' WHEN 'high' THEN 'high' WHEN 'medium' THEN 'medium'
                            WHEN 'low' THEN 'low' WHEN 'negligible' THEN 'low' END,
            o.fixed_version, o.cvss_vector
     FROM osv_ubuntu o
     WHERE o.release = rel AND o.cve = cve_id
       AND (o.package = pkg OR o.package IN (SELECT b.package FROM osv_ubuntu_binary b
                                            WHERE b.release = rel AND b.binary_name = pkg))
     ORDER BY o.package = pkg DESC,
              CASE o.priority WHEN 'critical' THEN 5 WHEN 'high' THEN 4 WHEN 'medium' THEN 3 WHEN 'low' THEN 2
                              WHEN 'negligible' THEN 1 ELSE 0 END DESC,
              o.package
     LIMIT 1 $$;
REVOKE ALL ON FUNCTION paddock_osv_match(text, text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION paddock_osv_match(text, text, text) TO paddock_worker;

-- +goose Down
