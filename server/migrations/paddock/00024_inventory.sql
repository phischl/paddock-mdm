-- Inventory and vulnerabilities (plan M5a decisions 6 and 7). Forward-only: there is no Down migration.
-- The worker maps Fleet hosts to devices by hardware UUID and stores, per device of the organization: the reference
-- to the Fleet host (the only place a Fleet ID appears), the installed packages, the vulnerability findings and the
-- results of Paddock's policies. The api reads them; every table is organization-scoped with forced RLS.
-- paddock_inventory_devices lets the worker's platform pool map hardware UUIDs to devices across organizations: it
-- returns a UUID only if exactly one active or quarantined device has it, so an ambiguous host is never stored.
-- +goose Up

CREATE TABLE device_inventory_ref (
  device_id uuid PRIMARY KEY REFERENCES device(id),
  organization_id uuid NOT NULL,
  external_id text NOT NULL,
  last_seen_at timestamptz,
  os_version text NOT NULL DEFAULT '',
  fleetd_version text NOT NULL DEFAULT '',
  synced_at timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (organization_id, device_id) REFERENCES device (organization_id, id)
);

CREATE TABLE installed_software (
  device_id uuid NOT NULL REFERENCES device(id),
  organization_id uuid NOT NULL,
  name text NOT NULL,
  version text NOT NULL,
  source text NOT NULL,
  PRIMARY KEY (device_id, name, version, source),
  FOREIGN KEY (organization_id, device_id) REFERENCES device (organization_id, id)
);
CREATE INDEX installed_software_org_name ON installed_software (organization_id, name, version);

CREATE TABLE vulnerability_finding (
  device_id uuid NOT NULL REFERENCES device(id),
  organization_id uuid NOT NULL,
  cve text NOT NULL,
  software_name text NOT NULL,
  software_version text NOT NULL,
  cvss_score numeric(3,1) CHECK (cvss_score BETWEEN 0 AND 10),
  severity text CHECK (severity IN ('critical','high','medium','low')),
  fixed_version text,
  first_seen_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (device_id, cve, software_name, software_version),
  FOREIGN KEY (organization_id, device_id) REFERENCES device (organization_id, id)
);
CREATE INDEX vulnerability_finding_org_cve ON vulnerability_finding (organization_id, cve);

CREATE TABLE inventory_policy_result (
  device_id uuid NOT NULL REFERENCES device(id),
  organization_id uuid NOT NULL,
  policy_key text NOT NULL,
  passing boolean NOT NULL,
  updated_at timestamptz NOT NULL,
  -- When the mutual watch reported the current failure of paddock_agent_running (plan M5a decision 8); cleared when
  -- the policy passes again.
  alerted_at timestamptz,
  PRIMARY KEY (device_id, policy_key),
  FOREIGN KEY (organization_id, device_id) REFERENCES device (organization_id, id)
);

ALTER TABLE device_inventory_ref ENABLE ROW LEVEL SECURITY;
ALTER TABLE device_inventory_ref FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON device_inventory_ref TO paddock_api, paddock_worker
  USING (organization_id = current_setting('paddock.org_id')::uuid)
  WITH CHECK (organization_id = current_setting('paddock.org_id')::uuid);

ALTER TABLE installed_software ENABLE ROW LEVEL SECURITY;
ALTER TABLE installed_software FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON installed_software TO paddock_api, paddock_worker
  USING (organization_id = current_setting('paddock.org_id')::uuid)
  WITH CHECK (organization_id = current_setting('paddock.org_id')::uuid);

ALTER TABLE vulnerability_finding ENABLE ROW LEVEL SECURITY;
ALTER TABLE vulnerability_finding FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON vulnerability_finding TO paddock_api, paddock_worker
  USING (organization_id = current_setting('paddock.org_id')::uuid)
  WITH CHECK (organization_id = current_setting('paddock.org_id')::uuid);

ALTER TABLE inventory_policy_result ENABLE ROW LEVEL SECURITY;
ALTER TABLE inventory_policy_result FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON inventory_policy_result TO paddock_api, paddock_worker
  USING (organization_id = current_setting('paddock.org_id')::uuid)
  WITH CHECK (organization_id = current_setting('paddock.org_id')::uuid);

GRANT SELECT ON device_inventory_ref, installed_software, vulnerability_finding, inventory_policy_result TO paddock_api;
GRANT SELECT, INSERT, UPDATE, DELETE ON device_inventory_ref, installed_software, vulnerability_finding,
  inventory_policy_result TO paddock_worker;

CREATE FUNCTION paddock_inventory_devices(uuids text[])
  RETURNS TABLE (hardware_uuid text, device_id uuid, organization_id uuid)
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS
  $$ SELECT lower(d.hardware_uuid), min(d.id::text)::uuid, min(d.organization_id::text)::uuid
     FROM device d
     WHERE lower(d.hardware_uuid) = ANY (SELECT lower(u) FROM unnest(uuids) u)
       AND d.state IN ('active','quarantined')
     GROUP BY lower(d.hardware_uuid)
     HAVING count(*) = 1 $$;
REVOKE ALL ON FUNCTION paddock_inventory_devices(text[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION paddock_inventory_devices(text[]) TO paddock_platform;

-- +goose Down
