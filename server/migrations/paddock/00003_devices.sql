-- Devices, enrollment, managed configuration and bundles (plan M2a §6.1). Forward-only: there is no Down migration.
-- Roles paddock_worker and paddock_compiler are created by deploy/compose/postgres/init/10-roles.sh. Both consume
-- messages of every organization by opening one InOrg transaction per message; they get tenant policies only.
-- +goose Up

-- Composite keys let foreign keys from user input carry the organization, so a reference can never point into
-- another organization even though foreign key checks bypass row-level security.
ALTER TABLE device_group ADD CONSTRAINT device_group_org_id_key UNIQUE (organization_id, id);

CREATE TABLE enrollment_token (
  id uuid PRIMARY KEY, organization_id uuid NOT NULL REFERENCES organization(id),
  name text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 100),
  secret_sha256 bytea NOT NULL UNIQUE,
  device_group_id uuid REFERENCES device_group(id),
  auto_approve boolean NOT NULL, max_uses int NOT NULL CHECK (max_uses BETWEEN 1 AND 1000),
  uses int NOT NULL DEFAULT 0, expires_at timestamptz NOT NULL, revoked_at timestamptz,
  created_by uuid NOT NULL, created_at timestamptz NOT NULL DEFAULT now(),
  CHECK (uses BETWEEN 0 AND max_uses),
  FOREIGN KEY (organization_id, device_group_id) REFERENCES device_group (organization_id, id)
);
CREATE TABLE device (
  id uuid PRIMARY KEY, organization_id uuid NOT NULL REFERENCES organization(id),
  hostname text NOT NULL, state text NOT NULL CHECK (state IN ('pending','active','rejected','quarantined','retired')),
  bundle_seq bigint NOT NULL DEFAULT 0, hardware_uuid text, machine_id text, os_release jsonb NOT NULL DEFAULT '{}',
  enrollment_token_id uuid REFERENCES enrollment_token(id), enrolled_at timestamptz NOT NULL DEFAULT now(),
  state_changed_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (organization_id, id)
);
CREATE TABLE device_identity_key (
  key_id text PRIMARY KEY,                 -- hex sha256 of the SubjectPublicKeyInfo DER
  organization_id uuid NOT NULL, device_id uuid NOT NULL REFERENCES device(id),
  public_key bytea NOT NULL,               -- SubjectPublicKeyInfo DER, ECDSA P-256
  key_protection text NOT NULL CHECK (key_protection IN ('tpm','file')),
  status text NOT NULL CHECK (status IN ('active','revoked')), created_at timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (organization_id, device_id) REFERENCES device (organization_id, id)
);
CREATE TABLE device_group_member (
  organization_id uuid NOT NULL, device_group_id uuid NOT NULL REFERENCES device_group(id) ON DELETE CASCADE,
  device_id uuid NOT NULL REFERENCES device(id), PRIMARY KEY (device_group_id, device_id),
  FOREIGN KEY (organization_id, device_group_id) REFERENCES device_group (organization_id, id) ON DELETE CASCADE,
  FOREIGN KEY (organization_id, device_id) REFERENCES device (organization_id, id)
);
CREATE TABLE device_status (
  device_id uuid PRIMARY KEY REFERENCES device(id), organization_id uuid NOT NULL,
  last_contact_at timestamptz, applied_bundle_version bigint, agent_version text, last_seq bigint NOT NULL DEFAULT 0,
  health jsonb NOT NULL DEFAULT '{}',
  FOREIGN KEY (organization_id, device_id) REFERENCES device (organization_id, id)
);
CREATE TABLE bundle (
  device_id uuid NOT NULL REFERENCES device(id), version bigint NOT NULL, organization_id uuid NOT NULL,
  content_sha256 bytea NOT NULL, envelope_sha256 bytea NOT NULL, object_key text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY (device_id, version),
  FOREIGN KEY (organization_id, device_id) REFERENCES device (organization_id, id)
);
CREATE TABLE managed_file (
  id uuid PRIMARY KEY, organization_id uuid NOT NULL REFERENCES organization(id),
  device_group_id uuid REFERENCES device_group(id) ON DELETE CASCADE,
  path text NOT NULL, mode text NOT NULL, owner text NOT NULL DEFAULT 'root', grp text NOT NULL DEFAULT 'root',
  content text NOT NULL, created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE NULLS NOT DISTINCT (organization_id, device_group_id, path),
  FOREIGN KEY (organization_id, device_group_id) REFERENCES device_group (organization_id, id) ON DELETE CASCADE
);
CREATE TABLE managed_unit (
  id uuid PRIMARY KEY, organization_id uuid NOT NULL REFERENCES organization(id),
  device_group_id uuid REFERENCES device_group(id) ON DELETE CASCADE,
  unit text NOT NULL, enabled boolean NOT NULL, active boolean NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE NULLS NOT DISTINCT (organization_id, device_group_id, unit),
  FOREIGN KEY (organization_id, device_group_id) REFERENCES device_group (organization_id, id) ON DELETE CASCADE
);
CREATE TABLE device_event_seen (
  device_id uuid NOT NULL, event_seq bigint NOT NULL, organization_id uuid NOT NULL, PRIMARY KEY (device_id, event_seq)
);

-- List and lookup indexes (ADR 0018).
CREATE INDEX enrollment_token_org_name_idx ON enrollment_token (organization_id, name);
CREATE INDEX enrollment_token_org_created_idx ON enrollment_token (organization_id, created_at);
CREATE INDEX enrollment_token_org_expires_idx ON enrollment_token (organization_id, expires_at);
CREATE INDEX device_org_hostname_idx ON device (organization_id, hostname);
CREATE INDEX device_org_enrolled_idx ON device (organization_id, enrolled_at);
CREATE INDEX device_org_state_idx ON device (organization_id, state);
CREATE INDEX device_identity_key_device_idx ON device_identity_key (device_id);
CREATE INDEX device_group_member_device_idx ON device_group_member (device_id);
CREATE INDEX device_status_org_contact_idx ON device_status (organization_id, last_contact_at);
CREATE INDEX managed_file_org_path_idx ON managed_file (organization_id, path);
CREATE INDEX managed_unit_org_unit_idx ON managed_unit (organization_id, unit);

-- Row-level security: tenant policies for exactly the roles that use each table.
ALTER TABLE enrollment_token ENABLE ROW LEVEL SECURITY;  ALTER TABLE enrollment_token FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON enrollment_token TO paddock_api, paddock_worker
  USING (organization_id = current_setting('paddock.org_id')::uuid)
  WITH CHECK (organization_id = current_setting('paddock.org_id')::uuid);
ALTER TABLE device ENABLE ROW LEVEL SECURITY;  ALTER TABLE device FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON device TO paddock_api, paddock_worker, paddock_compiler
  USING (organization_id = current_setting('paddock.org_id')::uuid)
  WITH CHECK (organization_id = current_setting('paddock.org_id')::uuid);
ALTER TABLE device_identity_key ENABLE ROW LEVEL SECURITY;  ALTER TABLE device_identity_key FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON device_identity_key TO paddock_api, paddock_worker
  USING (organization_id = current_setting('paddock.org_id')::uuid)
  WITH CHECK (organization_id = current_setting('paddock.org_id')::uuid);
ALTER TABLE device_group_member ENABLE ROW LEVEL SECURITY;  ALTER TABLE device_group_member FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON device_group_member TO paddock_api, paddock_worker, paddock_compiler
  USING (organization_id = current_setting('paddock.org_id')::uuid)
  WITH CHECK (organization_id = current_setting('paddock.org_id')::uuid);
ALTER TABLE device_status ENABLE ROW LEVEL SECURITY;  ALTER TABLE device_status FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON device_status TO paddock_api, paddock_worker
  USING (organization_id = current_setting('paddock.org_id')::uuid)
  WITH CHECK (organization_id = current_setting('paddock.org_id')::uuid);
ALTER TABLE bundle ENABLE ROW LEVEL SECURITY;  ALTER TABLE bundle FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON bundle TO paddock_api, paddock_compiler
  USING (organization_id = current_setting('paddock.org_id')::uuid)
  WITH CHECK (organization_id = current_setting('paddock.org_id')::uuid);
ALTER TABLE managed_file ENABLE ROW LEVEL SECURITY;  ALTER TABLE managed_file FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON managed_file TO paddock_api, paddock_compiler
  USING (organization_id = current_setting('paddock.org_id')::uuid)
  WITH CHECK (organization_id = current_setting('paddock.org_id')::uuid);
ALTER TABLE managed_unit ENABLE ROW LEVEL SECURITY;  ALTER TABLE managed_unit FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON managed_unit TO paddock_api, paddock_compiler
  USING (organization_id = current_setting('paddock.org_id')::uuid)
  WITH CHECK (organization_id = current_setting('paddock.org_id')::uuid);
ALTER TABLE device_event_seen ENABLE ROW LEVEL SECURITY;  ALTER TABLE device_event_seen FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON device_event_seen TO paddock_worker
  USING (organization_id = current_setting('paddock.org_id')::uuid)
  WITH CHECK (organization_id = current_setting('paddock.org_id')::uuid);
-- Existing tables used by the new roles.
CREATE POLICY tenant_worker_compiler ON device_group TO paddock_worker, paddock_compiler
  USING (organization_id = current_setting('paddock.org_id')::uuid);
CREATE POLICY tenant_worker_compiler ON action TO paddock_worker, paddock_compiler
  USING (organization_id = current_setting('paddock.org_id')::uuid)
  WITH CHECK (organization_id = current_setting('paddock.org_id')::uuid);
CREATE POLICY tenant_worker_compiler ON outbox TO paddock_worker, paddock_compiler
  USING (organization_id = current_setting('paddock.org_id')::uuid)
  WITH CHECK (organization_id = current_setting('paddock.org_id')::uuid);

-- The cache loops of worker and compiler iterate organizations without an organization context. The function
-- reveals nothing but the IDs; all organization data is then read with InOrg.
CREATE FUNCTION paddock_organization_ids() RETURNS SETOF uuid
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS
  $$ SELECT id FROM organization ORDER BY id $$;
REVOKE ALL ON FUNCTION paddock_organization_ids() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION paddock_organization_ids() TO paddock_worker, paddock_compiler;

-- Wake up the worker's Valkey cache sync (dk:, et:) when tokens, devices or keys change. The payload carries only
-- identifiers: <table>:<organization_id>:<id>; the trigger argument names the ID column.
-- +goose StatementBegin
CREATE FUNCTION device_cache_notify() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  PERFORM pg_notify('device_cache', TG_TABLE_NAME || ':' || NEW.organization_id::text || ':' ||
    (to_jsonb(NEW) ->> TG_ARGV[0]));
  RETURN NULL;
END $$;
-- +goose StatementEnd
CREATE TRIGGER device_cache_notify AFTER INSERT OR UPDATE ON enrollment_token
  FOR EACH ROW EXECUTE FUNCTION device_cache_notify('id');
CREATE TRIGGER device_cache_notify AFTER INSERT OR UPDATE ON device
  FOR EACH ROW EXECUTE FUNCTION device_cache_notify('id');
CREATE TRIGGER device_cache_notify AFTER INSERT OR UPDATE ON device_identity_key
  FOR EACH ROW EXECUTE FUNCTION device_cache_notify('device_id');

GRANT SELECT, INSERT, UPDATE ON enrollment_token TO paddock_api;
GRANT SELECT, UPDATE ON device TO paddock_api;
GRANT SELECT, UPDATE ON device_identity_key TO paddock_api;
GRANT SELECT, INSERT, DELETE ON device_group_member TO paddock_api;
GRANT SELECT ON device_status, bundle TO paddock_api;
GRANT SELECT, INSERT, UPDATE, DELETE ON managed_file, managed_unit TO paddock_api;

GRANT SELECT, UPDATE ON enrollment_token TO paddock_worker;
GRANT SELECT, INSERT, UPDATE ON device, device_status TO paddock_worker;
GRANT SELECT, INSERT ON device_identity_key, device_group_member, device_event_seen TO paddock_worker;
GRANT SELECT ON device_group TO paddock_worker;
GRANT INSERT, SELECT, UPDATE ON action TO paddock_worker;
GRANT INSERT ON outbox TO paddock_worker;

GRANT SELECT ON device, device_group, device_group_member, managed_file, managed_unit TO paddock_compiler;
GRANT UPDATE (bundle_seq) ON device TO paddock_compiler;
GRANT SELECT, INSERT ON bundle TO paddock_compiler;
GRANT INSERT, SELECT, UPDATE ON action TO paddock_compiler;
GRANT INSERT ON outbox TO paddock_compiler;

-- +goose Down
