-- Identity and privileges (plan M3a §3): organization domains, users and groups mirrored from Authentik, login
-- settings, login assignment and suspension, session reports, permission profiles and their assignments.
-- Forward-only: there is no Down migration.
-- +goose Up

-- Decision 1: domains of an organization, managed by platform admins; the first one is the primary domain. A domain
-- belongs to one organization only (enforced by the platform use case under an advisory lock).
ALTER TABLE organization ADD COLUMN domains text[] NOT NULL DEFAULT '{}';
CREATE INDEX organization_domains_idx ON organization USING gin (domains);
-- Worker (synchronization, Authentik reconcile) and compiler (login resource) read their own organization.
CREATE POLICY org_self_worker_compiler ON organization TO paddock_worker, paddock_compiler
  USING (id = current_setting('paddock.org_id')::uuid);

-- Decision 11: device-wide suspension of directory logins.
ALTER TABLE device ADD COLUMN logins_suspended boolean NOT NULL DEFAULT false;

-- Architecture §21: the schema versions the agent reported in its last materialized heartbeat ('{}' = none yet).
ALTER TABLE device_status ADD COLUMN schema_versions int[] NOT NULL DEFAULT '{}';

-- Decision 2: users of the organization. authentik_pk is '' while a local user is being provisioned.
CREATE TABLE app_user (
  id uuid PRIMARY KEY, organization_id uuid NOT NULL REFERENCES organization(id),
  authentik_pk text NOT NULL DEFAULT '',
  username text NOT NULL UNIQUE CHECK (username = lower(username) AND char_length(username) BETWEEN 3 AND 256),
  display_name text NOT NULL DEFAULT '' CHECK (char_length(display_name) <= 200),
  email text NOT NULL DEFAULT '' CHECK (char_length(email) <= 254),
  source text NOT NULL CHECK (source IN ('local','synced')),
  locked boolean NOT NULL DEFAULT false, locked_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (organization_id, id)
);
CREATE UNIQUE INDEX app_user_authentik_pk_idx ON app_user (authentik_pk) WHERE authentik_pk <> '';
CREATE INDEX app_user_org_username_idx ON app_user (organization_id, username);
CREATE INDEX app_user_org_display_name_idx ON app_user (organization_id, display_name);
CREATE INDEX app_user_org_created_idx ON app_user (organization_id, created_at);

-- Decision 3: local groups (paddock.<slug>.g.<group_slug>) and imported upstream groups (paddock.<slug>.s.<group_slug>).
CREATE TABLE user_group (
  id uuid PRIMARY KEY, organization_id uuid NOT NULL REFERENCES organization(id),
  slug text NOT NULL CHECK (slug ~ '^[a-z0-9][a-z0-9-]{0,40}[a-z0-9]$'),
  name text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 100),
  source text NOT NULL CHECK (source IN ('local','synced')),
  upstream_authentik_pk text, authentik_pk text NOT NULL DEFAULT '',
  created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (organization_id, slug), UNIQUE (organization_id, id),
  CHECK ((source = 'synced') = (upstream_authentik_pk IS NOT NULL))
);
CREATE INDEX user_group_org_name_idx ON user_group (organization_id, name);
CREATE INDEX user_group_org_created_idx ON user_group (organization_id, created_at);

CREATE TABLE user_group_member (
  organization_id uuid NOT NULL, group_id uuid NOT NULL, user_id uuid NOT NULL,
  PRIMARY KEY (group_id, user_id),
  FOREIGN KEY (organization_id, group_id) REFERENCES user_group (organization_id, id) ON DELETE CASCADE,
  FOREIGN KEY (organization_id, user_id) REFERENCES app_user (organization_id, id) ON DELETE CASCADE
);
CREATE INDEX user_group_member_user_idx ON user_group_member (user_id);

-- Decision 8 (+ 16: sudo_lecture_text): one row per organization, created with the defaults by a trigger.
CREATE TABLE organization_login_settings (
  organization_id uuid PRIMARY KEY REFERENCES organization(id),
  hello_enabled boolean NOT NULL DEFAULT true,
  hello_pin_min_length int NOT NULL DEFAULT 6 CHECK (hello_pin_min_length BETWEEN 6 AND 32),
  user_lock_session_action text NOT NULL DEFAULT 'lock_screen' CHECK (user_lock_session_action IN ('lock_screen','terminate')),
  break_glass_accounts text[] NOT NULL DEFAULT '{}',
  sudoers_d_allowlist text[] NOT NULL DEFAULT '{README}',
  sudo_lecture_text text NOT NULL DEFAULT 'This device is managed by your organization. Use administrative rights only for the tasks you are responsible for and as permitted by the acceptable-use policy. Your use of sudo is recorded.'
    CHECK (char_length(sudo_lecture_text) <= 2000),
  updated_at timestamptz NOT NULL DEFAULT now()
);
INSERT INTO organization_login_settings (organization_id) SELECT id FROM organization;
-- +goose StatementBegin
CREATE FUNCTION organization_login_settings_default() RETURNS trigger
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
  INSERT INTO organization_login_settings (organization_id) VALUES (NEW.id) ON CONFLICT DO NOTHING;
  RETURN NULL;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION organization_login_settings_default() FROM PUBLIC;
CREATE TRIGGER organization_login_settings_default AFTER INSERT ON organization
  FOR EACH ROW EXECUTE FUNCTION organization_login_settings_default();

-- Decision 9: login assignment of a device (subject_id is an app_user or a user_group of the organization; the use
-- cases delete the rows of a deleted subject in the same transaction).
CREATE TABLE device_login_assignment (
  organization_id uuid NOT NULL, device_id uuid NOT NULL,
  subject_type text NOT NULL CHECK (subject_type IN ('user','group')), subject_id uuid NOT NULL,
  PRIMARY KEY (device_id, subject_type, subject_id),
  FOREIGN KEY (organization_id, device_id) REFERENCES device (organization_id, id)
);
CREATE INDEX device_login_assignment_subject_idx ON device_login_assignment (subject_id);

-- Decision 10: users the agent saw log in (session.login events); no audit per login.
CREATE TABLE device_user_seen (
  organization_id uuid NOT NULL, device_id uuid NOT NULL, username text NOT NULL, last_seen_at timestamptz NOT NULL,
  PRIMARY KEY (device_id, username),
  FOREIGN KEY (organization_id, device_id) REFERENCES device (organization_id, id)
);
CREATE INDEX device_user_seen_username_idx ON device_user_seen (organization_id, username);

-- Decision 12: permission profiles and their assignments.
CREATE TABLE permission_profile (
  id uuid PRIMARY KEY, organization_id uuid NOT NULL REFERENCES organization(id),
  name text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 100),
  class text NOT NULL CHECK (class IN ('none','restricted','full')),
  commands text[] NOT NULL DEFAULT '{}',
  require_password boolean NOT NULL DEFAULT true,
  timestamp_timeout_min int NOT NULL DEFAULT 5 CHECK (timestamp_timeout_min BETWEEN 0 AND 60),
  lecture text NOT NULL DEFAULT 'once' CHECK (lecture IN ('always','once','never')),
  created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (organization_id, name), UNIQUE (organization_id, id),
  CHECK ((class = 'restricted') = (cardinality(commands) > 0))
);
CREATE INDEX permission_profile_org_created_idx ON permission_profile (organization_id, created_at);
CREATE INDEX permission_profile_org_updated_idx ON permission_profile (organization_id, updated_at);

-- A profile with assignments cannot be deleted (409 in_use); a deleted device group takes its scoped assignments.
CREATE TABLE profile_assignment (
  id uuid PRIMARY KEY, organization_id uuid NOT NULL REFERENCES organization(id),
  profile_id uuid NOT NULL,
  subject_type text NOT NULL CHECK (subject_type IN ('global','group','user')), subject_id uuid,
  device_group_id uuid,
  created_at timestamptz NOT NULL DEFAULT now(),
  CHECK ((subject_type = 'global') = (subject_id IS NULL)),
  UNIQUE NULLS NOT DISTINCT (profile_id, subject_type, subject_id, device_group_id),
  FOREIGN KEY (organization_id, profile_id) REFERENCES permission_profile (organization_id, id),
  FOREIGN KEY (organization_id, device_group_id) REFERENCES device_group (organization_id, id) ON DELETE CASCADE
);
CREATE INDEX profile_assignment_org_created_idx ON profile_assignment (organization_id, created_at);
CREATE INDEX profile_assignment_subject_idx ON profile_assignment (subject_id);

-- Row-level security: tenant policies for exactly the roles that use each table.
ALTER TABLE app_user ENABLE ROW LEVEL SECURITY;  ALTER TABLE app_user FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON app_user TO paddock_api, paddock_worker, paddock_compiler
  USING (organization_id = current_setting('paddock.org_id')::uuid)
  WITH CHECK (organization_id = current_setting('paddock.org_id')::uuid);
ALTER TABLE user_group ENABLE ROW LEVEL SECURITY;  ALTER TABLE user_group FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON user_group TO paddock_api, paddock_worker, paddock_compiler
  USING (organization_id = current_setting('paddock.org_id')::uuid)
  WITH CHECK (organization_id = current_setting('paddock.org_id')::uuid);
ALTER TABLE user_group_member ENABLE ROW LEVEL SECURITY;  ALTER TABLE user_group_member FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON user_group_member TO paddock_api, paddock_worker, paddock_compiler
  USING (organization_id = current_setting('paddock.org_id')::uuid)
  WITH CHECK (organization_id = current_setting('paddock.org_id')::uuid);
ALTER TABLE organization_login_settings ENABLE ROW LEVEL SECURITY;  ALTER TABLE organization_login_settings FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON organization_login_settings TO paddock_api, paddock_worker, paddock_compiler
  USING (organization_id = current_setting('paddock.org_id')::uuid)
  WITH CHECK (organization_id = current_setting('paddock.org_id')::uuid);
ALTER TABLE device_login_assignment ENABLE ROW LEVEL SECURITY;  ALTER TABLE device_login_assignment FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON device_login_assignment TO paddock_api, paddock_worker, paddock_compiler
  USING (organization_id = current_setting('paddock.org_id')::uuid)
  WITH CHECK (organization_id = current_setting('paddock.org_id')::uuid);
ALTER TABLE device_user_seen ENABLE ROW LEVEL SECURITY;  ALTER TABLE device_user_seen FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON device_user_seen TO paddock_api, paddock_worker, paddock_compiler
  USING (organization_id = current_setting('paddock.org_id')::uuid)
  WITH CHECK (organization_id = current_setting('paddock.org_id')::uuid);
ALTER TABLE permission_profile ENABLE ROW LEVEL SECURITY;  ALTER TABLE permission_profile FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON permission_profile TO paddock_api, paddock_worker, paddock_compiler
  USING (organization_id = current_setting('paddock.org_id')::uuid)
  WITH CHECK (organization_id = current_setting('paddock.org_id')::uuid);
ALTER TABLE profile_assignment ENABLE ROW LEVEL SECURITY;  ALTER TABLE profile_assignment FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON profile_assignment TO paddock_api, paddock_worker, paddock_compiler
  USING (organization_id = current_setting('paddock.org_id')::uuid)
  WITH CHECK (organization_id = current_setting('paddock.org_id')::uuid);
-- Existing tables used by roles that did not use them before.
CREATE POLICY tenant_compiler ON device_status TO paddock_compiler
  USING (organization_id = current_setting('paddock.org_id')::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON app_user, user_group, user_group_member, device_login_assignment,
  permission_profile, profile_assignment TO paddock_api;
GRANT SELECT, UPDATE ON organization_login_settings TO paddock_api;
GRANT SELECT ON device_user_seen TO paddock_api;

GRANT SELECT ON organization TO paddock_worker, paddock_compiler;
GRANT SELECT, INSERT, UPDATE, DELETE ON app_user, user_group_member, device_login_assignment TO paddock_worker;
GRANT SELECT, UPDATE ON user_group TO paddock_worker;
GRANT SELECT, INSERT, UPDATE ON device_user_seen TO paddock_worker;
GRANT SELECT ON organization_login_settings, permission_profile, profile_assignment TO paddock_worker;
GRANT DELETE ON profile_assignment TO paddock_worker;

GRANT SELECT ON app_user, user_group, user_group_member, organization_login_settings, device_login_assignment,
  device_user_seen, permission_profile, profile_assignment, device_status TO paddock_compiler;

-- +goose Down
