-- Paddock control-plane schema (plan M0 §6.1). Forward-only: there is no Down migration.
-- +goose Up
CREATE TABLE organization (
  id          uuid PRIMARY KEY,
  slug        text NOT NULL UNIQUE CHECK (slug ~ '^[a-z0-9][a-z0-9-]{1,30}[a-z0-9]$' AND slug <> 'platform'),
  name        text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 200),
  status      text NOT NULL CHECK (status IN ('provisioning','active','provisioning_failed','suspended')),
  created_at  timestamptz NOT NULL DEFAULT now(),
  updated_at  timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE organization ENABLE ROW LEVEL SECURITY;
ALTER TABLE organization FORCE ROW LEVEL SECURITY;
CREATE POLICY org_self ON organization TO paddock_api
  USING (id = current_setting('paddock.org_id')::uuid);
CREATE POLICY org_platform ON organization TO paddock_platform USING (true) WITH CHECK (true);

CREATE TABLE platform_admin (
  id            uuid PRIMARY KEY,
  authentik_sub text NOT NULL UNIQUE,
  username      text NOT NULL,
  display_name  text NOT NULL,
  locale        text NOT NULL DEFAULT 'en',
  last_login_at timestamptz
);
-- platform_admin is not organization-scoped; listed in the RLS lint allow list.

CREATE TABLE admin_account (
  id              uuid PRIMARY KEY,
  organization_id uuid NOT NULL REFERENCES organization(id),
  authentik_sub   text NOT NULL UNIQUE,
  username        text NOT NULL,
  display_name    text NOT NULL,
  role            text NOT NULL CHECK (role IN ('org_admin','org_operator','org_auditor')),
  locale          text NOT NULL DEFAULT 'en',
  last_login_at   timestamptz
);

CREATE TABLE device_group (
  id              uuid PRIMARY KEY,
  organization_id uuid NOT NULL REFERENCES organization(id),
  name            text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 100),
  description     text NOT NULL DEFAULT '' CHECK (char_length(description) <= 1000),
  created_at      timestamptz NOT NULL DEFAULT now(),
  updated_at      timestamptz NOT NULL DEFAULT now(),
  UNIQUE (organization_id, name)
);

-- organization_id = '00000000-0000-0000-0000-000000000000' is the platform pseudo-organization (audit only).
CREATE TABLE action (
  id              uuid PRIMARY KEY,           -- equals the audit event_id
  organization_id uuid NOT NULL,              -- no FK: may be the platform pseudo-organization
  code            text NOT NULL,
  status          text NOT NULL CHECK (status IN ('started','finished')),
  outcome         text CHECK (outcome IN ('success','failure','denied','unknown')),
  actor           jsonb NOT NULL,
  target          jsonb,
  params          jsonb NOT NULL DEFAULT '{}',
  error_code      text,
  correlation_id  text NOT NULL,
  started_at      timestamptz NOT NULL,
  finished_at     timestamptz,
  CHECK ((status = 'started' AND outcome IS NULL) OR (status = 'finished' AND outcome IS NOT NULL))
);
CREATE INDEX action_started_idx ON action (started_at) WHERE status = 'started';

CREATE TABLE outbox (
  id              bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  organization_id uuid NOT NULL,
  subject         text NOT NULL,
  msg_id          text NOT NULL UNIQUE,
  payload         jsonb NOT NULL,
  created_at      timestamptz NOT NULL DEFAULT now(),
  published_at    timestamptz
);
CREATE INDEX outbox_unpublished_idx ON outbox (id) WHERE published_at IS NULL;

-- RLS for organization-scoped tables (same pattern for admin_account, device_group, action, outbox)
ALTER TABLE admin_account ENABLE ROW LEVEL SECURITY;  ALTER TABLE admin_account FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON admin_account TO paddock_api
  USING (organization_id = current_setting('paddock.org_id')::uuid)
  WITH CHECK (organization_id = current_setting('paddock.org_id')::uuid);
ALTER TABLE device_group ENABLE ROW LEVEL SECURITY;  ALTER TABLE device_group FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON device_group TO paddock_api
  USING (organization_id = current_setting('paddock.org_id')::uuid)
  WITH CHECK (organization_id = current_setting('paddock.org_id')::uuid);
ALTER TABLE action ENABLE ROW LEVEL SECURITY;  ALTER TABLE action FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON action TO paddock_api
  USING (organization_id = current_setting('paddock.org_id')::uuid)
  WITH CHECK (organization_id = current_setting('paddock.org_id')::uuid);
CREATE POLICY platform ON action TO paddock_platform USING (true) WITH CHECK (true);
CREATE POLICY relay ON action TO paddock_relay USING (true) WITH CHECK (true);
ALTER TABLE outbox ENABLE ROW LEVEL SECURITY;  ALTER TABLE outbox FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON outbox TO paddock_api
  USING (organization_id = current_setting('paddock.org_id')::uuid)
  WITH CHECK (organization_id = current_setting('paddock.org_id')::uuid);
CREATE POLICY platform ON outbox TO paddock_platform USING (true) WITH CHECK (true);
CREATE POLICY relay ON outbox TO paddock_relay USING (true) WITH CHECK (true);

-- Login: map slug to id before an organization context exists.
CREATE FUNCTION paddock_org_id_by_slug(p_slug text) RETURNS uuid
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS
  $$ SELECT id FROM organization WHERE slug = p_slug AND status = 'active' $$;
REVOKE ALL ON FUNCTION paddock_org_id_by_slug(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION paddock_org_id_by_slug(text) TO paddock_api;

-- Wake up the relay.
CREATE FUNCTION outbox_notify() RETURNS trigger LANGUAGE plpgsql AS
  $$ BEGIN PERFORM pg_notify('outbox', ''); RETURN NULL; END $$;
CREATE TRIGGER outbox_notify AFTER INSERT ON outbox FOR EACH STATEMENT EXECUTE FUNCTION outbox_notify();

-- Grants (plan M0 §6.1 role table).
GRANT SELECT, INSERT, UPDATE, DELETE ON admin_account, device_group TO paddock_api;
GRANT SELECT ON organization TO paddock_api;
GRANT INSERT, SELECT, UPDATE ON action TO paddock_api;
GRANT INSERT ON outbox TO paddock_api;

GRANT SELECT, INSERT, UPDATE ON organization, platform_admin TO paddock_platform;
GRANT INSERT, SELECT, UPDATE ON action TO paddock_platform;
GRANT INSERT ON outbox TO paddock_platform;

GRANT SELECT, UPDATE, DELETE, INSERT ON outbox TO paddock_relay;
GRANT SELECT, UPDATE ON action TO paddock_relay;

-- +goose Down
