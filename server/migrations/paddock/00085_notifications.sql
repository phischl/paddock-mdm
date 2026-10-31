-- Notifications (plan M9 §6.2, decisions 10, 11 and 13; ADR 0031 decisions 10 and 11). Forward-only: there is no
-- Down migration. Organization destinations and their state are organization data; platform destinations use the
-- same tables with the nil organization (audit.PlatformOrganizationID) under the policy platform of paddock_platform
-- alone. The notifier (role paddock_notifier) reads destinations and writes delivery state of every organization, the
-- nil one included, under its organization context; paddock_platform only manages platform destinations. Webhook URL,
-- signing secret and pseudonym keys are stored only as Transit ciphertext of the derived key notification-wrap under
-- the organization as context, which the api creates and the notifier alone decrypts. Children reference their
-- destination and delivery together with the organization, so no row can point into another organization.
-- +goose Up

CREATE TABLE notification_destination (
  id uuid PRIMARY KEY,
  organization_id uuid NOT NULL,            -- the nil uuid is the platform scope; no FK (like action)
  type text NOT NULL CHECK (type IN ('webhook','email')),
  name text NOT NULL,
  enabled boolean NOT NULL DEFAULT true,
  filter_mode text NOT NULL CHECK (filter_mode IN ('security','all','custom')),
  codes text[] NOT NULL DEFAULT '{}',
  pseudonymize_users boolean NOT NULL DEFAULT false,
  include_params boolean NOT NULL DEFAULT false,
  url_ciphertext text,                      -- webhook; the URL is a secret (it may carry the credential)
  url_display text,                         -- webhook; scheme, host and masked path (outbound.DisplayURL)
  secret_ciphertext text,                   -- webhook; HMAC signing secret
  heartbeat_interval_s int NOT NULL DEFAULT 0
    CHECK (heartbeat_interval_s = 0 OR heartbeat_interval_s BETWEEN 60 AND 3600),
  recipients text[] NOT NULL DEFAULT '{}',  -- email
  email_min_interval_s int NOT NULL DEFAULT 300 CHECK (email_min_interval_s BETWEEN 60 AND 3600),
  created_by text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (organization_id, name),
  UNIQUE (id, organization_id)
);

-- Keys that a caller names (the destination of a state row or a forwarded event) include the organization, so a row of
-- another organization never collides with a new one and an ID of another organization fails like an unknown one.
CREATE TABLE notification_destination_state (
  destination_id uuid NOT NULL,
  organization_id uuid NOT NULL,
  cursor_commit_seq bigint NOT NULL DEFAULT 0,
  forward_seq bigint NOT NULL DEFAULT 0,
  status text NOT NULL DEFAULT 'active' CHECK (status IN ('active','stalled')),
  pending_delivery_id uuid,
  consecutive_failures int NOT NULL DEFAULT 0,
  first_failure_at timestamptz, stalled_since timestamptz, last_success_at timestamptz,
  last_attempt_at timestamptz, next_attempt_at timestamptz, last_heartbeat_at timestamptz,
  last_error text,
  last_test_at timestamptz, last_test_ok boolean, last_test_error text,
  PRIMARY KEY (destination_id, organization_id),
  FOREIGN KEY (destination_id, organization_id) REFERENCES notification_destination (id, organization_id)
    ON DELETE CASCADE
);

CREATE TABLE notification_delivery (
  id uuid PRIMARY KEY,
  destination_id uuid NOT NULL,
  organization_id uuid NOT NULL,
  kind text NOT NULL CHECK (kind IN ('events','heartbeat','test')),
  forward_from bigint, forward_to bigint,
  event_count int NOT NULL DEFAULT 0,
  created_at timestamptz NOT NULL DEFAULT now(),
  delivered_at timestamptz,
  attempts int NOT NULL DEFAULT 0,
  last_error text,
  requested_by text,                        -- kind test: the administrator's display
  UNIQUE (id, organization_id),
  FOREIGN KEY (destination_id, organization_id) REFERENCES notification_destination (id, organization_id)
    ON DELETE CASCADE
);
CREATE INDEX notification_delivery_destination_idx ON notification_delivery (destination_id, created_at DESC);

CREATE TABLE notification_delivery_event (
  destination_id uuid NOT NULL,
  organization_id uuid NOT NULL,
  forward_seq bigint NOT NULL,
  event_id uuid NOT NULL,
  commit_seq bigint NOT NULL,
  delivery_id uuid NOT NULL,
  PRIMARY KEY (destination_id, organization_id, forward_seq),
  FOREIGN KEY (destination_id, organization_id) REFERENCES notification_destination (id, organization_id)
    ON DELETE CASCADE,
  FOREIGN KEY (delivery_id, organization_id) REFERENCES notification_delivery (id, organization_id) ON DELETE CASCADE
);
CREATE INDEX notification_delivery_event_delivery_idx ON notification_delivery_event (delivery_id);

CREATE TABLE notification_pseudonym_key (
  organization_id uuid PRIMARY KEY,
  key_ciphertext text NOT NULL,             -- Transit datakey/wrapped, context = organization_id
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE notification_pseudonym_lookup (
  id uuid PRIMARY KEY,
  organization_id uuid NOT NULL,
  pseudonym text NOT NULL,
  requested_by text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  resolved_username text,
  resolved_at timestamptz
);
CREATE INDEX notification_pseudonym_lookup_created_idx ON notification_pseudonym_lookup (created_at);

ALTER TABLE notification_destination ENABLE ROW LEVEL SECURITY;
ALTER TABLE notification_destination FORCE ROW LEVEL SECURITY;
ALTER TABLE notification_destination_state ENABLE ROW LEVEL SECURITY;
ALTER TABLE notification_destination_state FORCE ROW LEVEL SECURITY;
ALTER TABLE notification_delivery ENABLE ROW LEVEL SECURITY;
ALTER TABLE notification_delivery FORCE ROW LEVEL SECURITY;
ALTER TABLE notification_delivery_event ENABLE ROW LEVEL SECURITY;
ALTER TABLE notification_delivery_event FORCE ROW LEVEL SECURITY;
ALTER TABLE notification_pseudonym_key ENABLE ROW LEVEL SECURITY;
ALTER TABLE notification_pseudonym_key FORCE ROW LEVEL SECURITY;
ALTER TABLE notification_pseudonym_lookup ENABLE ROW LEVEL SECURITY;
ALTER TABLE notification_pseudonym_lookup FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant ON notification_destination TO paddock_api, paddock_notifier
  USING (organization_id = current_setting('paddock.org_id')::uuid)
  WITH CHECK (organization_id = current_setting('paddock.org_id')::uuid);
CREATE POLICY tenant ON notification_destination_state TO paddock_api, paddock_notifier
  USING (organization_id = current_setting('paddock.org_id')::uuid)
  WITH CHECK (organization_id = current_setting('paddock.org_id')::uuid);
-- The api lists deliveries and inserts only fresh test deliveries (plan M9 §6.2): every result column at its default,
-- so it cannot forge a delivered or failed attempt. The notifier writes everything else.
CREATE POLICY tenant ON notification_delivery FOR SELECT TO paddock_api
  USING (organization_id = current_setting('paddock.org_id')::uuid);
CREATE POLICY tenant_test ON notification_delivery FOR INSERT TO paddock_api
  WITH CHECK (organization_id = current_setting('paddock.org_id')::uuid AND kind = 'test' AND delivered_at IS NULL
    AND attempts = 0 AND forward_from IS NULL AND forward_to IS NULL AND event_count = 0 AND last_error IS NULL);
CREATE POLICY notifier ON notification_delivery TO paddock_notifier
  USING (organization_id = current_setting('paddock.org_id')::uuid)
  WITH CHECK (organization_id = current_setting('paddock.org_id')::uuid);
CREATE POLICY tenant ON notification_delivery_event TO paddock_notifier
  USING (organization_id = current_setting('paddock.org_id')::uuid)
  WITH CHECK (organization_id = current_setting('paddock.org_id')::uuid);
CREATE POLICY tenant ON notification_pseudonym_key TO paddock_api, paddock_notifier
  USING (organization_id = current_setting('paddock.org_id')::uuid)
  WITH CHECK (organization_id = current_setting('paddock.org_id')::uuid);
-- The api requests a lookup and reads or deletes it; only the notifier resolves it (plan M9 decision 18).
CREATE POLICY tenant ON notification_pseudonym_lookup FOR SELECT TO paddock_api
  USING (organization_id = current_setting('paddock.org_id')::uuid);
CREATE POLICY tenant_request ON notification_pseudonym_lookup FOR INSERT TO paddock_api
  WITH CHECK (organization_id = current_setting('paddock.org_id')::uuid AND resolved_username IS NULL
    AND resolved_at IS NULL);
CREATE POLICY tenant_delete ON notification_pseudonym_lookup FOR DELETE TO paddock_api
  USING (organization_id = current_setting('paddock.org_id')::uuid);
CREATE POLICY notifier ON notification_pseudonym_lookup TO paddock_notifier
  USING (organization_id = current_setting('paddock.org_id')::uuid)
  WITH CHECK (organization_id = current_setting('paddock.org_id')::uuid);

CREATE POLICY platform ON notification_destination TO paddock_platform
  USING (organization_id = '00000000-0000-0000-0000-000000000000'::uuid)
  WITH CHECK (organization_id = '00000000-0000-0000-0000-000000000000'::uuid);
CREATE POLICY platform ON notification_destination_state TO paddock_platform
  USING (organization_id = '00000000-0000-0000-0000-000000000000'::uuid)
  WITH CHECK (organization_id = '00000000-0000-0000-0000-000000000000'::uuid);
CREATE POLICY platform ON notification_delivery FOR SELECT TO paddock_platform
  USING (organization_id = '00000000-0000-0000-0000-000000000000'::uuid);
CREATE POLICY platform_test ON notification_delivery FOR INSERT TO paddock_platform
  WITH CHECK (organization_id = '00000000-0000-0000-0000-000000000000'::uuid AND kind = 'test'
    AND delivered_at IS NULL AND attempts = 0 AND forward_from IS NULL AND forward_to IS NULL AND event_count = 0
    AND last_error IS NULL);

-- State: the api creates the row with the cursor at the scope's latest commit sequence (a new destination never
-- replays history, plan M9 decision 15) and moves only that cursor when an administrator enables a destination with
-- cursor "skip" (decision 16). Every result column (status, failures, attempts, test result, forward_seq,
-- pending_delivery_id) is the notifier's alone; without DELETE the api cannot reset forward_seq by re-creating the row.
GRANT SELECT, INSERT, UPDATE, DELETE ON notification_destination TO paddock_api;
GRANT SELECT, INSERT (destination_id, organization_id, cursor_commit_seq), UPDATE (cursor_commit_seq)
  ON notification_destination_state TO paddock_api;
GRANT SELECT, INSERT ON notification_delivery, notification_pseudonym_key TO paddock_api;
GRANT SELECT, INSERT, DELETE ON notification_pseudonym_lookup TO paddock_api;

-- paddock_platform is the platform administrators' api only: platform destinations, their state and test deliveries.
-- Platform destinations have no pseudonym operations (plan M9 decision 18).
GRANT SELECT, INSERT, UPDATE, DELETE ON notification_destination TO paddock_platform;
GRANT SELECT, INSERT (destination_id, organization_id, cursor_commit_seq), UPDATE (cursor_commit_seq)
  ON notification_destination_state TO paddock_platform;
GRANT SELECT, INSERT ON notification_delivery TO paddock_platform;

GRANT SELECT ON notification_destination, notification_pseudonym_key TO paddock_notifier;
GRANT SELECT, INSERT, UPDATE ON notification_destination_state, notification_delivery, notification_delivery_event
  TO paddock_notifier;
GRANT SELECT, UPDATE, DELETE ON notification_pseudonym_lookup TO paddock_notifier;

-- The notifier's reads around a message (slug, device and account names, pseudonym resolution) and its audit events
-- through ActionRunner, mirroring paddock_worker (00003, 00007, 00046).
CREATE POLICY notifier ON organization FOR SELECT TO paddock_notifier
  USING (id = current_setting('paddock.org_id')::uuid);
CREATE POLICY notifier ON device FOR SELECT TO paddock_notifier
  USING (organization_id = current_setting('paddock.org_id')::uuid);
CREATE POLICY notifier ON admin_account FOR SELECT TO paddock_notifier
  USING (organization_id = current_setting('paddock.org_id')::uuid);
CREATE POLICY notifier ON app_user FOR SELECT TO paddock_notifier
  USING (organization_id = current_setting('paddock.org_id')::uuid);
CREATE POLICY notifier ON action TO paddock_notifier
  USING (organization_id = current_setting('paddock.org_id')::uuid)
  WITH CHECK (organization_id = current_setting('paddock.org_id')::uuid);
CREATE POLICY notifier ON outbox TO paddock_notifier
  USING (organization_id = current_setting('paddock.org_id')::uuid)
  WITH CHECK (organization_id = current_setting('paddock.org_id')::uuid);
GRANT SELECT ON organization, device, admin_account, app_user TO paddock_notifier;
GRANT INSERT, SELECT, UPDATE ON action TO paddock_notifier;
GRANT INSERT ON outbox TO paddock_notifier;
-- The notifier's round iterates organizations before an organization context exists (plan M9 amendment B5.3).
GRANT EXECUTE ON FUNCTION paddock_organization_ids() TO paddock_notifier;

-- +goose Down
