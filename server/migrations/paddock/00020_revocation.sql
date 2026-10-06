-- Revocation: Lock, Destroy and the self-lock tokens of the dead man's switch (plan M4c decisions 5, 7–10, 15, 17).
-- Forward-only: there is no Down migration.
-- The api records requests and approvals (with the raw step-up ID token, never returned by any API); the
-- revocation-issuer (database role paddock_revocation, created with the cluster: deploy/compose/postgres/init/
-- 10-roles.sh; existing installations follow docs/operations/revocation.md) verifies them, enforces the limits of
-- ADR 0014, signs and issues, deletes the escrow of a Destroy and clears step-up tokens 30 days after a request
-- reached a final state; the worker records delivery, confirmation and expiry.
-- +goose Up

CREATE TABLE revocation_request (
  id uuid PRIMARY KEY,
  organization_id uuid NOT NULL, device_id uuid NOT NULL REFERENCES device(id),
  action text NOT NULL CHECK (action IN ('lock','destroy','self_lock')),
  status text NOT NULL CHECK (status IN ('requested','approved','issued','delivered','confirmed','failed','rejected',
                                         'cancelled','expired')),
  requested_by uuid,                      -- admin_account.id; NULL for self_lock (the issuer creates those)
  requested_at timestamptz NOT NULL DEFAULT now(),
  reason text NOT NULL DEFAULT '' CHECK (char_length(reason) <= 500),
  approved_at timestamptz,
  -- Issuance: the token's command_id equals id; expires_at is the token's (+30 d for Lock and Destroy).
  issued_at timestamptz, expires_at timestamptz, envelope bytea CHECK (octet_length(envelope) <= 8192),
  period_days int CHECK (period_days >= 1),  -- self_lock only
  delivered_at timestamptz, confirmed_at timestamptz,
  finished_at timestamptz,                -- when a final state was reached
  rejection text,                         -- why the issuer rejected or failed it, e.g. limit_admin_hour
  result jsonb,                           -- the device's confirmation {erased, slots_before, slots_after}
  CHECK ((action = 'self_lock') = (period_days IS NOT NULL)),
  CHECK ((action = 'self_lock') = (requested_by IS NULL)),
  FOREIGN KEY (organization_id, device_id) REFERENCES device (organization_id, id)
);
CREATE INDEX revocation_request_org_requested_idx ON revocation_request (organization_id, requested_at);
CREATE INDEX revocation_request_org_device_idx ON revocation_request (organization_id, device_id, requested_at);
CREATE INDEX revocation_request_issued_idx ON revocation_request (organization_id, requested_by, issued_at)
  WHERE issued_at IS NOT NULL;
-- At most one open request per device and action.
CREATE UNIQUE INDEX revocation_request_open_idx ON revocation_request (device_id, action)
  WHERE status IN ('requested','approved','issued','delivered');

CREATE TABLE revocation_approval (
  request_id uuid NOT NULL REFERENCES revocation_request(id),
  organization_id uuid NOT NULL,
  role text NOT NULL CHECK (role IN ('requester','approver')),
  admin_id uuid NOT NULL,                 -- admin_account.id
  subject text NOT NULL,                  -- the step-up token's sub (Authentik subject of the administrator)
  stepup_jti text NOT NULL UNIQUE,        -- one step-up token per approval
  stepup_id_token text,                   -- raw step-up ID token; NULL once deleted (30 d after a final state)
  approved_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (request_id, role)
);

-- A frozen administrator cannot have revocations issued until frozen_until (ADR 0014).
CREATE TABLE revocation_freeze (
  organization_id uuid NOT NULL, admin_id uuid NOT NULL,
  request_id uuid NOT NULL REFERENCES revocation_request(id),
  frozen_at timestamptz NOT NULL DEFAULT now(), frozen_until timestamptz NOT NULL,
  PRIMARY KEY (admin_id, frozen_at)
);
CREATE INDEX revocation_freeze_until_idx ON revocation_freeze (organization_id, admin_id, frozen_until);

ALTER TABLE revocation_request ENABLE ROW LEVEL SECURITY;  ALTER TABLE revocation_request FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON revocation_request TO paddock_api, paddock_worker, paddock_revocation
  USING (organization_id = current_setting('paddock.org_id')::uuid)
  WITH CHECK (organization_id = current_setting('paddock.org_id')::uuid);
ALTER TABLE revocation_approval ENABLE ROW LEVEL SECURITY;  ALTER TABLE revocation_approval FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON revocation_approval TO paddock_api, paddock_revocation
  USING (organization_id = current_setting('paddock.org_id')::uuid)
  WITH CHECK (organization_id = current_setting('paddock.org_id')::uuid);
ALTER TABLE revocation_freeze ENABLE ROW LEVEL SECURITY;  ALTER TABLE revocation_freeze FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON revocation_freeze TO paddock_api, paddock_revocation
  USING (organization_id = current_setting('paddock.org_id')::uuid)
  WITH CHECK (organization_id = current_setting('paddock.org_id')::uuid);

GRANT SELECT, INSERT, UPDATE ON revocation_request TO paddock_api;
GRANT SELECT, INSERT ON revocation_approval TO paddock_api;
GRANT SELECT ON revocation_freeze TO paddock_api;
GRANT SELECT, UPDATE ON revocation_request TO paddock_worker;

-- The revocation-issuer: revocation tables, devices and administrators (read), escrow (delete for Destroy), and its
-- own audit events through the action runner.
GRANT SELECT, INSERT, UPDATE ON revocation_request TO paddock_revocation;
GRANT SELECT, UPDATE ON revocation_approval TO paddock_revocation;
GRANT SELECT, INSERT ON revocation_freeze TO paddock_revocation;
CREATE POLICY revocation ON device FOR SELECT TO paddock_revocation
  USING (organization_id = current_setting('paddock.org_id')::uuid);
CREATE POLICY revocation ON admin_account FOR SELECT TO paddock_revocation
  USING (organization_id = current_setting('paddock.org_id')::uuid);
CREATE POLICY revocation ON escrow_secret FOR SELECT TO paddock_revocation
  USING (organization_id = current_setting('paddock.org_id')::uuid);
CREATE POLICY revocation_delete ON escrow_secret FOR DELETE TO paddock_revocation
  USING (organization_id = current_setting('paddock.org_id')::uuid);
CREATE POLICY revocation ON action TO paddock_revocation
  USING (organization_id = current_setting('paddock.org_id')::uuid)
  WITH CHECK (organization_id = current_setting('paddock.org_id')::uuid);
CREATE POLICY revocation ON outbox TO paddock_revocation
  USING (organization_id = current_setting('paddock.org_id')::uuid)
  WITH CHECK (organization_id = current_setting('paddock.org_id')::uuid);
GRANT SELECT ON device, admin_account TO paddock_revocation;
GRANT SELECT, DELETE ON escrow_secret TO paddock_revocation;
GRANT INSERT, SELECT, UPDATE ON action TO paddock_revocation;
GRANT INSERT ON outbox TO paddock_revocation;
GRANT EXECUTE ON FUNCTION paddock_organization_ids() TO paddock_revocation;

-- +goose Down
