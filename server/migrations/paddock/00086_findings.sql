-- Findings (plan M9 decisions 30–33, ADR 0031 decision 15, PDK-126): tamper events and attention conditions become
-- rows with a status, an assignee and a reason, so the reaction to a security event is recorded (AUD-06). Tamper
-- findings are written by the worker in the transaction of their audit event; attention findings by the worker's
-- findings round, which reads the attention view. The api changes the status (every change is an audit event).
-- At most one live finding per key: a tamper finding until it is closed, an attention finding until its condition
-- is gone. Forward-only: there is no Down migration.
-- +goose Up
CREATE TABLE finding (
  id uuid PRIMARY KEY,
  organization_id uuid NOT NULL REFERENCES organization(id),
  kind text NOT NULL CHECK (kind IN ('tamper', 'attention')),
  key text NOT NULL,
  device_id uuid NOT NULL REFERENCES device(id),
  code text NOT NULL,
  subject text NOT NULL DEFAULT '',
  status text NOT NULL CHECK (status IN ('open', 'acknowledged', 'in_progress', 'resolved', 'accepted_risk', 'false_positive')),
  assignee_account_id uuid REFERENCES admin_account(id),
  opened_at timestamptz NOT NULL,
  last_seen_at timestamptz NOT NULL,
  occurrences int NOT NULL DEFAULT 1,
  first_event_id uuid,
  last_event_id uuid,
  acknowledged_at timestamptz,
  closed_at timestamptz,
  closed_by text,
  reason text,
  external_ref text,
  cleared_at timestamptz,
  updated_at timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (organization_id, device_id) REFERENCES device (organization_id, id)
);
CREATE UNIQUE INDEX finding_live_tamper_idx ON finding (organization_id, key) WHERE kind = 'tamper' AND closed_at IS NULL;
CREATE UNIQUE INDEX finding_live_attention_idx ON finding (organization_id, key) WHERE kind = 'attention' AND cleared_at IS NULL;
CREATE INDEX finding_org_seen_idx ON finding (organization_id, last_seen_at DESC);
CREATE INDEX finding_org_device_idx ON finding (organization_id, device_id);

ALTER TABLE finding ENABLE ROW LEVEL SECURITY;
ALTER TABLE finding FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON finding TO paddock_api, paddock_worker
  USING (organization_id = current_setting('paddock.org_id')::uuid)
  WITH CHECK (organization_id = current_setting('paddock.org_id')::uuid);
GRANT SELECT, UPDATE ON finding TO paddock_api;
GRANT SELECT, INSERT, UPDATE ON finding TO paddock_worker;

-- The findings round reads the attention view with the worker's role (security_invoker: the view's tables are read
-- with the worker's grants and policies). Of those, the worker could not read the bundle metadata (config_behind: the
-- newest bundle's version and time, no content) and the current agent release (agent_outdated); it gets exactly the
-- columns and the function the view uses.
GRANT SELECT ON attention_condition TO paddock_worker;
GRANT SELECT (device_id, organization_id, version, created_at) ON bundle TO paddock_worker;
ALTER POLICY tenant ON bundle TO paddock_api, paddock_compiler, paddock_worker;
GRANT EXECUTE ON FUNCTION paddock_current_agent_version() TO paddock_worker;
