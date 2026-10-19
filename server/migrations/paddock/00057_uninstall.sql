-- Uninstall (ADR 0037 decision 4, plan M8d decision 36, PDK-228): an organization administrator asks a device to
-- remove Paddock with the signed command uninstall; the device reports the removal and is retired by it
-- (retired_reason 'uninstalled'). The attention view (as of migration 00049) gains uninstall_pending while the request
-- is open. The api cancels an undelivered command (status, finished_at). Forward-only: there is no Down migration.
-- +goose Up
ALTER TABLE device
  ADD COLUMN uninstall_requested_at timestamptz,
  ADD COLUMN uninstall_mode text CHECK (uninstall_mode IN ('leave','reset')),
  ADD COLUMN uninstall_command_id uuid,
  ADD COLUMN uninstalled_at timestamptz,
  ADD COLUMN retired_reason text;
CREATE INDEX device_org_uninstall_idx ON device (organization_id)
  WHERE uninstall_requested_at IS NOT NULL AND uninstalled_at IS NULL;

GRANT UPDATE (status, finished_at) ON device_command TO paddock_api;
-- The worker retires a device by its removal report and revokes its identity keys as an administrator's retire does.
GRANT UPDATE (status) ON device_identity_key TO paddock_worker;

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
  CROSS JOIN (SELECT (SELECT paddock_version_key(paddock_current_agent_version())) COLLATE "C" AS version_key) r
  WHERE d.state = 'active' AND r.version_key IS NOT NULL AND s.agent_version IS NOT NULL
    AND coalesce(s.agent_version_key < r.version_key, true)
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
         OR (r.status = 'expired' AND coalesce(r.finished_at, r.requested_at) > now() - interval '30 days'))
  UNION ALL
  SELECT 'agent_rollback_pending', d.id, d.hostname, f.reported_at, f.version, 'agent_rollback_pending:' || d.id::text
  FROM agent_update_report f JOIN device d ON d.id = f.device_id JOIN device_status s ON s.device_id = d.id
  WHERE f.outcome = 'rollback_failed' AND d.state = 'active' AND s.agent_version = f.version
    AND NOT EXISTS (SELECT 1 FROM agent_update_report b
                    WHERE b.device_id = f.device_id AND b.version = f.version AND b.outcome = 'rolled_back')
  UNION ALL
  SELECT 'agent_not_running', d.id, d.hostname, r.alerted_at, '', 'agent_not_running:' || d.id::text
  FROM inventory_policy_result r JOIN device d ON d.id = r.device_id
  WHERE d.state = 'active' AND r.policy_key = 'paddock_agent_running' AND NOT r.passing AND r.alerted_at IS NOT NULL
  UNION ALL
  SELECT 'uninstall_pending', d.id, d.hostname, d.uninstall_requested_at, d.uninstall_mode || ':' || c.status,
    'uninstall_pending:' || d.id::text
  FROM device d JOIN device_command c ON c.id = d.uninstall_command_id
  WHERE d.state = 'active' AND d.uninstall_requested_at IS NOT NULL AND d.uninstalled_at IS NULL;

-- +goose Down
