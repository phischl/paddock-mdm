-- In-place encryption (ADR 0039, plan M8e decision 6, PDK-241): one row per conversion of a device's root volume, from
-- the administrator's request (the signed command encrypt_disk) to completed, failed or cancelled; the device's phase
-- events move it (decision 9). At most one conversion of a device is open (requested, prepared or encrypting). The api
-- inserts and updates rows (request, cancel, Retire and Lock/Destroy withdrawals); the worker updates them from the
-- device's events and command results. The attention view gains disk_conversion_failed for the latest conversion of
-- an active device when it failed; columns, grants and every other branch stay as in 00064. Forward-only: there is no
-- Down migration.
-- +goose Up
CREATE TABLE device_disk_conversion (
  id uuid PRIMARY KEY, organization_id uuid NOT NULL, device_id uuid NOT NULL,
  command_id uuid NOT NULL REFERENCES device_command (id),
  requested_at timestamptz NOT NULL DEFAULT now(), requested_by uuid, reason text NOT NULL,
  phase text NOT NULL CHECK (phase IN ('requested','prepared','encrypting','completed','failed','cancelled')),
  layout text CHECK (layout IN ('lvm','plain')), luks_uuid uuid, data_bytes bigint,
  failure_stage text, failure_reason text, phase_at timestamptz NOT NULL DEFAULT now(), finished_at timestamptz,
  abort_command_id uuid REFERENCES device_command (id), abort_refused_reason text,
  FOREIGN KEY (organization_id, device_id) REFERENCES device (organization_id, id)
);
CREATE INDEX device_disk_conversion_device_idx ON device_disk_conversion (organization_id, device_id, requested_at DESC);
CREATE UNIQUE INDEX device_disk_conversion_open_idx ON device_disk_conversion (device_id)
  WHERE phase IN ('requested','prepared','encrypting');

ALTER TABLE device_disk_conversion ENABLE ROW LEVEL SECURITY;
ALTER TABLE device_disk_conversion FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON device_disk_conversion TO paddock_api, paddock_worker
  USING (organization_id = current_setting('paddock.org_id')::uuid)
  WITH CHECK (organization_id = current_setting('paddock.org_id')::uuid);
GRANT SELECT, INSERT, UPDATE ON device_disk_conversion TO paddock_api;
GRANT SELECT, UPDATE ON device_disk_conversion TO paddock_worker;

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
  WHERE d.state = 'active' AND d.uninstall_requested_at IS NOT NULL AND d.uninstalled_at IS NULL
  UNION ALL
  SELECT 'config_behind', d.id, d.hostname, b.created_at,
    coalesce(s.applied_bundle_version, 0)::text || ' < ' || b.version::text, 'config_behind:' || d.id::text
  FROM device d JOIN device_status s ON s.device_id = d.id
  JOIN LATERAL (SELECT version, created_at FROM bundle WHERE bundle.device_id = d.id ORDER BY version DESC LIMIT 1) b ON true
  WHERE d.state = 'active'
    AND b.created_at < now() - interval '1 hour'
    AND s.last_contact_at > b.created_at + interval '1 hour'
    AND coalesce(s.applied_bundle_version, 0) < b.version
  UNION ALL
  SELECT 'disk_conversion_failed', d.id, d.hostname, c.phase_at,
    coalesce(c.failure_stage, '') || ':' || coalesce(c.failure_reason, ''), 'disk_conversion_failed:' || c.id::text
  FROM device_disk_conversion c JOIN device d ON d.id = c.device_id
  WHERE d.state = 'active' AND c.phase = 'failed'
    AND c.id = (SELECT id FROM device_disk_conversion WHERE device_id = d.id
                ORDER BY (phase IN ('requested','prepared','encrypting')) DESC, phase_at DESC, id DESC LIMIT 1);

-- +goose Down
