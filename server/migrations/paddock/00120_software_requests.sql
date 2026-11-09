-- Approvals for available catalog entries (plan M13c decisions 8 to 10, PDK-810). A catalog entry gains approval:
-- none as before, or required, so its users must ask before they install it. A user's request arrives from the device
-- as the event software.request; the worker opens one software_request per device, entry and user (state requested,
-- valid for 30 days), an organization administrator approves or denies it, and the worker expires what is left open
-- after expires_at or once the entry no longer requires approval (§3.8 L4). The compiler renders the approved users
-- into the device's bundle. The plan's justification column is left out until the maintainer decides whether the
-- user's text may be stored (plan §12 Q4); a later migration adds it. decided_by is the deciding administrator's display
-- name. The worker reads an entry's approval (column grant) and which entries still have an available assignment
-- (catalog_entry_id and intent only): an approval holds only while its entry and assignment exist (architect decision
-- A10-17), so the worker expires the requests of an entry that lost them. The attention view gains software_requests_open, one row
-- per device with open requests; its columns, grants and every other branch stay as in 00094. The plan names this file
-- 00111; that number was taken. Forward-only: there is no Down migration.
-- +goose Up
ALTER TABLE software_catalog_entry
  ADD COLUMN approval text NOT NULL DEFAULT 'none' CHECK (approval IN ('none', 'required'));
GRANT SELECT (approval) ON software_catalog_entry TO paddock_worker;
CREATE POLICY tenant_worker ON software_assignment FOR SELECT TO paddock_worker
  USING (organization_id = current_setting('paddock.org_id')::uuid);
GRANT SELECT (organization_id, catalog_entry_id, intent) ON software_assignment TO paddock_worker;

CREATE TABLE software_request (
  id uuid PRIMARY KEY,
  organization_id uuid NOT NULL,
  catalog_entry_id uuid NOT NULL,
  device_id uuid NOT NULL,
  user_id uuid,
  username text NOT NULL CHECK (char_length(username) BETWEEN 1 AND 256),
  state text NOT NULL CHECK (state IN ('requested', 'approved', 'denied', 'expired', 'withdrawn')),
  requested_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  decided_by text CHECK (char_length(decided_by) <= 256),
  decided_at timestamptz,
  decision_reason text CHECK (char_length(decision_reason) <= 500),
  FOREIGN KEY (organization_id, catalog_entry_id) REFERENCES software_catalog_entry (organization_id, id) ON DELETE CASCADE,
  FOREIGN KEY (organization_id, device_id) REFERENCES device (organization_id, id),
  FOREIGN KEY (organization_id, user_id) REFERENCES app_user (organization_id, id) ON DELETE SET NULL (user_id)
);
CREATE UNIQUE INDEX software_request_open_idx ON software_request (device_id, catalog_entry_id, username)
  WHERE state = 'requested';
CREATE INDEX software_request_org_requested_idx ON software_request (organization_id, requested_at DESC, id);
CREATE INDEX software_request_entry_idx ON software_request (catalog_entry_id, state);

ALTER TABLE software_request ENABLE ROW LEVEL SECURITY;
ALTER TABLE software_request FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON software_request TO paddock_api, paddock_worker, paddock_compiler
  USING (organization_id = current_setting('paddock.org_id')::uuid)
  WITH CHECK (organization_id = current_setting('paddock.org_id')::uuid);
GRANT SELECT, UPDATE ON software_request TO paddock_api;
GRANT SELECT, INSERT, UPDATE ON software_request TO paddock_worker;
GRANT SELECT ON software_request TO paddock_compiler;

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
                ORDER BY (phase IN ('requested','prepared','encrypting')) DESC, phase_at DESC, id DESC LIMIT 1)
  UNION ALL
  SELECT 'clock_drift', d.id, d.hostname, s.clock_drift_since, s.clock_offset_s::text || ' s', 'clock_drift:' || d.id::text
  FROM device d JOIN device_status s ON s.device_id = d.id
  WHERE d.state = 'active' AND s.clock_drift_since IS NOT NULL
  UNION ALL
  SELECT 'event_gap', d.id, d.hostname, g.reported_at, g.from_seq::text || '-' || g.to_seq::text, 'event_gap:' || g.id::text
  FROM device_event_gap g JOIN device d ON d.id = g.device_id
  WHERE d.state = 'active' AND g.reported_at IS NOT NULL AND g.filled_at IS NULL
  UNION ALL
  SELECT 'report_only', d.id, d.hostname, coalesce(d.config_mode_changed_at, d.enrolled_at), d.enrollment_method,
    'report_only:' || d.id::text
  FROM device d
  WHERE d.state = 'active' AND d.config_mode = 'report_only'
  UNION ALL
  -- detail is the number of the device's open requests; since the oldest of them.
  SELECT 'software_requests_open', d.id, d.hostname, r.since, r.open::text, 'software_requests_open:' || d.id::text
  FROM (SELECT device_id, min(requested_at) AS since, count(*) AS open
        FROM software_request WHERE state = 'requested' GROUP BY device_id) r
  JOIN device d ON d.id = r.device_id
  WHERE d.state = 'active';

-- +goose Down
