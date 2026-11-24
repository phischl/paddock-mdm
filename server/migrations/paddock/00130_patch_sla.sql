-- Patch SLA and the patch compliance report (plan M13c decisions 17 and 18, PDK-814). An organization sets how many
-- days a vulnerability with a fixed version may stay open per severity (0 = no SLA for that severity); a trigger gives
-- every organization a row with the defaults 7/30/90/0. The worker claims one vulnerability.sla_breached summary per
-- organization and UTC day in vulnerability_sla_summary. The attention view gains patch_sla_breached, one row per
-- device with a finding open longer than its severity's SLA; its columns, grants and every other branch stay as in
-- 00119. The plan names this file 00113; that number was taken. Both new tables are registered in offboarding_table
-- (architecture §16.2). Forward-only: there is no Down migration.
-- +goose Up
CREATE TABLE organization_patch_sla (
  organization_id uuid PRIMARY KEY REFERENCES organization(id),
  critical_days int NOT NULL DEFAULT 7 CHECK (critical_days BETWEEN 0 AND 365),
  high_days int NOT NULL DEFAULT 30 CHECK (high_days BETWEEN 0 AND 365),
  medium_days int NOT NULL DEFAULT 90 CHECK (medium_days BETWEEN 0 AND 365),
  low_days int NOT NULL DEFAULT 0 CHECK (low_days BETWEEN 0 AND 365),
  updated_at timestamptz NOT NULL DEFAULT now(),
  updated_by uuid
);
INSERT INTO organization_patch_sla (organization_id) SELECT id FROM organization;
-- +goose StatementBegin
CREATE FUNCTION organization_patch_sla_default() RETURNS trigger
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
  INSERT INTO organization_patch_sla (organization_id) VALUES (NEW.id) ON CONFLICT DO NOTHING;
  RETURN NULL;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION organization_patch_sla_default() FROM PUBLIC;
CREATE TRIGGER organization_patch_sla_default AFTER INSERT ON organization
  FOR EACH ROW EXECUTE FUNCTION organization_patch_sla_default();
ALTER TABLE organization_patch_sla ENABLE ROW LEVEL SECURITY;
ALTER TABLE organization_patch_sla FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON organization_patch_sla TO paddock_api, paddock_worker
  USING (organization_id = current_setting('paddock.org_id')::uuid)
  WITH CHECK (organization_id = current_setting('paddock.org_id')::uuid);
GRANT SELECT, INSERT, UPDATE ON organization_patch_sla TO paddock_api;
GRANT SELECT ON organization_patch_sla TO paddock_worker;

CREATE TABLE vulnerability_sla_summary (
  organization_id uuid NOT NULL REFERENCES organization(id),
  day date NOT NULL,
  PRIMARY KEY (organization_id, day)
);
ALTER TABLE vulnerability_sla_summary ENABLE ROW LEVEL SECURITY;
ALTER TABLE vulnerability_sla_summary FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON vulnerability_sla_summary TO paddock_worker
  USING (organization_id = current_setting('paddock.org_id')::uuid)
  WITH CHECK (organization_id = current_setting('paddock.org_id')::uuid);
GRANT SELECT, INSERT ON vulnerability_sla_summary TO paddock_worker;

INSERT INTO offboarding_table (table_name, delete_order) VALUES
  ('organization_patch_sla', 395),
  ('vulnerability_sla_summary', 575);

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
  WHERE d.state = 'active'
  UNION ALL
  -- detail is the number of the device's findings open longer than their severity's SLA (days open, floored, above
  -- the SLA days); since the moment the first of them crossed it.
  SELECT 'patch_sla_breached', d.id, d.hostname, b.since, b.breached::text, 'patch_sla_breached:' || d.id::text
  FROM (SELECT f.device_id, min(f.first_seen_at + interval '24 hours' * (x.days + 1)) AS since, count(*) AS breached
        FROM vulnerability_finding f
        JOIN organization_patch_sla s ON s.organization_id = f.organization_id
        CROSS JOIN LATERAL (SELECT CASE f.severity WHEN 'critical' THEN s.critical_days WHEN 'high' THEN s.high_days
                                   WHEN 'medium' THEN s.medium_days WHEN 'low' THEN s.low_days ELSE 0 END AS days) x
        WHERE f.fixed_version IS NOT NULL AND x.days > 0 AND f.first_seen_at + interval '24 hours' * (x.days + 1) <= now()
        GROUP BY f.device_id) b
  JOIN device d ON d.id = b.device_id
  WHERE d.state = 'active';

-- +goose Down
