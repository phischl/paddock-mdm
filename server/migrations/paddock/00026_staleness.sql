-- Staleness alerts (plan M5b decision 10). Forward-only: there is no Down migration.
-- The worker compares every active device's last contact with the organization's thresholds and records each crossed
-- level as an open device_alert; contact clears it. Critical marks the device as presumed lost until its next contact.
-- At most one alert per device is open. The api reads alerts for the attention list.
-- +goose Up

CREATE TABLE device_alert (
  id uuid PRIMARY KEY,
  organization_id uuid NOT NULL,
  device_id uuid NOT NULL REFERENCES device(id),
  kind text NOT NULL CHECK (kind IN ('stale_warning','stale_critical')),
  raised_at timestamptz NOT NULL,
  cleared_at timestamptz,
  FOREIGN KEY (organization_id, device_id) REFERENCES device (organization_id, id)
);
CREATE UNIQUE INDEX device_alert_open_idx ON device_alert (device_id) WHERE cleared_at IS NULL;
CREATE INDEX device_alert_org_raised_idx ON device_alert (organization_id, raised_at);
ALTER TABLE device_alert ENABLE ROW LEVEL SECURITY;
ALTER TABLE device_alert FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON device_alert TO paddock_api, paddock_worker
  USING (organization_id = current_setting('paddock.org_id')::uuid)
  WITH CHECK (organization_id = current_setting('paddock.org_id')::uuid);
GRANT SELECT ON device_alert TO paddock_api;
GRANT SELECT, INSERT, UPDATE ON device_alert TO paddock_worker;

-- Since when a device is presumed lost: it crossed the critical threshold; cleared at its next contact.
ALTER TABLE device_status ADD COLUMN presumed_lost_at timestamptz;

-- The attention list (plan M5b decision 11) flags devices whose agent is not the current release: the release of the
-- most recently completed rollout. paddock_current_agent_version lets the api read it in organization scope.
CREATE FUNCTION paddock_current_agent_version() RETURNS text
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS
  $$ SELECT version FROM agent_rollout WHERE status = 'completed' ORDER BY updated_at DESC, version DESC LIMIT 1 $$;
REVOKE ALL ON FUNCTION paddock_current_agent_version() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION paddock_current_agent_version() TO paddock_api;

-- attention_condition is the attention list (plan M5b decision 11): one row per open condition of a device that needs
-- an administrator, a read-only aggregation over existing state. security_invoker keeps the row-level security of the
-- underlying tables. Expired Lock and Destroy requests stay listed for 30 days.
CREATE VIEW attention_condition WITH (security_invoker = true) AS
  SELECT a.kind, d.id AS device_id, d.hostname, a.raised_at AS since, ''::text AS detail
  FROM device_alert a JOIN device d ON d.id = a.device_id
  WHERE a.cleared_at IS NULL AND d.state = 'active'
  UNION ALL
  SELECT 'presumed_lost', d.id, d.hostname, s.presumed_lost_at, ''
  FROM device d JOIN device_status s ON s.device_id = d.id
  WHERE d.state = 'active' AND s.presumed_lost_at IS NOT NULL
  UNION ALL
  SELECT 'quarantined', d.id, d.hostname, d.state_changed_at, ''
  FROM device d WHERE d.state = 'quarantined'
  UNION ALL
  SELECT 'disk_not_compliant', d.id, d.hostname, coalesce(s.last_contact_at, d.state_changed_at), s.health -> 'disk' ->> 'state'
  FROM device d JOIN device_status s ON s.device_id = d.id
  WHERE d.state = 'active' AND s.health -> 'disk' ->> 'state' IS NOT NULL AND s.health -> 'disk' ->> 'state' <> 'compliant'
  UNION ALL
  SELECT 'agent_outdated', d.id, d.hostname, coalesce(s.last_contact_at, d.state_changed_at), s.agent_version
  FROM device d JOIN device_status s ON s.device_id = d.id CROSS JOIN (SELECT paddock_current_agent_version() AS version) r
  WHERE d.state = 'active' AND r.version IS NOT NULL AND s.agent_version IS NOT NULL AND s.agent_version <> r.version
  UNION ALL
  SELECT replace(s.login_state -> area.name ->> 'type', '.', '_'), d.id, d.hostname,
    coalesce((s.login_state -> area.name ->> 'occurred_at')::timestamptz, d.state_changed_at), coalesce(s.login_state -> area.name -> 'params' ->> 'stage', '')
  FROM device d JOIN device_status s ON s.device_id = d.id
  CROSS JOIN (VALUES ('login'), ('sudo')) AS area(name)
  WHERE d.state = 'active' AND s.login_state -> area.name ->> 'type' IN ('login.apply_failed', 'sudo.apply_failed')
  UNION ALL
  SELECT CASE WHEN r.status = 'expired' THEN 'revocation_expired' ELSE 'revocation_pending' END, d.id, d.hostname,
    CASE WHEN r.status = 'expired' THEN coalesce(r.finished_at, r.requested_at) ELSE r.requested_at END, r.action || ':' || r.status
  FROM revocation_request r JOIN device d ON d.id = r.device_id
  WHERE r.action IN ('lock', 'destroy')
    AND (r.status IN ('requested', 'approved', 'issued', 'delivered')
         OR (r.status = 'expired' AND coalesce(r.finished_at, r.requested_at) > now() - interval '30 days'));
GRANT SELECT ON attention_condition TO paddock_api;

-- +goose Down
