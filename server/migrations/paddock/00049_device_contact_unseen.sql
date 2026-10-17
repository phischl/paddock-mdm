-- Contact state "unseen" and attention kind "agent_not_running" (plan M8x decisions 58 and 60, PDK-295).
-- An active device without a check-in for more than 15 minutes, no staleness alert and not presumed lost is "unseen"
-- (No recent contact) instead of "ok" (Online). The 15 minutes are app.AgentSilence (three check-ins,
-- server/internal/app/inventory.go); change both together. The function takes the reference time as a fifth
-- argument, so it stays IMMUTABLE; every consumer passes now(). The comparison is written as
-- at - last_contact_at > interval, not last_contact_at < at - interval: timestamptz - interval is STABLE
-- (timestamptz_mi_interval), and an IMMUTABLE SQL function with a STABLE operator in its body is never inlined,
-- which would bring back the per-row function call that 00043 removed (PDK-089). timestamptz - timestamptz and the
-- interval comparison are IMMUTABLE; both forms agree, the boundary included.
-- attention_condition gains the open finding of fleetd's policy paddock_agent_running (inventory.PolicyAgentRunning):
-- alerted_at is set when the failure is reported as device.tamper_agent_not_running and cleared when the policy
-- passes again (UpsertPolicyResult). Columns, grants and every other branch stay as in 00044.
-- Forward-only: there is no Down migration.
-- +goose Up
DROP FUNCTION paddock_device_contact(text, timestamptz, timestamptz, text);

-- +goose StatementBegin
CREATE FUNCTION paddock_device_contact(state text, last_contact_at timestamptz, presumed_lost_at timestamptz,
                                       open_alert_kind text, at timestamptz)
RETURNS text LANGUAGE sql IMMUTABLE PARALLEL SAFE AS $$
  SELECT CASE
    WHEN state <> 'active' THEN CASE WHEN last_contact_at IS NULL THEN 'never' ELSE 'ok' END
    WHEN presumed_lost_at IS NOT NULL THEN 'presumed_lost'
    WHEN open_alert_kind = 'stale_critical' THEN 'stale_critical'
    WHEN open_alert_kind = 'stale_warning' THEN 'stale_warning'
    WHEN last_contact_at IS NULL THEN 'never'
    WHEN at - last_contact_at > interval '15 minutes' THEN 'unseen'
    ELSE 'ok'
  END
$$;
-- +goose StatementEnd

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
  WHERE d.state = 'active' AND r.policy_key = 'paddock_agent_running' AND NOT r.passing AND r.alerted_at IS NOT NULL;

-- +goose Down
