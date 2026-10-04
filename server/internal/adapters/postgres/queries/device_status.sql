-- Worker heartbeat materialization (plan M2a decision 12); an older heartbeat never overwrites a newer one.
-- name: UpsertDeviceStatus :exec
INSERT INTO device_status (device_id, organization_id, last_contact_at, applied_bundle_version, agent_version, last_seq, health,
                           schema_versions)
VALUES (@device_id, @organization_id, @last_contact_at, @applied_bundle_version, @agent_version, @last_seq, @health,
        @schema_versions)
ON CONFLICT (device_id) DO UPDATE
SET last_contact_at = EXCLUDED.last_contact_at, applied_bundle_version = EXCLUDED.applied_bundle_version,
    agent_version = EXCLUDED.agent_version, last_seq = greatest(device_status.last_seq, EXCLUDED.last_seq),
    health = EXCLUDED.health, schema_versions = EXCLUDED.schema_versions
WHERE device_status.last_contact_at IS NULL OR device_status.last_contact_at <= EXCLUDED.last_contact_at;

-- name: ListDeviceSeqs :many
SELECT device_id, last_seq FROM device_status WHERE last_seq > 0 ORDER BY device_id;

-- Device events are deduplicated by (device_id, event_seq) (plan M2a decision 14).
-- name: InsertDeviceEventSeen :execrows
INSERT INTO device_event_seen (device_id, event_seq, organization_id)
VALUES (@device_id, @event_seq, @organization_id)
ON CONFLICT DO NOTHING;

-- The latest login.* or sudo.* event of a device per area (plan M3b decision 17); an older event never overwrites a
-- newer one. A device whose heartbeat was not materialized yet gets its status row here.
-- name: SetDeviceLoginState :exec
INSERT INTO device_status (device_id, organization_id, login_state)
VALUES (@device_id, @organization_id, jsonb_build_object(@area::text, @state::jsonb))
ON CONFLICT (device_id) DO UPDATE
SET login_state = device_status.login_state || jsonb_build_object(@area::text, @state::jsonb)
WHERE (device_status.login_state -> @area::text) IS NULL
   OR (device_status.login_state -> @area::text ->> 'occurred_at')::timestamptz <= (@state::jsonb ->> 'occurred_at')::timestamptz;
