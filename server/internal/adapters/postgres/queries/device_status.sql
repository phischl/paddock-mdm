-- Worker heartbeat materialization (plan M2a decision 12); an older heartbeat never overwrites a newer one.
-- name: UpsertDeviceStatus :exec
INSERT INTO device_status (device_id, organization_id, last_contact_at, applied_bundle_version, agent_version, last_seq, health)
VALUES (@device_id, @organization_id, @last_contact_at, @applied_bundle_version, @agent_version, @last_seq, @health)
ON CONFLICT (device_id) DO UPDATE
SET last_contact_at = EXCLUDED.last_contact_at, applied_bundle_version = EXCLUDED.applied_bundle_version,
    agent_version = EXCLUDED.agent_version, last_seq = greatest(device_status.last_seq, EXCLUDED.last_seq),
    health = EXCLUDED.health
WHERE device_status.last_contact_at IS NULL OR device_status.last_contact_at <= EXCLUDED.last_contact_at;

-- name: ListDeviceSeqs :many
SELECT device_id, last_seq FROM device_status WHERE last_seq > 0 ORDER BY device_id;

-- Device events are deduplicated by (device_id, event_seq) (plan M2a decision 14).
-- name: InsertDeviceEventSeen :execrows
INSERT INTO device_event_seen (device_id, event_seq, organization_id)
VALUES (@device_id, @event_seq, @organization_id)
ON CONFLICT DO NOTHING;
