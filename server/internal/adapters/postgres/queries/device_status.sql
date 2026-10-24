-- Worker heartbeat materialization (plan M2a decision 12); an older heartbeat never overwrites a newer one.
-- name: UpsertDeviceStatus :exec
-- A health without revoke_capabilities keeps the last reported value: the device could not ask paddock-revoke this
-- time (PDK-009, review round 1), which must not change the volumes of its tokens.
-- event_seq_high is taken as reported, never the greater one: an agent whose state was reset reports a lower number
-- (plan M8b decision 12).
INSERT INTO device_status (device_id, organization_id, last_contact_at, applied_bundle_version, agent_version, last_seq, health,
                           schema_versions, arch, components_outdated, clock_offset_s, event_seq_high)
VALUES (@device_id, @organization_id, @last_contact_at, @applied_bundle_version, @agent_version, @last_seq, @health,
        @schema_versions, @arch, @components_outdated::text[], @clock_offset_s, @event_seq_high)
ON CONFLICT (device_id) DO UPDATE
SET last_contact_at = EXCLUDED.last_contact_at, applied_bundle_version = EXCLUDED.applied_bundle_version,
    agent_version = EXCLUDED.agent_version, last_seq = greatest(device_status.last_seq, EXCLUDED.last_seq),
    health = CASE
      WHEN NOT (EXCLUDED.health ? 'revoke_capabilities') AND device_status.health ? 'revoke_capabilities'
      THEN EXCLUDED.health || jsonb_build_object('revoke_capabilities', device_status.health -> 'revoke_capabilities')
      ELSE EXCLUDED.health END,
    schema_versions = EXCLUDED.schema_versions, arch = EXCLUDED.arch, components_outdated = EXCLUDED.components_outdated,
    clock_offset_s = EXCLUDED.clock_offset_s, event_seq_high = EXCLUDED.event_seq_high
WHERE device_status.last_contact_at IS NULL OR device_status.last_contact_at <= EXCLUDED.last_contact_at;

-- The clock state of a device (plan M8b decision 14): the offset of its newest materialized check-in and since when
-- its clock drifts.
-- name: GetDeviceClockState :one
SELECT clock_offset_s, clock_drift_since, last_contact_at FROM device_status WHERE device_id = @device_id;

-- Opens a clock drift episode; no row when one is open already (the claim of device.clock_drift).
-- name: SetClockDrift :execrows
UPDATE device_status SET clock_drift_since = @now WHERE device_id = @device_id AND clock_drift_since IS NULL;

-- Closes the clock drift episode; no row when none is open (the claim of device.clock_drift_cleared).
-- name: ClearClockDrift :execrows
UPDATE device_status SET clock_drift_since = NULL WHERE device_id = @device_id AND clock_drift_since IS NOT NULL;

-- name: ListDeviceSeqs :many
SELECT device_id, last_seq FROM device_status WHERE last_seq > 0 ORDER BY device_id;

-- Device events are deduplicated by (device_id, event_seq) (plan M2a decision 14); received_at is the gateway's
-- receipt time of the event's batch (plan M8b amendment of 2026-10-24).
-- name: InsertDeviceEventSeen :execrows
INSERT INTO device_event_seen (device_id, event_seq, organization_id, received_at)
VALUES (@device_id, @event_seq, @organization_id, @received_at)
ON CONFLICT DO NOTHING;

-- A range of event sequence numbers the agent admits it dropped (agent.events_dropped, plan M8b decision 19): no gap.
-- name: InsertDeviceEventDropped :exec
INSERT INTO device_event_dropped (device_id, from_seq, to_seq, organization_id)
VALUES (@device_id, @from_seq, @to_seq, @organization_id)
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
