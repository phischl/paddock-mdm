-- Event gaps and counter resets of devices (plan M8b decisions 17–22 with the amendment of 2026-10-24, worker).

-- The active devices whose numbering may hold a hole: a reported number above the contiguous pointer, an open gap or
-- a delivered number above the pointer.
-- name: ListEventGapCandidates :many
SELECT s.device_id, s.event_seq_high, s.event_seq_contiguous, s.last_seq, s.last_contact_at
FROM device_status s JOIN device d ON d.id = s.device_id
WHERE d.state = 'active'
  AND (s.event_seq_high > s.event_seq_contiguous
       OR EXISTS (SELECT 1 FROM device_event_gap g WHERE g.device_id = s.device_id AND g.filled_at IS NULL)
       OR EXISTS (SELECT 1 FROM device_event_seen e WHERE e.device_id = s.device_id AND e.event_seq > s.event_seq_contiguous))
ORDER BY s.device_id;

-- Locks a device's event numbering for one evaluation or reset, so the round and a reset never interleave
-- (PDK-108 review 1, B1); no row when the device never checked in.
-- name: LockDeviceEventSeq :one
SELECT event_seq_contiguous, event_seq_high, last_seq, last_contact_at FROM device_status WHERE device_id = @device_id FOR UPDATE;

-- name: ListDeviceEventSeenAbove :many
SELECT event_seq FROM device_event_seen WHERE device_id = @device_id AND event_seq > @above ORDER BY event_seq LIMIT 10000;

-- name: ListDeviceEventDroppedAbove :many
SELECT from_seq, to_seq FROM device_event_dropped WHERE device_id = @device_id AND to_seq > @above ORDER BY from_seq;

-- name: ListOpenDeviceEventGaps :many
SELECT * FROM device_event_gap WHERE device_id = @device_id AND filled_at IS NULL ORDER BY from_seq;

-- The highest number of a device whose event the gateway received before @before; a row from before migration 00069
-- has no receipt time and counts as earlier. The agent sends the events it numbered after a check-in right after
-- that check-in, and the worker may record them before the check-in, so only earlier events are compared with it.
-- name: MaxDeviceEventSeenBefore :one
SELECT coalesce((SELECT event_seq FROM device_event_seen
                 WHERE device_id = @device_id AND (received_at IS NULL OR received_at < @before::timestamptz)
                 ORDER BY event_seq DESC LIMIT 1), 0)::bigint;

-- name: SetEventSeqContiguous :exec
UPDATE device_status SET event_seq_contiguous = @value WHERE device_id = @device_id AND event_seq_contiguous < @value;

-- name: InsertDeviceEventGap :exec
INSERT INTO device_event_gap (id, organization_id, device_id, from_seq, to_seq, first_seen_at, first_seen_last_seq)
VALUES (@id, @organization_id, @device_id, @from_seq, @to_seq, @first_seen_at, @first_seen_last_seq)
ON CONFLICT (device_id, from_seq) WHERE filled_at IS NULL DO NOTHING;

-- Closes an open gap; no row when it is closed already (the claim of device.event_gap_filled).
-- name: FillDeviceEventGap :execrows
UPDATE device_event_gap SET filled_at = @now WHERE id = @id AND filled_at IS NULL;

-- Marks an open gap reported; no row when it is reported or closed already (the claim of device.event_gap).
-- name: ReportDeviceEventGap :execrows
UPDATE device_event_gap SET reported_at = @now WHERE id = @id AND reported_at IS NULL AND filled_at IS NULL;

-- Forgets the delivered numbers of a device whose counter restarted, as far as the gateway received them before the
-- check-in that showed the reset: later rows already belong to the new numbering (the claim of device.event_seq_reset).
-- name: DeleteDeviceEventSeenBefore :execrows
DELETE FROM device_event_seen WHERE device_id = @device_id AND (received_at IS NULL OR received_at < @before::timestamptz);

-- name: DeleteDeviceEventDropped :exec
DELETE FROM device_event_dropped WHERE device_id = @device_id;

-- name: CloseOpenDeviceEventGaps :exec
UPDATE device_event_gap SET filled_at = @now WHERE device_id = @device_id AND filled_at IS NULL;

-- name: ResetEventSeq :exec
UPDATE device_status SET event_seq_contiguous = 0, event_seq_high = @high WHERE device_id = @device_id;
