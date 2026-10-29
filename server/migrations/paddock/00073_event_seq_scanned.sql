-- Event gap scan position (PDK-419, plan M8b amendment 2026-10-29): device_status records event_seq_scanned, the
-- number up to which the event gap round has looked for holes. Every number up to it was delivered, declared dropped
-- or lies in an open gap row, so the round reads delivered numbers above it instead of above event_seq_contiguous,
-- which a permanent gap pins. Existing devices start at their contiguous pointer, where the round read so far.
-- Grants are unchanged: the worker updates device_status as before.
-- Forward-only: there is no Down migration.
-- +goose Up
ALTER TABLE device_status ADD COLUMN event_seq_scanned bigint NOT NULL DEFAULT 0;
UPDATE device_status SET event_seq_scanned = event_seq_contiguous;
