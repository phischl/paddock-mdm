-- The organization indexes of device_event_seen, device_event_gap and device_event_dropped keep the device key (ADR 0055
-- amendment 2026-11-15 (2) decision 10): a generic plan of a device-keyed lookup that takes the organization index
-- read every row of a large organization (30 000 buffers for MaxDeviceEventSeenBefore); with (organization_id,
-- device_id) it reads one device's rows. The deletion keeps an index led by organization_id (plan M17 amendment
-- 2026-11-16 q point 1). Built and dropped concurrently, outside a transaction, so the tables keep serving writes. A
-- build that fails leaves an INVALID index and goose does not record the version; the re-run drops that leftover and
-- builds it again, and drops the organization-only index only after its replacement is valid.
-- Forward-only: there is no Down migration.
-- +goose NO TRANSACTION
-- +goose Up
DROP INDEX CONCURRENTLY IF EXISTS device_event_seen_org_device_idx;
CREATE INDEX CONCURRENTLY device_event_seen_org_device_idx ON device_event_seen (organization_id, device_id);
DROP INDEX CONCURRENTLY IF EXISTS device_event_seen_org_idx;
DROP INDEX CONCURRENTLY IF EXISTS device_event_gap_org_device_idx;
CREATE INDEX CONCURRENTLY device_event_gap_org_device_idx ON device_event_gap (organization_id, device_id);
DROP INDEX CONCURRENTLY IF EXISTS device_event_gap_org_idx;
DROP INDEX CONCURRENTLY IF EXISTS device_event_dropped_org_device_idx;
CREATE INDEX CONCURRENTLY device_event_dropped_org_device_idx ON device_event_dropped (organization_id, device_id);
DROP INDEX CONCURRENTLY IF EXISTS device_event_dropped_org_idx;

-- +goose Down
