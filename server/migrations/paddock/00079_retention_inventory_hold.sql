-- server/migrations/paddock/00079_retention_inventory_hold.sql
-- The retention round keeps a retired device's Fleet host and host reference while a device of the same hardware may
-- still use the host ('hardware') or the host checked in after the retirement ('seen_recently'). The last answer the
-- round recorded an event for is held here, so an unchanged answer records no event every round and, after a fixed
-- number of unchanged rounds, one notice (plan M10 amendment 2026-10-30, PDK-583 round 2). retired_at is the device's
-- retirement the answer belongs to, so a device reactivated and retired again records its answer anew. The row goes
-- with the answer's change and with the device. Forward-only: there is no Down migration.
-- +goose Up
CREATE TABLE retention_inventory_hold (
  device_id uuid PRIMARY KEY REFERENCES device(id) ON DELETE CASCADE,
  organization_id uuid NOT NULL REFERENCES organization(id),
  last_answer text NOT NULL CHECK (last_answer IN ('hardware', 'seen_recently')),
  retired_at timestamptz NOT NULL,
  unchanged_rounds int NOT NULL DEFAULT 0,
  last_event_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE retention_inventory_hold ENABLE ROW LEVEL SECURITY;
ALTER TABLE retention_inventory_hold FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON retention_inventory_hold TO paddock_worker
  USING (organization_id = current_setting('paddock.org_id')::uuid)
  WITH CHECK (organization_id = current_setting('paddock.org_id')::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON retention_inventory_hold TO paddock_worker;
-- +goose Down
