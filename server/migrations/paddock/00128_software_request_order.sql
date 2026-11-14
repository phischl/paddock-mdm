-- The order of a software request and its withdrawal (plan M19 decision D8, PDK-811d, RR-135). The worker processes a
-- device's event batches concurrently and in any order, so a withdrawal can be processed before the request it
-- withdraws, or after a later repeat of it. The device numbers its events (event_seq), and the order is taken from
-- that: software_request.reported_seq is the number of the newest software.request the open request stands for (NULL
-- for requests opened before this migration), and software_request_withdrawal keeps, per device, entry and user, the
-- highest number of a withdrawal processed so far. A request opens only when no withdrawal with a higher number exists;
-- a withdrawal closes only a request with a lower number (or NULL). The worker serializes both per device with a
-- transaction advisory lock. The device numbers anew after its agent state was reset (device.event_seq_reset), so
-- the worker then deletes the device's withdrawal rows and sets reported_seq to NULL on its open requests (amendment
-- 2026-11-14 c, D8.5): only the worker deletes rows here. A withdrawal row follows the retention of the requests (ADR 0032): it stays as long as the
-- requests do, and goes with its catalog entry. The plan's file name is <next>; 00126 and 00127 are taken by PDK-1013
-- and PDK-1034. Forward-only: there is no Down migration.
-- +goose Up
ALTER TABLE software_request ADD COLUMN reported_seq bigint;

CREATE TABLE software_request_withdrawal (
  organization_id uuid NOT NULL,
  device_id uuid NOT NULL,
  catalog_entry_id uuid NOT NULL,
  username text NOT NULL CHECK (char_length(username) BETWEEN 1 AND 256),
  event_seq bigint NOT NULL,
  received_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id, device_id, catalog_entry_id, username),
  FOREIGN KEY (organization_id, catalog_entry_id) REFERENCES software_catalog_entry (organization_id, id) ON DELETE CASCADE,
  FOREIGN KEY (organization_id, device_id) REFERENCES device (organization_id, id)
);

ALTER TABLE software_request_withdrawal ENABLE ROW LEVEL SECURITY;
ALTER TABLE software_request_withdrawal FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON software_request_withdrawal TO paddock_worker
  USING (organization_id = current_setting('paddock.org_id')::uuid)
  WITH CHECK (organization_id = current_setting('paddock.org_id')::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON software_request_withdrawal TO paddock_worker;

-- +goose Down
