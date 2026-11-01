-- Before-states of change sets (plan M11 decisions 17-20). Forward-only: there is no Down migration.
-- Every configuration write records a change set; the items a change replaced or removed are kept in "before" so a
-- change set can be reverted. Rows from before this migration keep before NULL ("recorded before before-states were
-- stored"). The retention pass of M10 clears "before" after 90 days and sets before_purged_at; nothing else is updated.
-- +goose Up

ALTER TABLE change_set
  ADD COLUMN before jsonb,
  ADD COLUMN before_purged_at timestamptz,
  ADD COLUMN reverts_change_set_id uuid REFERENCES change_set(id),
  ADD COLUMN rollout text NOT NULL DEFAULT 'immediate' CHECK (rollout IN ('immediate', 'staged', 'urgent')),
  ADD COLUMN urgent_reason text CHECK (char_length(urgent_reason) BETWEEN 2 AND 500),
  ADD COLUMN reason text CHECK (char_length(reason) <= 500);
CREATE INDEX change_set_reverts_idx ON change_set (reverts_change_set_id) WHERE reverts_change_set_id IS NOT NULL;
GRANT UPDATE (before, before_purged_at) ON change_set TO paddock_worker;

-- The purge needs the rows of its own organization only, and only the columns its WHERE reads.
CREATE POLICY worker_purge ON change_set TO paddock_worker
  USING (organization_id = current_setting('paddock.org_id')::uuid)
  WITH CHECK (organization_id = current_setting('paddock.org_id')::uuid);
GRANT SELECT (id, organization_id, applied_at, before) ON change_set TO paddock_worker;
