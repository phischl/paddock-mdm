-- Software catalog targets, the available intent and Flatpak sources (plan M13b decisions 3 to 5, ADR 0049, PDK-798).
-- A source gains its kind: apt as before, or flatpak, a Flatpak remote with exactly one URL and no suites, components
-- or architectures; its key and fingerprint follow the apt rules. An assignment gains the targets user and user group
-- next to the device group (at most one; none = the whole organization), as organization-bound foreign keys that
-- remove the assignment with the user or the group, and the intent available. The unique key covers every target, so a
-- second assignment of an entry to the same target (the organization included) is refused. A status row gains its
-- scope and the user of a user-scope install; existing rows become system rows without a user. Grants and RLS stay as
-- they are. The plan names this file 00108; that number was taken. Forward-only: there is no Down migration.
-- +goose Up
ALTER TABLE software_source ADD COLUMN kind text NOT NULL DEFAULT 'apt' CHECK (kind IN ('apt', 'flatpak'));
ALTER TABLE software_source DROP CONSTRAINT software_source_suites_check;
ALTER TABLE software_source ADD CONSTRAINT software_source_kind_shape CHECK (
  (kind = 'apt' AND cardinality(suites) BETWEEN 1 AND 8)
  OR (kind = 'flatpak' AND cardinality(uris) = 1 AND cardinality(suites) = 0 AND cardinality(components) = 0
    AND cardinality(architectures) = 0));

ALTER TABLE software_assignment
  ADD COLUMN user_id uuid,
  ADD COLUMN user_group_id uuid,
  ADD CONSTRAINT software_assignment_one_target CHECK (num_nonnulls(device_group_id, user_id, user_group_id) <= 1),
  ADD CONSTRAINT software_assignment_user_fk FOREIGN KEY (organization_id, user_id)
    REFERENCES app_user (organization_id, id) ON DELETE CASCADE,
  ADD CONSTRAINT software_assignment_user_group_fk FOREIGN KEY (organization_id, user_group_id)
    REFERENCES user_group (organization_id, id) ON DELETE CASCADE,
  DROP CONSTRAINT software_assignment_intent_check,
  ADD CONSTRAINT software_assignment_intent_check
    CHECK (intent IN ('required', 'uninstall', 'hold', 'forbid', 'available')),
  DROP CONSTRAINT software_assignment_check,
  ADD CONSTRAINT software_assignment_check CHECK (
    (intent = 'required' AND update_rule = 'pinned' AND version IS NOT NULL)
    OR (intent = 'required' AND update_rule = 'latest' AND version IS NULL)
    OR (intent = 'hold' AND update_rule = 'latest')
    OR (intent IN ('uninstall', 'forbid', 'available') AND update_rule = 'latest' AND version IS NULL)),
  DROP CONSTRAINT software_assignment_organization_id_catalog_entry_id_device_key;
CREATE UNIQUE INDEX software_assignment_target_idx
  ON software_assignment (organization_id, catalog_entry_id, device_group_id, user_id, user_group_id) NULLS NOT DISTINCT;
CREATE INDEX software_assignment_user_idx ON software_assignment (user_id) WHERE user_id IS NOT NULL;
CREATE INDEX software_assignment_user_group_idx ON software_assignment (user_group_id) WHERE user_group_id IS NOT NULL;

ALTER TABLE device_software_status
  ADD COLUMN scope text NOT NULL DEFAULT 'system' CHECK (scope IN ('system', 'user')),
  ADD COLUMN username text NOT NULL DEFAULT '' CHECK (char_length(username) <= 254),
  DROP CONSTRAINT device_software_status_pkey,
  ADD PRIMARY KEY (device_id, catalog_entry_id, scope, username);

-- +goose Down
