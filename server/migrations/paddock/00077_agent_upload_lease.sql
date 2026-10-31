-- Upload leases of agent release files (PDK-496, architect decision option C). An upload takes a lease on the object
-- of its file while the release is a draft, writes the object and then records the file and drops the lease in one
-- transaction. Publishing locks the release and refuses while an unexpired lease exists, so no upload that passed the
-- draft check can still write a published object; a commit after the lease expired is refused. Object keys are
-- unchanged: deployed agents validate the package path. Platform data like the release itself (no organization, no
-- RLS). Forward-only: there is no Down migration.
-- +goose Up
CREATE TABLE agent_upload_lease (
  id uuid PRIMARY KEY,
  version text NOT NULL REFERENCES agent_release(version),
  object_key text NOT NULL,
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (version, object_key)
);

GRANT SELECT, INSERT, UPDATE, DELETE ON agent_upload_lease TO paddock_platform;
